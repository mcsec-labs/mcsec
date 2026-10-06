//! Runs a rule definition over a class through the data flow engine.
//!
//! The rule's sources become the engine's policy. Its sinks and sanitizers
//! are matched against calls as the engine replays each method, and each
//! method gets at most one finding per sink, for its most severe use.

use super::Context;
use super::spec::{MethodSig, Rule, Sink, SinkKind, Target, fill};
use crate::class_file::{Operand, op};
use crate::dataflow::{self, Alloc, Frame, Labels, MethodType, Policy, Site, Value};
use crate::finding::{EvidenceStep, Finding, MethodRef, Severity};

struct RuleSources<'s, 'c, 'r, 'a> {
    rule: &'s Rule,
    context: &'c Context<'r, 'a>,
}

impl RuleSources<'_, '_, '_, '_> {
    fn matching(&self, ty: &str) -> Option<&super::spec::Source> {
        self.rule.sources.iter().find(|source| {
            let types: Vec<&str> = source.types.iter().map(String::as_str).collect();
            self.context.hierarchy.extends_any(ty, &types)
        })
    }
}

impl Policy for RuleSources<'_, '_, '_, '_> {
    fn parameter(&self, ty: &str, receiver: bool) -> Option<(Labels, String)> {
        let source = self.matching(ty)?;
        let template = if receiver {
            &source.receiver
        } else {
            &source.parameter
        };
        Some((source.label, fill(template, &[("type", ty)])))
    }

    fn call(&self, owner: &str, name: &str, _descriptor: &str) -> Option<(Labels, String)> {
        let source = self.matching(owner)?;
        Some((
            source.label,
            fill(&source.call, &[("owner", owner), ("name", name)]),
        ))
    }

    fn allocation(&self, _class: &str) -> Option<(Labels, String)> {
        // A freshly created buffer is empty, not untrusted data.
        None
    }
}

/// A read from a stream the method created.
struct Read {
    offset: u32,
    stream: Value,
    created: Alloc,
}

/// What one method does with one sink.
#[derive(Default)]
struct SinkUse {
    reads: Vec<Read>,
    /// Streams a sanitizer was applied to, by creation offset, with the
    /// sanitizer's note.
    sanitized: Vec<(u32, usize)>,
}

pub(crate) fn check(rule: &Rule, context: &Context, findings: &mut Vec<Finding>) {
    let class = &context.parsed.class;
    let pool = &class.constant_pool;
    let policy = RuleSources { rule, context };
    for method in &class.methods {
        let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
            continue;
        };
        let mut uses: Vec<SinkUse> = rule.sinks.iter().map(|_| SinkUse::default()).collect();
        dataflow::analyze(class, method, &policy, &mut |site, frame| {
            observe(rule, context, site, frame, &mut uses);
        });

        let method_ref = MethodRef {
            name: name.into_owned(),
            descriptor: descriptor.into_owned(),
        };
        for (sink, sink_use) in rule.sinks.iter().zip(uses) {
            if let Some(finding) = finding(rule, sink, context, &method_ref, sink_use) {
                findings.push(finding);
            }
        }
    }
}

fn observe(rule: &Rule, context: &Context, site: &Site, frame: &Frame, uses: &mut [SinkUse]) {
    let ins = site.instruction;
    let index = match (ins.opcode, &ins.operand) {
        (op::INVOKEVIRTUAL | op::INVOKESPECIAL | op::INVOKESTATIC, Operand::Constant(index)) => {
            *index
        }
        (op::INVOKEINTERFACE, Operand::InvokeInterface { index, .. }) => *index,
        _ => return,
    };
    let Ok(target) = site.pool.member_ref(index) else {
        return;
    };
    let (owner, name, descriptor) = (
        target.class_name.as_ref(),
        target.name.as_ref(),
        target.descriptor.as_ref(),
    );
    let matches = |sig: &MethodSig| {
        sig.name == name
            && sig.descriptor == descriptor
            && context.hierarchy.extends_any(owner, &[sig.owner.as_str()])
    };
    // Each value takes one stack entry in the engine, wide or not.
    let arguments = MethodType::parse(descriptor).params.len();

    for (sink, sink_use) in rule.sinks.iter().zip(uses.iter_mut()) {
        match sink.kind {
            SinkKind::Stream => {
                if ins.opcode != op::INVOKESTATIC && sink.reads.iter().any(matches) {
                    // Only streams this method creates. One received as a
                    // parameter belongs to whoever created it.
                    if let Some(stream) = frame.peek(arguments)
                        && let Some(created) = stream.alloc.clone().filter(|a| {
                            context
                                .hierarchy
                                .extends_any(&a.class, &[sink.stream_type.as_str()])
                        })
                    {
                        sink_use.reads.push(Read {
                            offset: ins.offset,
                            stream: stream.clone(),
                            created,
                        });
                    }
                }
            }
        }
        for (which, sanitizer) in sink.sanitizers.iter().enumerate() {
            if !matches(&sanitizer.call) {
                continue;
            }
            let depth = match sanitizer.target {
                Target::Receiver => Some(arguments),
                Target::Argument(i) => arguments.checked_sub(i + 1),
            };
            if let Some(alloc) = depth
                .and_then(|d| frame.peek(d))
                .and_then(|v| v.alloc.as_ref())
            {
                sink_use.sanitized.push((alloc.offset, which));
            }
        }
    }
}

fn severity_of(sink: &Sink, read: &Read, sanitized: &[(u32, usize)]) -> Severity {
    let custom = sink.subclass.is_some() && *read.created.class != *sink.stream_type;
    if custom
        || sanitized
            .iter()
            .any(|(offset, _)| *offset == read.created.offset)
    {
        Severity::Notice
    } else if read.stream.labels.0 & sink.critical.0 != 0 {
        Severity::Critical
    } else {
        Severity::Warning
    }
}

fn finding(
    rule: &Rule,
    sink: &Sink,
    context: &Context,
    method: &MethodRef,
    sink_use: SinkUse,
) -> Option<Finding> {
    let sanitized = &sink_use.sanitized;
    let read = sink_use.reads.into_iter().max_by_key(|read| {
        (
            severity_of(sink, read, sanitized),
            std::cmp::Reverse(read.offset),
        )
    })?;
    let severity = severity_of(sink, &read, sanitized);
    let title = match severity {
        Severity::Critical => &sink.title.critical,
        Severity::Warning => &sink.title.warning,
        Severity::Notice => &sink.title.notice,
    };

    let step = |description: String, offset: u32| EvidenceStep {
        description,
        location: context.location(method, offset),
    };
    let mut evidence = Vec::new();
    if let Some(origin) = &read.stream.origin {
        evidence.push(step(origin.description.to_string(), origin.offset));
    }
    let created = &read.created;
    let type_value = [("type", &*created.class)];
    evidence.push(step(fill(&sink.creates, &type_value), created.offset));
    if let Some((_, which)) = sanitized
        .iter()
        .find(|(offset, _)| *offset == created.offset)
    {
        evidence.push(step(sink.sanitizers[*which].note.clone(), created.offset));
    } else if let Some(subclass) = sink
        .subclass
        .as_ref()
        .filter(|_| *created.class != *sink.stream_type)
    {
        evidence.push(step(fill(subclass, &type_value), created.offset));
    }
    evidence.push(step(sink.read.clone(), read.offset));

    Some(Finding {
        rule_id: rule.id.clone(),
        severity,
        title: title.clone(),
        location: context.location(method, read.offset),
        evidence,
    })
}
