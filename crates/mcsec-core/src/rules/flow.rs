//! Runs a rule definition over a class through the data flow engine.
//!
//! The rule's sources become the engine's policy. Its sinks and settings
//! are matched against calls as the engine replays each method, and each
//! method gets at most one finding per sink, for its most severe use.

use std::cmp::Ordering;

use super::Context;
use super::spec::{Condition, Effect, Is, MethodSig, Rule, Sink, SinkKind, Target, fill};
use crate::analysis::compare_versions;
use crate::class_file::{Operand, op};
use crate::dataflow::{self, Alloc, Frame, Known, Labels, MethodType, Policy, Site, Value};
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

/// One call to a sink.
struct Use {
    offset: u32,
    /// The value whose labels decide the severity, the stream for stream
    /// sinks and the data argument for call sinks.
    data: Value,
    /// The stream or receiver, when this method created it.
    created: Option<Alloc>,
    /// Set when the sink has a receiver this method did not create, so its
    /// settings are not visible. Holds the receiver's declared type.
    outside: Option<String>,
}

/// A setting call applied to an object this method created.
struct Applied {
    alloc: u32,
    setting: usize,
    offset: u32,
}

/// What one method does with one sink.
#[derive(Default)]
struct SinkUse {
    uses: Vec<Use>,
    applied: Vec<Applied>,
}

pub(crate) fn check(rule: &Rule, context: &Context, findings: &mut Vec<Finding>) {
    let class = &context.parsed.class;
    let pool = &class.constant_pool;
    let policy = RuleSources { rule, context };
    for method in &class.methods {
        let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
            continue;
        };
        let mut sink_uses: Vec<SinkUse> = rule.sinks.iter().map(|_| SinkUse::default()).collect();
        dataflow::analyze(class, method, &policy, &mut |site, frame| {
            observe(rule, context, site, frame, &mut sink_uses);
        });

        let method_ref = MethodRef {
            name: name.into_owned(),
            descriptor: descriptor.into_owned(),
        };
        for (sink, sink_use) in rule.sinks.iter().zip(sink_uses) {
            if let Some(finding) = finding(rule, sink, context, &method_ref, sink_use) {
                findings.push(finding);
            }
        }
    }
}

fn observe(rule: &Rule, context: &Context, site: &Site, frame: &Frame, sink_uses: &mut [SinkUse]) {
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
    let extends = |class: &str, ancestors: &[String]| {
        let ancestors: Vec<&str> = ancestors.iter().map(String::as_str).collect();
        context.hierarchy.extends_any(class, &ancestors)
    };
    let matches = |sig: &MethodSig| {
        sig.matches_name(name, descriptor) && context.hierarchy.extends_any(owner, &[&sig.owner])
    };
    let is_static = ins.opcode == op::INVOKESTATIC;
    // Each value takes one stack entry in the engine, wide or not.
    let arguments = MethodType::parse(descriptor).params.len();
    let at = |target: Target| target.depth(arguments).and_then(|d| frame.peek(d));
    let created_from =
        |value: &Value, types: &[String]| value.alloc.clone().filter(|a| extends(&a.class, types));

    for (sink, sink_use) in rule.sinks.iter().zip(sink_uses.iter_mut()) {
        if sink.calls.iter().any(matches) {
            let found = match sink.kind {
                // Only streams this method creates. One received as a
                // parameter belongs to whoever created it.
                SinkKind::Stream if !is_static => at(Target::Receiver)
                    .and_then(|stream| Some((stream, created_from(stream, &sink.types)?)))
                    .map(|(stream, created)| Use {
                        offset: ins.offset,
                        data: stream.clone(),
                        created: Some(created),
                        outside: None,
                    }),
                SinkKind::Stream => None,
                SinkKind::Call => sink.data.and_then(at).map(|data| {
                    let receiver = (!is_static && !sink.types.is_empty())
                        .then(|| at(Target::Receiver))
                        .flatten();
                    let created = receiver.and_then(|r| created_from(r, &sink.types));
                    Use {
                        offset: ins.offset,
                        data: data.clone(),
                        outside: (receiver.is_some() && created.is_none())
                            .then(|| owner.to_owned()),
                        created,
                    }
                }),
            };
            sink_use.uses.extend(found);
        }

        for (which, setting) in sink.settings.iter().enumerate() {
            if !matches(&setting.call) {
                continue;
            }
            let holds = setting.condition.as_ref().is_none_or(|condition| {
                at(Target::Argument(condition.argument))
                    .is_some_and(|value| condition_holds(condition, value, &extends))
            });
            if let Some(alloc) = at(setting.target).and_then(|v| v.alloc.as_ref())
                && holds
            {
                sink_use.applied.push(Applied {
                    alloc: alloc.offset,
                    setting: which,
                    offset: ins.offset,
                });
            }
        }
    }
}

fn condition_holds(
    condition: &Condition,
    value: &Value,
    extends: &dyn Fn(&str, &[String]) -> bool,
) -> bool {
    let is = condition
        .is
        .as_ref()
        .is_none_or(|is| match (is, &value.known) {
            (Is::Int(want), Some(Known::Int(got))) => want == got,
            (Is::Static(want), Some(Known::Static(got))) => **want == **got,
            _ => false,
        });
    let class = value.alloc.as_ref().map(|a| &*a.class);
    let within = |ty: &Option<String>, expected: bool| {
        ty.as_ref().is_none_or(|ty| {
            class.is_some_and(|c| extends(c, std::slice::from_ref(ty)) == expected)
        })
    };
    is && within(&condition.extends, true) && within(&condition.not_extends, false)
}

/// The judgment on one use, with the evidence step that decided it.
struct Assessment {
    severity: Severity,
    /// Explains the judgment, with the offset it points at.
    reason: Option<(String, u32)>,
}

fn assess(sink: &Sink, item: &Use, applied: &[Applied], context: &Context) -> Option<Assessment> {
    let critical = item.data.labels.0 & sink.critical.0 != 0;
    let dangerous = |reason| Assessment {
        severity: if critical {
            Severity::Critical
        } else {
            Severity::Warning
        },
        reason,
    };
    let notice = |reason| Assessment {
        severity: Severity::Notice,
        reason,
    };

    if let Some(ty) = &item.outside {
        // Settings on a receiver from elsewhere cannot be seen, so only
        // network data into one that is unsafe by default is reported.
        let note = sink
            .outside
            .as_ref()
            .map(|t| (fill(t, &[("type", ty)]), item.offset));
        return (sink.default == Effect::Unsafe && critical).then_some(Assessment {
            severity: Severity::Warning,
            reason: note,
        });
    }

    if let Some(created) = &item.created {
        let on_created = |effect: Effect| {
            applied
                .iter()
                .filter(|a| a.alloc == created.offset)
                .find(|a| sink.settings[a.setting].effect == effect)
                .map(|a| (sink.settings[a.setting].note.clone(), a.offset))
        };
        if let Some(reason) = on_created(Effect::Unsafe) {
            return Some(dangerous(Some(reason)));
        }
        if let Some(reason) = on_created(Effect::Safe) {
            return Some(notice(Some(reason)));
        }
        if let Some(subclass) = sink
            .subclass
            .as_ref()
            .filter(|_| !sink.types.iter().any(|t| **t == *created.class))
        {
            let text = fill(subclass, &[("type", &created.class)]);
            return Some(notice(Some((text, created.offset))));
        }
    }
    if sink.default == Effect::Safe {
        return None;
    }

    let Some(library) = &sink.library else {
        return Some(dangerous(None));
    };
    let (name, safe_from) = (&library.name, &library.safe_from);
    Some(match context.libraries.version(&library.coordinates) {
        Some(version) if compare_versions(version, safe_from) != Ordering::Less => notice(Some((
            format!("Bundles {name} {version}, whose defaults only accept allowed classes"),
            item.offset,
        ))),
        Some(version) => dangerous(Some((
            format!(
                "Bundles {name} {version}, which accepts any class by default before {safe_from}"
            ),
            item.offset,
        ))),
        None => dangerous(Some((
            format!(
                "{name} accepts any class by default before {safe_from}, and no bundled copy shows which version runs"
            ),
            item.offset,
        ))),
    })
}

fn finding(
    rule: &Rule,
    sink: &Sink,
    context: &Context,
    method: &MethodRef,
    sink_use: SinkUse,
) -> Option<Finding> {
    let (item, assessment) = sink_use
        .uses
        .into_iter()
        .filter_map(|item| {
            let assessment = assess(sink, &item, &sink_use.applied, context)?;
            Some((item, assessment))
        })
        .max_by_key(|(item, assessment)| (assessment.severity, std::cmp::Reverse(item.offset)))?;
    let severity = assessment.severity;
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
    if let Some(origin) = &item.data.origin {
        evidence.push(step(origin.description.to_string(), origin.offset));
    }
    if let (Some(created), Some(creates)) = (&item.created, &sink.creates) {
        evidence.push(step(
            fill(creates, &[("type", &created.class)]),
            created.offset,
        ));
    }
    if let Some((reason, offset)) = assessment.reason {
        evidence.push(step(reason, offset));
    }
    evidence.push(step(sink.read.clone(), item.offset));

    Some(Finding {
        rule_id: rule.id.clone(),
        severity,
        title: title.clone(),
        location: context.location(method, item.offset),
        evidence,
    })
}
