//! Runs a rule definition over one method through the data flow engine.
//!
//! The rule's sources become the engine's policy. Its sinks and settings
//! are matched against calls as the engine replays the method, and the
//! method gets at most one finding per sink, for its most severe use.
//!
//! Severity follows from where the data comes from and what limits the
//! sink. Network data with no safeguard is Critical, data the analysis could
//! not trace is Warning, and anything else is a Notice whose origin and
//! safeguard say why. When the data is one of the method's own parameters
//! and nothing limits the sink, the method gets a summary, so a caller
//! passing network data into that parameter is reported at the call.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use super::restriction;
use super::spec::{Condition, Effect, Is, MethodSig, Rule, Sink, SinkKind, Target, fill};
use super::{Context, method_key};
use crate::analysis::compare_versions;
use crate::class_file::{Member, Operand, op};
use crate::dataflow::{self, Alloc, Frame, Known, Labels, MethodType, Policy, Site, Value};
use crate::finding::{DataOrigin, EvidenceStep, Finding, Location, MethodRef, Safeguard, Severity};

/// A method, as (declaring class, name, descriptor).
pub(crate) type MethodKey = (String, String, String);

/// A parameter of a method that reaches a sink with nothing limiting it,
/// with the evidence from the call into the method through to the sink.
#[derive(Debug, Clone)]
pub(crate) struct ParamSink {
    pub param: usize,
    pub sink: usize,
    pub steps: Vec<EvidenceStep>,
}

/// A field, as `declaring class.name`.
pub(crate) type FieldKey = String;

/// Untrusted data some method stores in a field.
#[derive(Debug, Clone)]
pub(crate) struct FieldTaint {
    pub labels: Labels,
    /// The method that stores it, as `class.method`.
    pub writer: String,
}

/// What earlier rounds learned about the jar for one rule.
#[derive(Default)]
pub(crate) struct Facts {
    pub summaries: HashMap<MethodKey, Vec<ParamSink>>,
    /// The (name, descriptor) of every summarized method, so calls to any
    /// other method skip looking for override targets.
    pub summarized: HashSet<(String, String)>,
    pub fields: HashMap<FieldKey, FieldTaint>,
}

/// Something a method's result depends on, so a change to it means
/// checking the method again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Dependency {
    /// Calls to methods with this (name, descriptor), whichever class the
    /// call reaches.
    Call(String, String),
    Field(FieldKey),
}

/// What checking one method produced for one rule.
pub(crate) struct MethodResult {
    pub key: MethodKey,
    pub findings: Vec<Finding>,
    pub summary: Vec<ParamSink>,
    /// Untrusted data the method stores in fields.
    pub fields_written: Vec<(FieldKey, Labels)>,
    /// Methods it may call and fields it reads.
    pub depends: Vec<Dependency>,
}

struct RuleSources<'s, 'c, 'r, 'a> {
    rule: &'s Rule,
    context: &'c Context<'r, 'a>,
    facts: &'s Facts,
}

impl RuleSources<'_, '_, '_, '_> {
    fn typed(&self, ty: &str) -> Option<&super::spec::Source> {
        self.rule.sources.iter().find(|source| {
            let types: Vec<&str> = source.types.iter().map(String::as_str).collect();
            !types.is_empty() && self.context.hierarchy.extends_any(ty, &types)
        })
    }
}

impl Policy for RuleSources<'_, '_, '_, '_> {
    fn parameter(&self, index: Option<usize>, ty: &str) -> Option<(Labels, String)> {
        let source = self.typed(ty)?;
        let template = if index.is_none() {
            &source.receiver
        } else {
            &source.parameter
        };
        Some((source.label, fill(template, &[("type", ty)])))
    }

    fn call(&self, owner: &str, name: &str, descriptor: &str) -> Option<(Labels, String)> {
        let values = [("owner", owner), ("name", name)];
        if let Some(source) = self.typed(owner) {
            return Some((source.label, fill(&source.call, &values)));
        }
        self.rule.sources.iter().find_map(|source| {
            source
                .calls
                .iter()
                .any(|sig| {
                    sig.matches_name(name, descriptor)
                        && self.context.hierarchy.extends_any(owner, &[&sig.owner])
                })
                .then(|| (source.label, fill(&source.read, &values)))
        })
    }

    fn allocation(&self, class: &str) -> Option<(Labels, String)> {
        // A freshly created buffer is empty, so only listed classes that
        // open data, such as a file stream, are sources.
        self.rule.sources.iter().find_map(|source| {
            let allocations: Vec<&str> = source.allocations.iter().map(String::as_str).collect();
            (!allocations.is_empty() && self.context.hierarchy.extends_any(class, &allocations))
                .then(|| (source.label, fill(&source.opens, &[("type", class)])))
        })
    }

    fn field(&self, owner: &str, name: &str, descriptor: &str) -> Option<(Labels, String)> {
        let key = self.context.resolve_field(owner, name);
        let typed = dataflow::field_type(descriptor)
            .and_then(|t| t.reference)
            .and_then(|ty| Some((self.typed(&ty)?, ty)));
        if let Some((source, ty)) = typed {
            return Some((
                source.label,
                fill(&source.field, &[("field", &key), ("type", &ty)]),
            ));
        }
        let taint = self.facts.fields.get(&key)?;
        let stored = Value {
            labels: taint.labels,
            ..Value::default()
        };
        let what = match origin_of(self.rule, &stored) {
            DataOrigin::Network => "network data",
            DataOrigin::LocalFile => "data from a local file",
            _ => "an embedded serialized object",
        };
        Some((
            taint.labels,
            format!("Reads {key}, which {} fills with {what}", taint.writer),
        ))
    }

    fn static_field(&self, owner: &str, name: &str) -> Option<(Labels, String)> {
        let bytes = self.context.constants.byte_array(owner, name)?;
        self.rule.sources.iter().find_map(|source| {
            (!source.constant_prefix.is_empty() && bytes.starts_with(&source.constant_prefix)).then(
                || {
                    (
                        source.label,
                        fill(&source.copies, &[("owner", owner), ("name", name)]),
                    )
                },
            )
        })
    }
}

/// Where data comes from, judged from its labels and parameters. Network
/// data outranks local files, which outrank embedded templates, which
/// outrank the caller's data.
fn origin_of(rule: &Rule, value: &Value) -> DataOrigin {
    let carries = |origin: DataOrigin| {
        rule.sources
            .iter()
            .any(|s| s.origin == origin && value.labels.0 & s.label.0 != 0)
    };
    [
        DataOrigin::Network,
        DataOrigin::LocalFile,
        DataOrigin::EmbeddedTemplate,
    ]
    .into_iter()
    .find(|origin| carries(*origin))
    .unwrap_or(if value.params != 0 {
        DataOrigin::Caller
    } else {
        DataOrigin::Untraced
    })
}

/// A call into a method whose summary leads a parameter to this sink.
struct Via {
    callee: String,
    param: usize,
    steps: Vec<EvidenceStep>,
}

/// One use of a sink.
struct Use {
    offset: u32,
    /// The value whose origin decides the severity, the stream for stream
    /// sinks and the data argument for call sinks and calls into summaries.
    data: Value,
    /// The stream or receiver, when this method created it.
    created: Option<Alloc>,
    /// Set when the sink has a receiver this method did not create, so its
    /// settings are not visible. Holds the receiver's declared type.
    outside: Option<String>,
    via: Option<Via>,
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

pub(crate) fn check_method(
    rule: &Rule,
    context: &Context,
    method: &Member,
    facts: &Facts,
) -> Option<MethodResult> {
    let class = &context.parsed.class;
    let pool = &class.constant_pool;
    let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
        return None;
    };
    let method_ref = MethodRef {
        name: name.into_owned(),
        descriptor: descriptor.into_owned(),
    };
    let policy = RuleSources {
        rule,
        context,
        facts,
    };
    let mut sink_uses: Vec<SinkUse> = rule.sinks.iter().map(|_| SinkUse::default()).collect();
    let mut seen = Seen::default();
    dataflow::analyze(class, method, &policy, &mut |site, frame| {
        observe(rule, context, facts, site, frame, &mut sink_uses, &mut seen);
    });
    seen.depends.sort();
    seen.depends.dedup();

    let mut result = MethodResult {
        key: method_key(
            &context.parsed.name,
            &method_ref.name,
            &method_ref.descriptor,
        ),
        findings: Vec::new(),
        summary: Vec::new(),
        fields_written: seen.fields_written,
        depends: seen.depends,
    };
    for (index, (sink, sink_use)) in rule.sinks.iter().zip(sink_uses).enumerate() {
        judge_sink(
            rule,
            index,
            sink,
            context,
            &method_ref,
            sink_use,
            &mut result,
        );
    }
    Some(result)
}

/// Fields and calls one method touches, gathered while it is replayed.
#[derive(Default)]
struct Seen {
    fields_written: Vec<(FieldKey, Labels)>,
    depends: Vec<Dependency>,
}

fn observe(
    rule: &Rule,
    context: &Context,
    facts: &Facts,
    site: &Site,
    frame: &Frame,
    sink_uses: &mut [SinkUse],
    seen: &mut Seen,
) {
    let ins = site.instruction;
    if let (op::GETSTATIC..=op::PUTFIELD, Operand::Constant(index)) = (ins.opcode, &ins.operand) {
        if let Ok(field) = site.pool.member_ref(*index) {
            let key = context.resolve_field(&field.class_name, &field.name);
            match ins.opcode {
                op::PUTSTATIC | op::PUTFIELD => {
                    if let Some(value) = frame.peek(0).filter(|v| !v.labels.is_empty()) {
                        seen.fields_written.push((key, value.labels));
                    }
                }
                _ => seen.depends.push(Dependency::Field(key)),
            }
        }
        return;
    }
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
    // Calls into methods in the jar, and through their summaries, into the
    // sinks those methods pass a parameter to. A virtual or interface call
    // can reach any override in a class that extends or implements the
    // named owner, so each of those counts. Targets are only looked for when
    // some method with this name and descriptor has a summary.
    seen.depends
        .push(Dependency::Call(name.to_owned(), descriptor.to_owned()));
    if !facts
        .summarized
        .contains(&(name.to_owned(), descriptor.to_owned()))
    {
        return observe_sinks(
            rule, context, ins, frame, sink_uses, owner, name, descriptor,
        );
    }
    // Each value takes one stack entry in the engine, wide or not.
    let arguments = MethodType::parse(descriptor).params.len();
    let at = |target: Target| target.depth(arguments).and_then(|d| frame.peek(d));
    let mut targets: Vec<&str> = context
        .resolve_method(owner, name, descriptor)
        .map(|(class, _)| class.name.as_str())
        .into_iter()
        .collect();
    if matches!(ins.opcode, op::INVOKEVIRTUAL | op::INVOKEINTERFACE) {
        targets.extend(
            context
                .classes
                .implementations(name, descriptor)
                .iter()
                .copied()
                .filter(|class| context.hierarchy.is_subtype(class, owner)),
        );
    }
    targets.sort_unstable();
    targets.dedup();
    let mut reached: Vec<(usize, usize)> = Vec::new();
    for target_class in targets {
        let key = method_key(target_class, name, descriptor);
        for param_sink in facts.summaries.get(&key).into_iter().flatten() {
            if reached.contains(&(param_sink.param, param_sink.sink)) {
                continue;
            }
            let Some(data) = at(Target::Argument(param_sink.param)) else {
                continue;
            };
            reached.push((param_sink.param, param_sink.sink));
            sink_uses[param_sink.sink].uses.push(Use {
                offset: ins.offset,
                data: data.clone(),
                created: None,
                outside: None,
                via: Some(Via {
                    callee: format!("{target_class}.{name}"),
                    param: param_sink.param,
                    steps: param_sink.steps.clone(),
                }),
            });
        }
    }
    observe_sinks(
        rule, context, ins, frame, sink_uses, owner, name, descriptor,
    );
}

/// Matches a call against the rule's sinks and settings.
#[allow(clippy::too_many_arguments)]
fn observe_sinks(
    rule: &Rule,
    context: &Context,
    ins: &crate::class_file::Instruction,
    frame: &Frame,
    sink_uses: &mut [SinkUse],
    owner: &str,
    name: &str,
    descriptor: &str,
) {
    let extends = |class: &str, ancestors: &[String]| {
        let ancestors: Vec<&str> = ancestors.iter().map(String::as_str).collect();
        context.hierarchy.extends_any(class, &ancestors)
    };
    let matches = |sig: &MethodSig| {
        sig.matches_name(name, descriptor) && context.hierarchy.extends_any(owner, &[&sig.owner])
    };
    let is_static = ins.opcode == op::INVOKESTATIC;
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
                        via: None,
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
                        via: None,
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

/// The judgment on one use.
struct Assessment {
    /// `None` when the use is not reported in this method.
    severity: Option<Severity>,
    origin: DataOrigin,
    safeguard: Option<Safeguard>,
    /// Explains the judgment, each with the offset it points at.
    reasons: Vec<(String, u32)>,
    /// Nothing limits the sink, so untrusted data reaching it is a problem.
    unlimited: bool,
}

fn assess(
    rule: &Rule,
    sink: &Sink,
    item: &Use,
    applied: &[Applied],
    context: &Context,
) -> Assessment {
    let origin = origin_of(rule, &item.data);
    let by_origin = match origin {
        DataOrigin::Network => Severity::Critical,
        DataOrigin::Untraced => Severity::Warning,
        _ => Severity::Notice,
    };
    let unlimited = |reasons| Assessment {
        severity: Some(by_origin),
        origin,
        safeguard: None,
        reasons,
        unlimited: true,
    };
    let guarded = |safeguard, reasons| Assessment {
        severity: Some(Severity::Notice),
        origin,
        safeguard: Some(safeguard),
        reasons,
        unlimited: false,
    };

    if item.via.is_some() {
        // The callee reports the sink itself, so its caller reports only
        // network data it passes in.
        return Assessment {
            severity: (origin == DataOrigin::Network).then_some(Severity::Critical),
            origin,
            safeguard: None,
            reasons: Vec::new(),
            unlimited: true,
        };
    }

    if let Some(ty) = &item.outside {
        // Settings on a receiver from elsewhere cannot be seen, so only
        // network data into one that is unsafe by default is reported.
        let note = sink
            .outside
            .as_ref()
            .map(|t| (fill(t, &[("type", ty)]), item.offset));
        // A bundled library whose defaults are safe still decides it, since
        // the instance would have to be configured to accept any class.
        if let Some(library) = &sink.library
            && let Some(version) = context.libraries.version(&library.coordinates)
            && compare_versions(version, &library.safe_from) != Ordering::Less
            && origin == DataOrigin::Network
        {
            let bundled = (
                format!(
                    "Bundles {} {version}, whose defaults only accept allowed classes",
                    library.name
                ),
                item.offset,
            );
            return guarded(
                Safeguard::LibraryVersion,
                note.into_iter().chain([bundled]).collect(),
            );
        }
        return Assessment {
            severity: (sink.default == Effect::Unsafe && origin == DataOrigin::Network)
                .then_some(Severity::Warning),
            origin,
            safeguard: None,
            reasons: note.into_iter().collect(),
            unlimited: false,
        };
    }

    let mut reasons = Vec::new();
    if let Some(created) = &item.created {
        let on_created = |effect: Effect| {
            applied
                .iter()
                .filter(|a| a.alloc == created.offset)
                .find(|a| sink.settings[a.setting].effect == effect)
                .map(|a| (sink.settings[a.setting].note.clone(), a.offset))
        };
        if let Some(reason) = on_created(Effect::Unsafe) {
            return unlimited(vec![reason]);
        }
        if let Some(reason) = on_created(Effect::Safe) {
            return guarded(Safeguard::Setting, vec![reason]);
        }
        let custom = !sink.types.iter().any(|t| **t == *created.class);
        if let Some(subclass) = sink.subclass.as_ref().filter(|_| custom) {
            let text = fill(subclass, &[("type", &created.class)]);
            return guarded(Safeguard::UncheckedSubclass, vec![(text, created.offset)]);
        }
        if let Some(restriction) = sink.restriction.as_ref().filter(|_| custom) {
            let judgment = restriction::judge(context, &sink.types, &created.class, restriction);
            let note = (judgment.note(restriction, &created.class), created.offset);
            match judgment {
                restriction::Judgment::Allowlist(_)
                | restriction::Judgment::ConditionalAllowlist(_) => {
                    return guarded(Safeguard::Allowlist, vec![note]);
                }
                restriction::Judgment::Unseen => {
                    return guarded(Safeguard::UncheckedSubclass, vec![note]);
                }
                _ => reasons.push(note),
            }
        }
    }
    if sink.default == Effect::Safe {
        return Assessment {
            severity: None,
            origin,
            safeguard: None,
            reasons,
            unlimited: false,
        };
    }

    let Some(library) = &sink.library else {
        return unlimited(reasons);
    };
    let (name, safe_from) = (&library.name, &library.safe_from);
    match context.libraries.version(&library.coordinates) {
        Some(version) if compare_versions(version, safe_from) != Ordering::Less => {
            reasons.push((
                format!("Bundles {name} {version}, whose defaults only accept allowed classes"),
                item.offset,
            ));
            guarded(Safeguard::LibraryVersion, reasons)
        }
        Some(version) => {
            reasons.push((
                format!(
                    "Bundles {name} {version}, which accepts any class by default before {safe_from}"
                ),
                item.offset,
            ));
            unlimited(reasons)
        }
        None => {
            reasons.push((
                format!(
                    "{name} accepts any class by default before {safe_from}, and no bundled copy shows which version runs"
                ),
                item.offset,
            ));
            unlimited(reasons)
        }
    }
}

/// Evidence from where the data enters this method through to the sink.
fn steps_for(
    sink: &Sink,
    item: &Use,
    assessment: &Assessment,
    location: &dyn Fn(u32) -> Location,
) -> Vec<EvidenceStep> {
    let step = |description: String, offset: u32| EvidenceStep {
        description,
        location: location(offset),
    };
    let mut steps = Vec::new();
    if let Some(via) = &item.via {
        steps.push(step(
            format!(
                "Passes the data to {} as parameter {}",
                via.callee,
                via.param + 1
            ),
            item.offset,
        ));
        steps.extend(via.steps.iter().cloned());
        return steps;
    }
    if let (Some(created), Some(creates)) = (&item.created, &sink.creates) {
        steps.push(step(
            fill(creates, &[("type", &created.class)]),
            created.offset,
        ));
    }
    for (reason, offset) in &assessment.reasons {
        steps.push(step(reason.clone(), *offset));
    }
    steps.push(step(sink.read.clone(), item.offset));
    steps
}

#[allow(clippy::too_many_arguments)]
fn judge_sink(
    rule: &Rule,
    index: usize,
    sink: &Sink,
    context: &Context,
    method: &MethodRef,
    sink_use: SinkUse,
    result: &mut MethodResult,
) {
    let location = |offset: u32| context.location(method, offset);
    let assessed: Vec<(Use, Assessment)> = sink_use
        .uses
        .into_iter()
        .map(|item| {
            let assessment = assess(rule, sink, &item, &sink_use.applied, context);
            (item, assessment)
        })
        .collect();

    // A parameter reaching the sink with nothing limiting it, and no
    // untrusted data already mixed in, becomes part of the summary.
    for (item, assessment) in &assessed {
        if !assessment.unlimited || assessment.origin == DataOrigin::Network {
            continue;
        }
        let steps = steps_for(sink, item, assessment, &location);
        for param in (0..64).filter(|p| item.data.params & (1 << p) != 0) {
            let known = result
                .summary
                .iter()
                .any(|s| s.param == param && s.sink == index);
            if !known {
                result.summary.push(ParamSink {
                    param,
                    sink: index,
                    steps: steps.clone(),
                });
            }
        }
    }

    let Some((item, assessment)) = assessed
        .into_iter()
        .filter(|(_, assessment)| assessment.severity.is_some())
        .max_by_key(|(item, assessment)| (assessment.severity, std::cmp::Reverse(item.offset)))
    else {
        return;
    };
    let Some(severity) = assessment.severity else {
        return;
    };
    let title = match severity {
        Severity::Critical => &sink.title.critical,
        Severity::Warning => &sink.title.warning,
        Severity::Notice => &sink.title.notice,
    };

    let mut evidence = Vec::new();
    if let Some(origin) = &item.data.origin {
        evidence.push(EvidenceStep {
            description: origin.description.to_string(),
            location: location(origin.offset),
        });
    } else if assessment.origin == DataOrigin::Caller {
        let params: Vec<String> = (0..64)
            .filter(|p| item.data.params & (1 << p) != 0)
            .map(|p| (p + 1).to_string())
            .collect();
        evidence.push(EvidenceStep {
            description: format!(
                "Takes the data from its caller as parameter {}",
                params.join(" and ")
            ),
            location: location(0),
        });
    }
    evidence.extend(steps_for(sink, &item, &assessment, &location));

    result.findings.push(Finding {
        rule_id: rule.id.clone(),
        severity,
        title: title.clone(),
        location: location(item.offset),
        class_sha1: Some(crate::hash::sha1_hex(&context.parsed.entry.data)),
        origin: Some(assessment.origin),
        safeguard: assessment.safeguard,
        evidence,
    });
}
