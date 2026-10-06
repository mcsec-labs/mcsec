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

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::exposure::{self, FROM_EITHER};
use super::restriction;
use super::spec::{Condition, Effect, Is, MethodSig, Rule, Sink, SinkKind, Target, fill};
use super::{Context, method_key};
use crate::analysis::compare_versions;
use crate::class_file::{BootstrapMethod, Member, Operand, op};
use crate::dataflow::{self, Alloc, Frame, Inputs, Known, Labels, MethodType, Policy, Site, Value};
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
    /// The type the argument must have for this path to run, when the
    /// parameter reaches the sink unchanged through a cast or a callee that
    /// needs one. A call passing a value that can never have this type does
    /// not use the summary.
    pub requires: Option<Rc<str>>,
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

/// A parameter a method stores in a field itself, with a field write or by
/// adding it to a collection the field holds. Stores through further calls
/// are left out, since following them would recheck every caller up the
/// call graph of a large library each round.
pub(crate) type ParamStore = (usize, FieldKey);

impl Facts {
    /// Sets or clears the shape learned for a method. Returns true when it
    /// changed.
    pub fn set_shape(&mut self, key: &MethodKey, shape: Option<Inputs>) -> bool {
        let (class, name, descriptor) = key;
        let by_class = self
            .shapes
            .entry(name.clone())
            .or_default()
            .entry(descriptor.clone())
            .or_default();
        match shape {
            Some(shape) => by_class.insert(class.clone(), shape) != Some(shape),
            None => by_class.remove(class).is_some(),
        }
    }
}

/// What earlier rounds learned about the jar for one rule.
#[derive(Default)]
pub(crate) struct Facts {
    pub summaries: HashMap<MethodKey, Vec<ParamSink>>,
    pub stores: HashMap<MethodKey, Vec<ParamStore>>,
    /// Labels a method returns whatever its caller passes, such as an
    /// accessor for a field holding network data.
    pub returns: HashMap<MethodKey, Labels>,
    /// The descriptors of methods in `returns` by name, so calls to any
    /// other method skip resolving their target.
    pub returning: HashMap<String, HashSet<String>>,
    /// The inputs a method's returned references come from, for methods
    /// whose result comes from fewer than all of their inputs.
    /// Kept by name, then descriptor, then declaring class, so a call looks
    /// one up without building a key.
    pub shapes: HashMap<String, HashMap<String, HashMap<String, Inputs>>>,
    /// The classes declaring a method with a summary or a parameter store,
    /// by the method's name and then descriptor. A call passing labeled or
    /// parameter data only looks among these for the methods it can reach.
    pub learned: HashMap<String, HashMap<String, Vec<String>>>,
    pub fields: HashMap<FieldKey, FieldTaint>,
    /// The sides whose packet data callers pass into a method, so its own
    /// packet buffer parameters carry them too.
    pub entries: HashMap<MethodKey, Labels>,
}

/// Something a method's result depends on, so a change to it means
/// checking the method again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Dependency {
    /// Calls passing labeled or parameter data to methods with this (name,
    /// descriptor), whichever class the call reaches.
    Call(String, String),
    /// Calls passing labeled data to methods with this (name, descriptor),
    /// which parameter stores turn into field writes. Used for calls that
    /// can reach any override.
    Store(String, String),
    /// Calls passing labeled data to this exact method, for calls with one
    /// possible target such as constructors and static methods.
    StoreIn(MethodKey),
    /// The labels this method returns.
    Returns(MethodKey),
    /// The inputs this method's result comes from, which matter to calls
    /// passing it labeled or parameter data.
    Shape(MethodKey),
    Field(FieldKey),
    /// The sides whose packet data callers pass into this method.
    Entry(MethodKey),
}

/// What checking one method produced for one rule.
pub(crate) struct MethodResult {
    pub key: MethodKey,
    pub findings: Vec<Finding>,
    pub summary: Vec<ParamSink>,
    /// Untrusted data the method stores in fields.
    pub fields_written: Vec<(FieldKey, Labels)>,
    pub stores: Vec<ParamStore>,
    pub returns: Labels,
    /// The inputs its returned references come from, when fewer than all.
    pub shape: Option<Inputs>,
    /// Packet data from these sides passed into methods it calls.
    pub entries: Vec<(MethodKey, Labels)>,
    /// Methods it may call and fields it reads.
    pub depends: Vec<Dependency>,
}

struct RuleSources<'s, 'c, 'r, 'a> {
    rule: &'s Rule,
    context: &'c Context<'r, 'a>,
    facts: &'s Facts,
    bootstraps: &'s [BootstrapMethod],
    /// The sides whose packets reach the method being checked.
    sides: Labels,
    /// Known result inputs by call offset. The facts do not change while
    /// one method is checked, and the engine passes over each call many
    /// times.
    shapes: RefCell<HashMap<u32, Option<Inputs>>>,
    /// Labels for call results by call offset, for the same reason.
    calls: RefCell<HashMap<u32, Option<(Labels, String)>>>,
}

impl RuleSources<'_, '_, '_, '_> {
    fn typed(&self, ty: &str) -> Option<&super::spec::Source> {
        self.rule.sources.iter().find(|source| {
            let types: Vec<&str> = source.types.iter().map(String::as_str).collect();
            !types.is_empty() && self.context.hierarchy.extends_any(ty, &types)
        })
    }

    /// Labels a call's result carries because of its owner, a listed
    /// source call, or what the method it reaches returns.
    fn find_call(&self, owner: &str, name: &str, descriptor: &str) -> Option<(Labels, String)> {
        let values = [("owner", owner), ("name", name)];
        if let Some(source) = self.typed(owner) {
            return Some((self.typed_labels(source), fill(&source.call, &values)));
        }
        let listed = self.rule.sources.iter().find_map(|source| {
            source
                .calls
                .iter()
                .any(|sig| {
                    sig.matches_name(name, descriptor)
                        && self.context.hierarchy.extends_any(owner, &[&sig.owner])
                })
                .then(|| (source.label, fill(&source.read, &values)))
        });
        let returning = self
            .facts
            .returning
            .get(name)
            .is_some_and(|descriptors| descriptors.contains(descriptor));
        if listed.is_some() || !returning {
            return listed;
        }
        // A method in the jar that returns labeled data passes it on. Only
        // the method the call resolves to counts, since an override picked
        // from the whole hierarchy would spread one class's data to calls
        // that never reach it.
        let (class, _) = self.context.resolve_method(owner, name, descriptor)?;
        let returned = *self
            .facts
            .returns
            .get(&method_key(&class.name, name, descriptor))?;
        Some((
            returned,
            format!(
                "Calls {}.{name}, which returns {}",
                class.name,
                describe(self.rule, returned)
            ),
        ))
    }

    /// The inputs a call's result comes from, when every method it can
    /// reach has a known shape.
    fn find_result_inputs(
        &self,
        owner: &str,
        name: &str,
        descriptor: &str,
        dispatches: bool,
    ) -> Option<Inputs> {
        let by_class = self.facts.shapes.get(name)?.get(descriptor)?;
        // Every method the call can reach needs a known shape, or the
        // result keeps all of its inputs. The method the call resolves to is
        // checked first, as looking for overrides costs far more. A shape
        // under the named class means that class declares the method, which
        // is then what the call resolves to.
        let shape = match by_class.get(owner) {
            Some(shape) => *shape,
            None => {
                let (resolved, _) = self.context.resolve_method(owner, name, descriptor)?;
                *by_class.get(resolved.name.as_str())?
            }
        };
        if !dispatches {
            return Some(shape);
        }
        call_targets(self.context, owner, name, descriptor, true)
            .iter()
            .try_fold(shape, |acc, class| Some(acc.union(*by_class.get(*class)?)))
    }

    /// A typed source's labels. Network types are packet buffers, so their
    /// data also carries the sides whose packets reach the method.
    fn typed_labels(&self, source: &super::spec::Source) -> Labels {
        if source.origin == DataOrigin::Network {
            Labels(source.label.0 | self.sides.0)
        } else {
            source.label
        }
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
        Some((self.typed_labels(source), fill(template, &[("type", ty)])))
    }

    fn call(
        &self,
        site: u32,
        owner: &str,
        name: &str,
        descriptor: &str,
    ) -> Option<(Labels, String)> {
        if let Some(known) = self.calls.borrow().get(&site) {
            return known.clone();
        }
        let found = self.find_call(owner, name, descriptor);
        self.calls.borrow_mut().insert(site, found.clone());
        found
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
                self.typed_labels(source),
                fill(&source.field, &[("field", &key), ("type", &ty)]),
            ));
        }
        let taint = self.facts.fields.get(&key)?;
        Some((
            taint.labels,
            format!(
                "Reads {key}, which {} fills with {}",
                taint.writer,
                describe(self.rule, taint.labels)
            ),
        ))
    }

    fn result_inputs(
        &self,
        site: u32,
        owner: &str,
        name: &str,
        descriptor: &str,
        dispatches: bool,
    ) -> Option<Inputs> {
        if let Some(known) = self.shapes.borrow().get(&site) {
            return *known;
        }
        let found = self.find_result_inputs(owner, name, descriptor, dispatches);
        self.shapes.borrow_mut().insert(site, found);
        found
    }

    fn lambda_result(&self, index: u16) -> Option<(Labels, String)> {
        let pool = &self.context.parsed.class.constant_pool;
        let lambda = dataflow::lambda_target(pool, self.bootstraps, index)?;
        let (class, _) =
            self.context
                .resolve_method(&lambda.owner, &lambda.name, &lambda.descriptor)?;
        let returned =
            *self
                .facts
                .returns
                .get(&method_key(&class.name, &lambda.name, &lambda.descriptor))?;
        Some((
            returned,
            format!(
                "Gets back what {}.{} returns, which is {}",
                class.name,
                lambda.name,
                describe(self.rule, returned)
            ),
        ))
    }

    fn serializes(&self, owner: &str, name: &str, descriptor: &str) -> Option<(Labels, String)> {
        let values = [("owner", owner), ("name", name)];
        self.rule.sources.iter().find_map(|source| {
            source
                .serializes
                .iter()
                .any(|sig| {
                    sig.matches_name(name, descriptor)
                        && self.context.hierarchy.extends_any(owner, &[&sig.owner])
                })
                .then(|| (source.label, fill(&source.writes, &values)))
        })
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
/// outrank objects the mod serialized itself, which outrank the caller's
/// data.
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
        DataOrigin::Serialized,
    ]
    .into_iter()
    .find(|origin| carries(*origin))
    .unwrap_or(if value.params != 0 {
        DataOrigin::Caller
    } else {
        DataOrigin::Untraced
    })
}

/// Names what data carrying `labels` is, for evidence that it was stored
/// or returned somewhere else.
fn describe(rule: &Rule, labels: Labels) -> &'static str {
    let stored = Value {
        labels,
        ..Value::default()
    };
    match origin_of(rule, &stored) {
        DataOrigin::Network => "network data",
        DataOrigin::LocalFile => "data from a local file",
        DataOrigin::Serialized => "an object it serialized itself",
        _ => "an embedded serialized object",
    }
}

/// The classes with learned facts whose method a call to `owner.name` can
/// run, the one it resolves to plus, when `dispatches`, any override in a
/// class that extends or implements `owner`.
fn learned_targets<'f>(
    context: &Context,
    facts: &'f Facts,
    owner: &str,
    name: &str,
    descriptor: &str,
    dispatches: bool,
) -> Vec<&'f str> {
    let Some(classes) = facts.learned.get(name).and_then(|d| d.get(descriptor)) else {
        return Vec::new();
    };
    let resolved = context
        .resolve_method(owner, name, descriptor)
        .map(|(class, _)| class.name.as_str());
    classes
        .iter()
        .map(String::as_str)
        .filter(|class| {
            Some(*class) == resolved || (dispatches && context.hierarchy.is_subtype(class, owner))
        })
        .collect()
}

/// The classes in the jar whose method a call to `owner.name` can run, the
/// one it resolves to plus, when `dispatches`, every override in a class
/// that extends or implements `owner`.
fn call_targets<'r>(
    context: &Context<'r, '_>,
    owner: &str,
    name: &str,
    descriptor: &str,
    dispatches: bool,
) -> Vec<&'r str> {
    let mut targets: Vec<&'r str> = context
        .resolve_method(owner, name, descriptor)
        .map(|(class, _)| class.name.as_str())
        .into_iter()
        .collect();
    if dispatches {
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
    targets
}

/// Final classes from the JDK with the types each can also be seen as.
const FINAL_TYPES: &[(&str, &[&str])] = &[
    (
        "java/lang/String",
        &[
            "java/lang/CharSequence",
            "java/lang/Comparable",
            "java/lang/constant/Constable",
            "java/lang/constant/ConstantDesc",
        ],
    ),
    ("java/lang/Long", BOXED_NUMBER),
    ("java/lang/Integer", BOXED_NUMBER),
    ("java/lang/Short", BOXED_NUMBER),
    ("java/lang/Byte", BOXED_NUMBER),
    ("java/lang/Double", BOXED_NUMBER),
    ("java/lang/Float", BOXED_NUMBER),
    (
        "java/lang/Boolean",
        &["java/lang/Comparable", "java/lang/constant/Constable"],
    ),
    (
        "java/lang/Character",
        &["java/lang/Comparable", "java/lang/constant/Constable"],
    ),
];

const BOXED_NUMBER: &[&str] = &[
    "java/lang/Number",
    "java/lang/Comparable",
    "java/lang/constant/Constable",
    "java/lang/constant/ConstantDesc",
];

/// Types every array and every final JDK class above is also an instance of.
const UNIVERSAL: &[&str] = &[
    "java/lang/Object",
    "java/io/Serializable",
    "java/lang/Cloneable",
];

/// True when a value whose static type is `ty` can never be an instance of
/// `required`. Only certain cases count, an array against a class other
/// than the types every array has, primitive arrays of different element
/// types, and a final JDK class against a type it does not extend.
fn never_instance(ty: &str, required: &str) -> bool {
    if ty == required || UNIVERSAL.contains(&ty) || UNIVERSAL.contains(&required) {
        return false;
    }
    match (ty.starts_with('['), required.starts_with('[')) {
        (true, true) => {
            // A primitive array descriptor is the bracket and one letter.
            let primitive = |t: &str| t.len() == 2;
            primitive(ty) || primitive(required)
        }
        (true, false) | (false, true) => true,
        (false, false) => {
            let fixed = |class: &str, other: &str| {
                FINAL_TYPES
                    .iter()
                    .find(|(name, _)| *name == class)
                    .is_some_and(|(_, supers)| !supers.contains(&other))
            };
            // A final class can only be seen as itself or a supertype, so a
            // value of another type can only be it if that type is one.
            fixed(ty, required) || fixed(required, ty)
        }
    }
}

/// A call into a method whose summary leads a parameter to this sink.
struct Via {
    callee: String,
    param: usize,
    steps: Vec<EvidenceStep>,
    /// The type the callee needs its argument to have.
    requires: Option<Rc<str>>,
    /// The call is the creation of a lambda or method reference that
    /// captures the data, rather than a direct call.
    lambda: bool,
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
    /// The data is built only from arrays this method created and never
    /// wrote, so it is all zeros and deserializing it creates nothing.
    empty: bool,
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
    let key = method_key(
        &context.parsed.name,
        &method_ref.name,
        &method_ref.descriptor,
    );
    let registered = context.registrations.sides(
        &context.parsed.name,
        &method_ref.name,
        &method_ref.descriptor,
    );
    let passed = facts.entries.get(&key).copied().unwrap_or_default();
    let sides = Labels(registered.0 | passed.0);
    let bootstraps = class.bootstrap_methods().unwrap_or_default();
    let policy = RuleSources {
        rule,
        context,
        facts,
        bootstraps: &bootstraps,
        sides,
        shapes: RefCell::new(HashMap::new()),
        calls: RefCell::new(HashMap::new()),
    };
    let mut observer = Observer {
        rule,
        context,
        facts,
        bootstraps: &bootstraps,
        sides,
        sink_uses: rule.sinks.iter().map(|_| SinkUse::default()).collect(),
        seen: Seen::default(),
    };
    dataflow::analyze(class, method, &policy, &mut |site, frame| {
        observer.observe(site, frame);
    });
    let Observer {
        sink_uses,
        mut seen,
        ..
    } = observer;
    seen.depends.push(Dependency::Entry(key.clone()));
    seen.depends.sort();
    seen.depends.dedup();
    seen.stores.sort();
    seen.stores.dedup();

    // A reference result coming from fewer than all inputs is worth
    // recording, so callers pass on only what it really comes from.
    let parsed_type = MethodType::parse(&method_ref.descriptor);
    let shape = parsed_type
        .returns
        .as_ref()
        .is_some_and(|r| r.reference.is_some())
        .then(|| {
            let count = parsed_type.params.len().min(64);
            let all = Inputs {
                params: if count == 64 {
                    u64::MAX
                } else {
                    (1 << count) - 1
                },
                receiver: method.access_flags & ACC_STATIC == 0,
            };
            (seen.returned != all).then_some(seen.returned)
        })
        .flatten();
    let mut result = MethodResult {
        key,
        shape,
        findings: Vec::new(),
        summary: Vec::new(),
        fields_written: seen.fields_written,
        stores: seen.stores,
        returns: seen.returns,
        entries: seen.entries,
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

const ACC_STATIC: u16 = 0x0008;

/// Fields, calls, and returns of one method, gathered while it is replayed.
#[derive(Default)]
struct Seen {
    fields_written: Vec<(FieldKey, Labels)>,
    stores: Vec<ParamStore>,
    /// Labels on returned values that did not come in with a parameter.
    returns: Labels,
    /// The inputs returned references come from.
    returned: Inputs,
    entries: Vec<(MethodKey, Labels)>,
    depends: Vec<Dependency>,
}

impl Seen {
    /// Records `value` being stored in `field`, as untrusted data when it
    /// carries labels and as a parameter store when it comes from one.
    fn store(&mut self, field: FieldKey, value: &Value) {
        for param in (0..64).filter(|p| value.params & (1 << p) != 0) {
            self.stores.push((param, field.clone()));
        }
        self.write(field, value);
    }

    /// Records untrusted data in `value` being stored in `field`.
    fn write(&mut self, field: FieldKey, value: &Value) {
        if !value.labels.is_empty() {
            self.fields_written.push((field, value.labels));
        }
    }
}

/// Collection methods that store their arguments in the collection.
const COLLECTION_STORES: &[&str] = &[
    "add",
    "addAll",
    "addElement",
    "addFirst",
    "addLast",
    "compute",
    "computeIfAbsent",
    "computeIfPresent",
    "insertElementAt",
    "merge",
    "offer",
    "offerFirst",
    "offerLast",
    "push",
    "put",
    "putAll",
    "putFirst",
    "putIfAbsent",
    "putLast",
    "replace",
    "set",
];

/// A call into methods in the jar, through a call instruction or the
/// creation of a lambda.
struct Callee<'v> {
    /// Classes whose method the call can run and has learned facts.
    learned: Vec<String>,
    /// Classes whose method the call can run and that receive packet data
    /// from a known side through it.
    entered: Vec<String>,
    /// Sides passed to `entered` besides those the arguments carry.
    sides: Labels,
    name: String,
    descriptor: String,
    /// The value passed as each declared parameter, where the call site
    /// supplies it.
    arguments: Vec<Option<&'v Value>>,
    lambda: bool,
}

/// True when any argument carries packet data from a known side.
fn carries_sides(arguments: &[Option<&Value>]) -> bool {
    arguments
        .iter()
        .flatten()
        .any(|value| value.labels.0 & FROM_EITHER.0 != 0)
}

/// Watches one method's replay for sinks, stores, and calls into what
/// earlier rounds learned.
struct Observer<'o, 'r, 'a> {
    rule: &'o Rule,
    context: &'o Context<'r, 'a>,
    facts: &'o Facts,
    bootstraps: &'o [BootstrapMethod],
    /// The sides whose packets reach the method being checked.
    sides: Labels,
    sink_uses: Vec<SinkUse>,
    seen: Seen,
}

impl Observer<'_, '_, '_> {
    fn observe(&mut self, site: &Site, frame: &Frame) {
        let ins = site.instruction;
        match (ins.opcode, &ins.operand) {
            (op::GETSTATIC..=op::PUTFIELD, Operand::Constant(index)) => {
                let Ok(field) = site.pool.member_ref(*index) else {
                    return;
                };
                let key = self.context.resolve_field(&field.class_name, &field.name);
                match ins.opcode {
                    op::PUTSTATIC | op::PUTFIELD => {
                        if let Some(value) = frame.peek(0) {
                            self.seen.store(key, value);
                        }
                    }
                    _ => self.seen.depends.push(Dependency::Field(key)),
                }
            }
            // Only references are followed through returns. Labeled numbers
            // and flags returned from accessors spread to every caller round
            // after round, and none of them can be deserialized.
            (op::ARETURN, _) => {
                if let Some(value) = frame.peek(0) {
                    self.seen.returned = self.seen.returned.union(value.inputs());
                    if value.origin.as_ref().is_some_and(|o| !o.parameter) {
                        self.seen.returns.0 |= value.labels.0;
                    }
                }
            }
            (op::INVOKEDYNAMIC, Operand::Constant(index)) => self.lambda(site, frame, *index),
            (
                op::INVOKEVIRTUAL | op::INVOKESPECIAL | op::INVOKESTATIC,
                Operand::Constant(index),
            )
            | (op::INVOKEINTERFACE, Operand::InvokeInterface { index, .. }) => {
                self.call(site, frame, *index)
            }
            _ => {}
        }
    }

    fn call(&mut self, site: &Site, frame: &Frame, index: u16) {
        let ins = site.instruction;
        let Ok(target) = site.pool.member_ref(index) else {
            return;
        };
        let (owner, name, descriptor) = (
            target.class_name.as_ref(),
            target.name.as_ref(),
            target.descriptor.as_ref(),
        );
        // Each value takes one stack entry in the engine, wide or not.
        let count = MethodType::parse(descriptor).params.len();
        let at = |target: Target| target.depth(count).and_then(|d| frame.peek(d));

        // Adding to a collection read from a field stores into that field.
        if ins.opcode != op::INVOKESTATIC
            && owner.starts_with("java/util/")
            && COLLECTION_STORES.contains(&name)
            && let Some(field) = at(Target::Receiver).and_then(|r| r.field.as_deref())
            && let Some((field_owner, field_name)) = field.rsplit_once('.')
        {
            let key = self.context.resolve_field(field_owner, field_name);
            for value in (0..count).filter_map(|i| at(Target::Argument(i))) {
                self.seen.store(key.clone(), value);
            }
        }

        // Calls into methods in the jar, and through their summaries, into
        // the sinks those methods pass a parameter to. A virtual or
        // interface call can reach any override in a class that extends or
        // implements the named owner, so each of those counts. Targets are
        // only looked for when some method with this name and descriptor
        // has learned facts. Those facts only matter to a call passing
        // labeled or parameter data, while returned labels matter to any
        // call of the method it resolves to.
        let arguments: Vec<Option<&Value>> = (0..count).map(|i| at(Target::Argument(i))).collect();
        let dispatches = matches!(ins.opcode, op::INVOKEVIRTUAL | op::INVOKEINTERFACE);
        let receiver = (ins.opcode != op::INVOKESTATIC)
            .then(|| at(Target::Receiver))
            .flatten();
        let carries =
            self.depend_on_arguments(receiver, &arguments, owner, name, descriptor, dispatches);
        if MethodType::parse(descriptor).returns.is_some()
            && let Some((class, _)) = self.context.resolve_method(owner, name, descriptor)
        {
            let key = method_key(&class.name, name, descriptor);
            if carries {
                self.seen.depends.push(Dependency::Shape(key.clone()));
            }
            self.seen.depends.push(Dependency::Returns(key));
        }
        let learned = if carries {
            learned_targets(
                self.context,
                self.facts,
                owner,
                name,
                descriptor,
                dispatches,
            )
        } else {
            Vec::new()
        };
        let entered = self.entered(&arguments, owner, name, descriptor, dispatches);
        if !learned.is_empty() || !entered.is_empty() {
            self.apply_callee(
                ins.offset,
                Callee {
                    learned: learned.into_iter().map(str::to_owned).collect(),
                    entered,
                    sides: Labels::default(),
                    name: name.to_owned(),
                    descriptor: descriptor.to_owned(),
                    arguments,
                    lambda: false,
                },
            );
        }
        observe_sinks(
            self.rule,
            self.context,
            ins,
            frame,
            &mut self.sink_uses,
            owner,
            name,
            descriptor,
        );
    }

    /// Records what the facts about a callee with this signature mean to
    /// this call, given what its arguments carry. Returns true when they
    /// carry labeled or parameter data, so the callee's facts can apply.
    fn depend_on_arguments(
        &mut self,
        receiver: Option<&Value>,
        arguments: &[Option<&Value>],
        owner: &str,
        name: &str,
        descriptor: &str,
        dispatches: bool,
    ) -> bool {
        // A receiver carrying data matters too, as the callee's result may
        // or may not come from it.
        let carries = receiver.is_some_and(Value::carries_anything)
            || arguments.iter().flatten().any(|v| v.carries_anything());
        if carries {
            self.seen
                .depends
                .push(Dependency::Call(name.to_owned(), descriptor.to_owned()));
        }
        if arguments.iter().flatten().any(|v| !v.labels.is_empty()) {
            if dispatches {
                self.seen
                    .depends
                    .push(Dependency::Store(name.to_owned(), descriptor.to_owned()));
            } else if let Some((class, _)) = self.context.resolve_method(owner, name, descriptor) {
                self.seen.depends.push(Dependency::StoreIn(method_key(
                    &class.name,
                    name,
                    descriptor,
                )));
            }
        }
        carries
    }

    /// True when a method with this descriptor takes a packet buffer.
    fn takes_buffer(&self, descriptor: &str) -> bool {
        MethodType::parse(descriptor)
            .params
            .iter()
            .filter_map(|param| param.reference.as_deref())
            .any(|ty| {
                self.rule.sources.iter().any(|source| {
                    let types: Vec<&str> = source.types.iter().map(String::as_str).collect();
                    source.origin == DataOrigin::Network
                        && !types.is_empty()
                        && self.context.hierarchy.extends_any(ty, &types)
                })
            })
    }

    /// The classes whose method a call reaches with packet data from a
    /// known side, when that method takes a packet buffer that the data's
    /// sides then apply to.
    fn entered(
        &self,
        arguments: &[Option<&Value>],
        owner: &str,
        name: &str,
        descriptor: &str,
        dispatches: bool,
    ) -> Vec<String> {
        if !carries_sides(arguments) || !self.takes_buffer(descriptor) {
            return Vec::new();
        }
        call_targets(self.context, owner, name, descriptor, dispatches)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// The creation of a lambda or method reference counts as a call into
    /// the method holding its body, with the captured values as that
    /// method's leading parameters.
    fn lambda(&mut self, site: &Site, frame: &Frame, index: u16) {
        let Some(lambda) = dataflow::lambda_target(site.pool, self.bootstraps, index) else {
            return;
        };
        // A call handed the function object can return what its body
        // returns, so this method depends on that.
        if let Some((class, _)) =
            self.context
                .resolve_method(&lambda.owner, &lambda.name, &lambda.descriptor)
        {
            self.seen.depends.push(Dependency::Returns(method_key(
                &class.name,
                &lambda.name,
                &lambda.descriptor,
            )));
        }
        let count = MethodType::parse(&lambda.descriptor).params.len();
        let mut arguments = vec![None; count];
        for captured in 0..lambda.captured {
            if let Some(param) = lambda.parameter(captured).filter(|p| *p < count) {
                arguments[param] = frame.peek(lambda.captured - 1 - captured);
            }
        }
        // A lambda taking a packet buffer, made by a method reading packets
        // from known sides, is almost always handed that same buffer, as
        // with a reader passed to a buffer's own list or map reader.
        let creator = Labels(self.sides.0 & FROM_EITHER.0);
        let inherits = !creator.is_empty() && self.takes_buffer(&lambda.descriptor);
        let carries = self.depend_on_arguments(
            None,
            &arguments,
            &lambda.owner,
            &lambda.name,
            &lambda.descriptor,
            lambda.dispatches,
        );
        if !carries && !inherits {
            return;
        }
        let learned = learned_targets(
            self.context,
            self.facts,
            &lambda.owner,
            &lambda.name,
            &lambda.descriptor,
            lambda.dispatches,
        );
        let entered = if inherits {
            call_targets(
                self.context,
                &lambda.owner,
                &lambda.name,
                &lambda.descriptor,
                lambda.dispatches,
            )
            .into_iter()
            .map(str::to_owned)
            .collect()
        } else {
            self.entered(
                &arguments,
                &lambda.owner,
                &lambda.name,
                &lambda.descriptor,
                lambda.dispatches,
            )
        };
        if learned.is_empty() && entered.is_empty() {
            return;
        }
        self.apply_callee(
            site.instruction.offset,
            Callee {
                learned: learned.into_iter().map(str::to_owned).collect(),
                entered,
                sides: if inherits { creator } else { Labels::default() },
                name: lambda.name,
                descriptor: lambda.descriptor,
                arguments,
                lambda: true,
            },
        );
    }

    /// Applies what is known about a callee to the values passed into it,
    /// its summaries as sink uses at this call and its parameter stores as
    /// stores into those fields. Packet data from a known side passed in
    /// tells the callee which sides reach it.
    fn apply_callee(&mut self, offset: u32, callee: Callee) {
        let sides = callee
            .arguments
            .iter()
            .flatten()
            .fold(callee.sides.0, |acc, value| {
                acc | (value.labels.0 & FROM_EITHER.0)
            });
        for target_class in &callee.entered {
            let key = method_key(target_class, &callee.name, &callee.descriptor);
            self.seen.entries.push((key, Labels(sides)));
        }
        let mut reached: Vec<(usize, usize)> = Vec::new();
        for target_class in &callee.learned {
            let key = method_key(target_class, &callee.name, &callee.descriptor);
            for (param, field) in self.facts.stores.get(&key).into_iter().flatten() {
                if let Some(Some(value)) = callee.arguments.get(*param) {
                    self.seen.write(field.clone(), value);
                }
            }
            for param_sink in self.facts.summaries.get(&key).into_iter().flatten() {
                if reached.contains(&(param_sink.param, param_sink.sink)) {
                    continue;
                }
                let Some(Some(data)) = callee.arguments.get(param_sink.param) else {
                    continue;
                };
                if let (Some(ty), Some(required)) = (&data.ty, &param_sink.requires)
                    && never_instance(ty, required)
                {
                    continue;
                }
                reached.push((param_sink.param, param_sink.sink));
                self.sink_uses[param_sink.sink].uses.push(Use {
                    offset,
                    data: (*data).clone(),
                    empty: false,
                    created: None,
                    outside: None,
                    via: Some(Via {
                        callee: format!("{target_class}.{}", callee.name),
                        param: param_sink.param,
                        steps: param_sink.steps.clone(),
                        requires: param_sink.requires.clone(),
                        lambda: callee.lambda,
                    }),
                });
            }
        }
    }
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
    let created_from = |value: &Value, types: &[String]| {
        value
            .alloc
            .clone()
            .filter(|a| a.made && extends(&a.class, types))
    };

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
                        empty: !stream.carries_anything()
                            && frame.holds_only_empty_arrays(created.offset),
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
                        empty: !data.carries_anything()
                            && data
                                .alloc
                                .as_ref()
                                .is_some_and(|a| frame.holds_only_empty_arrays(a.offset)),
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
    // Only an object the method created shows its real class.
    let class = value.alloc.as_ref().filter(|a| a.made).map(|a| &*a.class);
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
    if item.empty {
        return Assessment {
            severity: None,
            origin,
            safeguard: None,
            reasons: Vec::new(),
            unlimited: false,
        };
    }
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
            return guarded(Safeguard::UncheckedSubclass, vec![(text, created.site())]);
        }
        if let Some(restriction) = sink.restriction.as_ref().filter(|_| custom) {
            let judgment = restriction::judge(context, &sink.types, &created.class, restriction);
            let note = (judgment.note(restriction, &created.class), created.site());
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
        let description = if via.lambda {
            format!(
                "Captures the data in a lambda or method reference that runs {} with it as parameter {}",
                via.callee,
                via.param + 1
            )
        } else {
            format!(
                "Passes the data to {} as parameter {}",
                via.callee,
                via.param + 1
            )
        };
        steps.push(step(description, item.offset));
        steps.extend(via.steps.iter().cloned());
        return steps;
    }
    if let (Some(created), Some(creates)) = (&item.created, &sink.creates) {
        steps.push(step(
            fill(creates, &[("type", &created.class)]),
            created.site(),
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
            // A parameter reaching the sink unchanged must have the type it
            // has there, or the type the callee it goes on to needs.
            let requires = (item.data.param == Some(param))
                .then(|| {
                    item.via
                        .as_ref()
                        .and_then(|via| via.requires.clone())
                        .or_else(|| item.data.ty.clone())
                })
                .flatten();
            if !known {
                result.summary.push(ParamSink {
                    param,
                    sink: index,
                    steps: steps.clone(),
                    requires,
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
        exposure: exposure::exposure(assessment.origin, item.data.labels),
        evidence,
    });
}
