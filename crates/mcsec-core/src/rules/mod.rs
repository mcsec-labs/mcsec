//! Detection rules. Rules are definition files run through the data flow
//! engine, and each finding carries the exact location and evidence behind it.
//!
//! Each rule runs over every method once. A method that passes one of its
//! own parameters into a sink gets a summary, and so does one that stores a
//! parameter in a field or returns untrusted data. A field that some method
//! fills with untrusted data, directly or through a collection it holds, is
//! recorded. The methods calling such a method, creating a lambda that runs
//! it, or reading such a field are then checked again with what was learned,
//! so data is followed from method to method and through fields to the
//! sink. Rechecking repeats until nothing changes, up to a bound on rounds.

mod exposure;
mod flow;
mod restriction;
pub mod spec;

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::analysis::{Classes, Constants, Hierarchy, Libraries, ParsedArchive, ParsedClass};
use crate::class_file::{BootstrapMethod, Member, Operand, op};
use crate::dataflow;
use crate::finding::{Finding, Location, MethodRef};
use exposure::Registrations;
use flow::{Dependency, Facts, FieldTaint, MethodKey, MethodResult};

/// Bound on rounds of rechecking, which is how many calls or field hops
/// deep data is followed.
const MAX_ROUNDS: usize = 8;

/// Runs every rule over a jar and the archives nested in it.
pub fn run(root: &ParsedArchive) -> Vec<Finding> {
    let hierarchy = Hierarchy::build(root);
    let libraries = Libraries::build(root);
    let classes = Classes::build(root);
    let constants = Constants::build(root);
    let registrations = Registrations::build(root);

    let mut slots = Vec::new();
    for archive in root.walk() {
        for parsed in &archive.classes {
            let context = Context {
                archive,
                parsed,
                hierarchy: &hierarchy,
                libraries: &libraries,
                classes: &classes,
                constants: &constants,
                registrations: &registrations,
            };
            for method in &parsed.class.methods {
                slots.push((context.clone(), method));
            }
        }
    }

    let order = callee_first(&slots);
    let mut findings = Vec::new();
    for rule in spec::embedded() {
        let mut facts = Facts::default();
        // Callees go first, and what each method returns is learned as soon
        // as it is checked, so its callers already see it.
        let mut results: Vec<Option<MethodResult>> = (0..slots.len()).map(|_| None).collect();
        for &index in &order {
            let (context, method) = &slots[index];
            let result = flow::check_method(rule, context, method, &facts);
            if let Some(result) = &result {
                learn_returned(&mut facts, result);
            }
            results[index] = result;
        }
        let mut changed = learn(&mut facts, &results, |_| true);

        // Methods by the hash of what they depend on, so a round visits only
        // the methods holding a dependency that changed. Two dependencies
        // sharing a hash only cause an extra recheck.
        let mut dependents: HashMap<u64, Vec<usize>> = HashMap::new();
        for (index, result) in results.iter().enumerate() {
            index_depends(&mut dependents, index, result.as_ref());
        }

        for _ in 0..MAX_ROUNDS {
            if changed.is_empty() {
                break;
            }
            let mut affected: Vec<usize> = changed
                .iter()
                .filter_map(|d| dependents.get(&hash_of(d)))
                .flatten()
                .copied()
                .collect();
            affected.sort_unstable();
            affected.dedup();
            let mut rechecked = vec![false; slots.len()];
            for index in affected {
                let (context, method) = &slots[index];
                results[index] = flow::check_method(rule, context, method, &facts);
                rechecked[index] = true;
                index_depends(&mut dependents, index, results[index].as_ref());
            }
            changed = learn(&mut facts, &results, |i| rechecked[i]);
        }
        findings.extend(results.into_iter().flatten().flat_map(|r| r.findings));
    }
    findings
}

/// Slot indexes ordered so each method comes after the methods it calls in
/// the jar, as far as calls do not form a cycle. A call counts toward the
/// method it resolves to, and creating a lambda toward the method holding
/// its body.
fn callee_first(slots: &[(Context, &Member)]) -> Vec<usize> {
    let mut index_of: HashMap<(&str, String, String), usize> = HashMap::new();
    for (index, (context, method)) in slots.iter().enumerate() {
        let pool = &context.parsed.class.constant_pool;
        if let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) {
            index_of.insert(
                (
                    context.parsed.name.as_str(),
                    name.into_owned(),
                    descriptor.into_owned(),
                ),
                index,
            );
        }
    }
    let mut bootstraps: HashMap<&str, Vec<BootstrapMethod>> = HashMap::new();
    let callees: Vec<Vec<usize>> = slots
        .iter()
        .map(|(context, method)| {
            let pool = &context.parsed.class.constant_pool;
            let Ok(Some(code)) = method.code(pool) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            for ins in code.instructions().flatten() {
                let target = match (ins.opcode, &ins.operand) {
                    (op::INVOKEDYNAMIC, Operand::Constant(index)) => {
                        let methods = bootstraps
                            .entry(context.parsed.name.as_str())
                            .or_insert_with(|| {
                                context.parsed.class.bootstrap_methods().unwrap_or_default()
                            });
                        dataflow::lambda_target(pool, methods, *index)
                            .map(|l| (l.owner, l.name, l.descriptor))
                    }
                    (
                        op::INVOKEVIRTUAL | op::INVOKESPECIAL | op::INVOKESTATIC,
                        Operand::Constant(index),
                    )
                    | (op::INVOKEINTERFACE, Operand::InvokeInterface { index, .. }) => {
                        pool.member_ref(*index).ok().map(|m| {
                            (
                                m.class_name.into_owned(),
                                m.name.into_owned(),
                                m.descriptor.into_owned(),
                            )
                        })
                    }
                    _ => None,
                };
                let Some((owner, name, descriptor)) = target else {
                    continue;
                };
                let Some((class, _)) = context.resolve_method(&owner, &name, &descriptor) else {
                    continue;
                };
                if let Some(&callee) = index_of.get(&(class.name.as_str(), name, descriptor))
                    && !out.contains(&callee)
                {
                    out.push(callee);
                }
            }
            out
        })
        .collect();

    // Depth first, recording each method once all it calls are recorded.
    let mut order = Vec::with_capacity(slots.len());
    let mut visited = vec![false; slots.len()];
    for start in 0..slots.len() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some((node, next)) = stack.last_mut() {
            if let Some(&callee) = callees[*node].get(*next) {
                *next += 1;
                if !visited[callee] {
                    visited[callee] = true;
                    stack.push((callee, 0));
                }
            } else {
                order.push(*node);
                stack.pop();
            }
        }
    }
    order
}

/// Learns the inputs and labels a method's result comes from right after it
/// is checked, so methods checked later in the same pass use them.
fn learn_returned(facts: &mut Facts, result: &MethodResult) {
    let (_, name, descriptor) = &result.key;
    if result.shape.is_some() {
        facts.set_shape(&result.key, result.shape);
    }
    if !result.returns.is_empty() {
        facts.returns.entry(result.key.clone()).or_default().0 |= result.returns.0;
        facts
            .returning
            .entry(name.clone())
            .or_default()
            .insert(descriptor.clone());
    }
}

/// Records the method at `index` under each dependency of its result. A
/// dependency a recheck no longer has stays recorded, which only costs an
/// extra recheck later.
fn index_depends(
    dependents: &mut HashMap<u64, Vec<usize>>,
    index: usize,
    result: Option<&MethodResult>,
) {
    for dependency in result.into_iter().flat_map(|r| &r.depends) {
        let methods = dependents.entry(hash_of(dependency)).or_default();
        if methods.last() != Some(&index) {
            methods.push(index);
        }
    }
}

fn hash_of(dependency: &Dependency) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    dependency.hash(&mut hasher);
    hasher.finish()
}

/// Adds the summaries and field contents in `results` to `facts`, for the
/// results `include` selects, and returns what grew.
fn learn(
    facts: &mut Facts,
    results: &[Option<MethodResult>],
    include: impl Fn(usize) -> bool,
) -> HashSet<Dependency> {
    let mut changed = HashSet::new();
    for (index, result) in results.iter().enumerate() {
        let Some(result) = result.as_ref().filter(|_| include(index)) else {
            continue;
        };
        // Summaries and stores matter to calls by signature, returned
        // labels to calls of this exact method.
        let (_, name, descriptor) = &result.key;
        let mut grew = false;
        let known = facts.summaries.get(&result.key).map_or(0, Vec::len);
        if result.summary.len() > known {
            facts
                .summaries
                .insert(result.key.clone(), result.summary.clone());
            changed.insert(Dependency::Call(name.clone(), descriptor.clone()));
            grew = true;
        }
        // Stores and shapes are replaced rather than grown. A recheck with a
        // callee's exact result can show a store or an input never happens.
        if facts.stores.get(&result.key).map_or(&[][..], Vec::as_slice) != result.stores {
            if result.stores.is_empty() {
                facts.stores.remove(&result.key);
            } else {
                facts
                    .stores
                    .insert(result.key.clone(), result.stores.clone());
                grew = true;
            }
            changed.insert(Dependency::Store(name.clone(), descriptor.clone()));
            changed.insert(Dependency::StoreIn(result.key.clone()));
        }
        if facts.set_shape(&result.key, result.shape) {
            // Shapes only narrow as facts improve, so a call still using an
            // override's earlier shape keeps more inputs than it needs, never
            // fewer.
            changed.insert(Dependency::Shape(result.key.clone()));
        }
        if !result.returns.is_empty() {
            let returns = facts.returns.entry(result.key.clone()).or_default();
            if returns.0 | result.returns.0 != returns.0 {
                returns.0 |= result.returns.0;
                facts
                    .returning
                    .entry(name.clone())
                    .or_default()
                    .insert(descriptor.clone());
                changed.insert(Dependency::Returns(result.key.clone()));
            }
        }
        for (callee, sides) in &result.entries {
            let known = facts.entries.entry(callee.clone()).or_default();
            if known.0 | sides.0 != known.0 {
                known.0 |= sides.0;
                changed.insert(Dependency::Entry(callee.clone()));
            }
        }
        if grew {
            let classes = facts
                .learned
                .entry(name.clone())
                .or_default()
                .entry(descriptor.clone())
                .or_default();
            if !classes.contains(&result.key.0) {
                classes.push(result.key.0.clone());
            }
        }
    }

    // Field contents come from every method's latest result, so a write a
    // recheck no longer makes stops counting.
    let mut fields: HashMap<String, FieldTaint> = HashMap::new();
    for result in results.iter().flatten() {
        for (field, labels) in &result.fields_written {
            let taint = fields.entry(field.clone()).or_insert_with(|| FieldTaint {
                labels: Default::default(),
                writer: format!("{}.{}", result.key.0, result.key.1),
            });
            taint.labels.0 |= labels.0;
        }
    }
    for field in facts.fields.keys().chain(fields.keys()) {
        let before = facts.fields.get(field).map(|t| t.labels);
        let after = fields.get(field).map(|t| t.labels);
        if before != after {
            changed.insert(Dependency::Field(field.clone()));
        }
    }
    facts.fields = fields;
    changed
}

/// What a rule sees while checking one class.
#[derive(Clone)]
pub(crate) struct Context<'r, 'a> {
    pub archive: &'r ParsedArchive<'a>,
    pub parsed: &'r ParsedClass<'a>,
    pub hierarchy: &'r Hierarchy,
    pub libraries: &'r Libraries,
    pub classes: &'r Classes<'r, 'a>,
    pub constants: &'r Constants,
    pub registrations: &'r Registrations,
}

impl<'r, 'a> Context<'r, 'a> {
    /// A location in the current class, narrowed to a method and offset.
    pub fn location(&self, method: &MethodRef, offset: u32) -> Location {
        Location {
            archive_path: self.archive.archive.path.clone(),
            entry: Some(self.parsed.entry.name.clone()),
            class_name: Some(self.parsed.name.clone()),
            method: Some(method.clone()),
            bytecode_offset: Some(offset),
        }
    }

    /// A field's key, named by the class in the jar that declares it, found
    /// by walking up from the class an instruction names. A field declared
    /// outside the jar keeps the named class.
    pub fn resolve_field(&self, owner: &str, name: &str) -> String {
        let mut current = owner.to_owned();
        let mut seen = HashSet::new();
        while seen.insert(current.clone()) {
            let Some(parsed) = self.classes.get(&current) else {
                break;
            };
            let pool = &parsed.class.constant_pool;
            if parsed
                .class
                .fields
                .iter()
                .any(|f| f.name(pool).is_ok_and(|n| n == name))
            {
                return format!("{current}.{name}");
            }
            match self.hierarchy.super_of(&current) {
                Some(parent) => current = parent.to_owned(),
                None => break,
            }
        }
        format!("{owner}.{name}")
    }

    /// The method with a body that a call reaches in the jar, from its
    /// owner up through the superclasses the jar contains.
    pub fn resolve_method(
        &self,
        owner: &str,
        name: &str,
        descriptor: &str,
    ) -> Option<(&'r ParsedClass<'a>, &'r Member<'a>)> {
        // Most calls name a class from outside the jar, such as the JDK.
        let parsed = self.classes.get(owner)?;
        if let Some(method) = declared_method(parsed, name, descriptor) {
            return Some((parsed, method));
        }
        let mut current = owner.to_owned();
        let mut seen = HashSet::new();
        // A cycle cannot occur in classes the JVM loads, but a crafted jar
        // can contain one.
        while seen.insert(current.clone()) {
            let parsed = self.classes.get(&current)?;
            if let Some(method) = declared_method(parsed, name, descriptor) {
                return Some((parsed, method));
            }
            current = self.hierarchy.super_of(&current)?.to_owned();
        }
        None
    }
}

/// A method with a body that `parsed` itself declares.
pub(crate) fn declared_method<'c, 'a>(
    parsed: &'c ParsedClass<'a>,
    name: &str,
    descriptor: &str,
) -> Option<&'c Member<'a>> {
    let pool = &parsed.class.constant_pool;
    parsed.class.methods.iter().find(|m| {
        m.name(pool).is_ok_and(|n| n == name)
            && m.descriptor(pool).is_ok_and(|d| d == descriptor)
            && m.code(pool).is_ok_and(|code| code.is_some())
    })
}

/// Keys of methods by the class that declares them.
pub(crate) fn method_key(class: &str, name: &str, descriptor: &str) -> MethodKey {
    (class.to_owned(), name.to_owned(), descriptor.to_owned())
}
