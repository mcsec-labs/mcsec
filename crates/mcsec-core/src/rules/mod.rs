//! Detection rules. Rules are definition files run through the data flow
//! engine, and each finding carries the exact location and evidence behind it.
//!
//! Each rule runs over every method once. A method that passes one of its
//! own parameters into a sink gets a summary, and a field that some method
//! fills with untrusted data is recorded. The methods calling such a method
//! or reading such a field are then checked again with what was learned, so
//! data is followed from method to method and through fields to the sink.
//! Rechecking repeats until nothing changes, up to a bound on rounds.

mod flow;
mod restriction;
pub mod spec;

use std::collections::HashSet;

use crate::analysis::{Classes, Constants, Hierarchy, Libraries, ParsedArchive, ParsedClass};
use crate::class_file::Member;
use crate::finding::{Finding, Location, MethodRef};
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
            };
            for method in &parsed.class.methods {
                slots.push((context.clone(), method));
            }
        }
    }

    let mut findings = Vec::new();
    for rule in spec::embedded() {
        let mut facts = Facts::default();
        let mut results: Vec<Option<MethodResult>> = slots
            .iter()
            .map(|(context, method)| flow::check_method(rule, context, method, &facts))
            .collect();
        let mut changed = learn(&mut facts, &results, |_| true);

        for _ in 0..MAX_ROUNDS {
            if changed.is_empty() {
                break;
            }
            let mut rechecked = vec![false; slots.len()];
            for ((context, method), (result, again)) in slots
                .iter()
                .zip(results.iter_mut().zip(rechecked.iter_mut()))
            {
                let affected = result
                    .as_ref()
                    .is_some_and(|r| r.depends.iter().any(|d| changed.contains(d)));
                if affected {
                    *result = flow::check_method(rule, context, method, &facts);
                    *again = true;
                }
            }
            changed = learn(&mut facts, &results, |i| rechecked[i]);
        }
        findings.extend(results.into_iter().flatten().flat_map(|r| r.findings));
    }
    findings
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
        let known = facts.summaries.get(&result.key).map_or(0, Vec::len);
        if result.summary.len() > known {
            facts
                .summaries
                .insert(result.key.clone(), result.summary.clone());
            let (_, name, descriptor) = result.key.clone();
            facts.summarized.insert((name.clone(), descriptor.clone()));
            changed.insert(Dependency::Call(name, descriptor));
        }
        for (field, labels) in &result.fields_written {
            let taint = facts
                .fields
                .entry(field.clone())
                .or_insert_with(|| FieldTaint {
                    labels: Default::default(),
                    writer: format!("{}.{}", result.key.0, result.key.1),
                });
            if taint.labels.0 | labels.0 != taint.labels.0 {
                taint.labels.0 |= labels.0;
                changed.insert(Dependency::Field(field.clone()));
            }
        }
    }
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
