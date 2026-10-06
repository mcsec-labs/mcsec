//! Judges whether a subclass of a stream type restricts the classes it
//! creates, by reading the code of the method that resolves them.
//!
//! A restricting override cannot hand back a class the name chose unless a
//! lookup on that name succeeded first, on every path including its
//! exception handlers. That is an allowlist whatever the lookup is, a set,
//! a map, a string comparison, a prefix check, or a helper that throws. An
//! override that checks every class but throws for a missing one only when
//! a setting allows, falling back to logging otherwise, is a conditional
//! allowlist. An override that throws only for classes its lookup finds is a
//! blocklist,
//! which any gadget class missing from the list gets past. One that can
//! return a class for any name, such as by asking a class loader first and
//! checking a list only when that fails, restricts nothing.

use std::collections::{HashMap, HashSet};

use super::spec::Restriction;
use super::{Context, declared_method};
use crate::analysis::ParsedClass;
use crate::class_file::Member;
use crate::dataflow::{self, LabeledCall, Labels, Policy};

/// The label for the class being resolved and values computed from it.
const RESOLVED: Labels = Labels(1);

/// Bound on how far the resolved class is followed into other methods.
const MAX_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Judgment {
    /// The named class, or one it delegates to, throws unless the class is
    /// one it finds.
    Allowlist(String),
    /// Checks every class against its allowed set, but rejects a missing
    /// one only on some paths, such as when a setting turns blocking on.
    ConditionalAllowlist(String),
    Blocklist(String),
    Open(String),
    Inherits,
    Unseen,
}

impl Judgment {
    pub fn note(&self, restriction: &Restriction, created: &str) -> String {
        let (template, ty) = match self {
            Self::Allowlist(class) => (&restriction.allowlist, class.as_str()),
            Self::ConditionalAllowlist(class) => (&restriction.conditional, class.as_str()),
            Self::Blocklist(class) => (&restriction.blocklist, class.as_str()),
            Self::Open(class) => (&restriction.open, class.as_str()),
            Self::Inherits => (&restriction.inherits, created),
            Self::Unseen => (&restriction.unseen, created),
        };
        template.replace("{type}", ty)
    }
}

/// Labels the parameters that carry the resolved class.
struct Resolved<'p> {
    params: &'p [usize],
}

impl Policy for Resolved<'_> {
    fn parameter(&self, index: Option<usize>, _ty: &str) -> Option<(Labels, String)> {
        index
            .filter(|i| self.params.contains(i))
            .map(|_| (RESOLVED, "the class being resolved".to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allowlist,
    ConditionalAllowlist,
    Blocklist,
    Open,
}

/// Judges `created`, a class extending one of `types`, by the first class
/// from it up toward `types` that overrides the restriction method.
pub(crate) fn judge(
    context: &Context,
    types: &[String],
    created: &str,
    restriction: &Restriction,
) -> Judgment {
    let Some((name, descriptor)) = restriction
        .method
        .find('(')
        .map(|i| restriction.method.split_at(i))
    else {
        return Judgment::Unseen;
    };
    let mut current = created.to_owned();
    let mut seen = HashSet::new();
    loop {
        if types.contains(&current) {
            return Judgment::Inherits;
        }
        // A cycle cannot occur in classes the JVM loads, but a crafted jar
        // can contain one.
        if !seen.insert(current.clone()) {
            return Judgment::Unseen;
        }
        let Some(parsed) = context.classes.get(&current) else {
            return Judgment::Unseen;
        };
        if let Some(method) = declared_method(parsed, name, descriptor) {
            let mut visited = HashSet::new();
            return match classify(context, parsed, method, &[0], 0, &mut visited) {
                Verdict::Allowlist => Judgment::Allowlist(current),
                Verdict::ConditionalAllowlist => Judgment::ConditionalAllowlist(current),
                Verdict::Blocklist => Judgment::Blocklist(current),
                Verdict::Open => Judgment::Open(current),
            };
        }
        match context.hierarchy.super_of(&current) {
            Some(parent) => current = parent.to_owned(),
            None => return Judgment::Unseen,
        }
    }
}

fn classify(
    context: &Context,
    parsed: &ParsedClass,
    method: &Member,
    params: &[usize],
    depth: usize,
    visited: &mut HashSet<(String, String, String)>,
) -> Verdict {
    let policy = Resolved { params };
    // A call passing the resolved class on, such as to a helper that checks
    // the name or to the parent class's own override, guards the path when
    // the callee is itself an allowlist. Relying on a conditional one makes
    // this method conditional too.
    let mut conditional = false;
    // Both path searches ask about the same calls, so each callee's verdict
    // is kept for the second.
    let mut judged: HashMap<(String, String, String), Verdict> = HashMap::new();
    let mut guards = |call: &LabeledCall| {
        if depth >= MAX_DEPTH {
            return false;
        }
        let Some((callee_class, callee)) =
            context.resolve_method(&call.owner, &call.name, &call.descriptor)
        else {
            return false;
        };
        let key = (
            callee_class.name.clone(),
            call.name.clone(),
            call.descriptor.clone(),
        );
        let verdict = match judged.get(&key) {
            Some(verdict) => *verdict,
            None => {
                // A callee already being judged further up is part of a
                // cycle, which guards nothing.
                if !visited.insert(key.clone()) {
                    return false;
                }
                let verdict = classify(
                    context,
                    callee_class,
                    callee,
                    &call.arguments,
                    depth + 1,
                    visited,
                );
                judged.insert(key, verdict);
                verdict
            }
        };
        match verdict {
            Verdict::Allowlist => true,
            Verdict::ConditionalAllowlist => {
                conditional = true;
                true
            }
            _ => false,
        }
    };
    let unguarded =
        dataflow::finishes_unguarded(&parsed.class, method, &policy, RESOLVED, &mut guards);
    let unchecked =
        dataflow::finishes_unchecked(&parsed.class, method, &policy, RESOLVED, &mut guards);
    if !unguarded {
        return if conditional {
            Verdict::ConditionalAllowlist
        } else {
            Verdict::Allowlist
        };
    }
    let decisions = dataflow::decisions(&parsed.class, method, &policy, RESOLVED);
    // Every path looks the class up first, and a miss can end in a throw,
    // so the method rejects classes it does not find, only not always.
    if !unchecked && decisions.iter().any(|d| d.not_found.throws) {
        return Verdict::ConditionalAllowlist;
    }
    let blocks = decisions
        .iter()
        .any(|d| d.found.throws && !d.found.returns && d.not_found.returns);
    if blocks {
        Verdict::Blocklist
    } else {
        Verdict::Open
    }
}
