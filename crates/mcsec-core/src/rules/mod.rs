//! Detection rules. Rules are definition files run through the data flow
//! engine, and each finding carries the exact location and evidence behind it.

mod flow;
pub mod spec;

use crate::analysis::{Hierarchy, Libraries, ParsedArchive, ParsedClass};
use crate::finding::{Finding, Location, MethodRef};

/// Runs every rule over a jar and the archives nested in it.
pub fn run(root: &ParsedArchive) -> Vec<Finding> {
    let hierarchy = Hierarchy::build(root);
    let libraries = Libraries::build(root);
    let mut findings = Vec::new();
    for archive in root.walk() {
        for parsed in &archive.classes {
            let context = Context {
                archive,
                parsed,
                hierarchy: &hierarchy,
                libraries: &libraries,
            };
            for rule in spec::embedded() {
                flow::check(rule, &context, &mut findings);
            }
        }
    }
    findings
}

/// What a rule sees while checking one class.
pub(crate) struct Context<'r, 'a> {
    pub archive: &'r ParsedArchive<'a>,
    pub parsed: &'r ParsedClass<'a>,
    pub hierarchy: &'r Hierarchy,
    pub libraries: &'r Libraries,
}

impl Context<'_, '_> {
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
}
