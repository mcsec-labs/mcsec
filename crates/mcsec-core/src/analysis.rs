//! Parsed classes shared by the report and the detection rules, so each class
//! is parsed once per scan.

use std::collections::{HashMap, HashSet};

use crate::archive::{Archive, Entry, UnreadableEntry};
use crate::class_file::ClassFile;

/// A class entry with its parsed class file.
pub struct ParsedClass<'a> {
    pub entry: &'a Entry,
    pub class: ClassFile<'a>,
    /// Internal JVM name, for example `net/example/Mod`.
    pub name: String,
}

/// An archive with every class entry parsed, mirroring [`Archive`]'s nesting.
pub struct ParsedArchive<'a> {
    pub archive: &'a Archive,
    pub classes: Vec<ParsedClass<'a>>,
    /// Class entries that failed to parse, or whose method bodies failed to
    /// decode. Classes that parse but fail to decode are still analyzed, and
    /// rules skip the methods that fail.
    pub unparsed: Vec<UnreadableEntry>,
    pub nested: Vec<ParsedArchive<'a>>,
}

impl<'a> ParsedArchive<'a> {
    pub fn parse(archive: &'a Archive) -> Self {
        let mut classes = Vec::new();
        let mut unparsed = Vec::new();
        for entry in archive.classes() {
            let unreadable = |reason: String| UnreadableEntry {
                name: entry.name.clone(),
                reason,
            };
            let class = match ClassFile::parse(&entry.data) {
                Ok(class) => class,
                Err(error) => {
                    unparsed.push(unreadable(error.to_string()));
                    continue;
                }
            };
            if let Err(error) = class.check_code() {
                unparsed.push(unreadable(error.to_string()));
            }
            let Ok(name) = class.name() else {
                unparsed.push(unreadable("class name is not a valid constant".to_owned()));
                continue;
            };
            classes.push(ParsedClass {
                entry,
                name: name.into_owned(),
                class,
            });
        }
        Self {
            archive,
            classes,
            unparsed,
            nested: archive.nested.iter().map(ParsedArchive::parse).collect(),
        }
    }

    /// This archive followed by every archive nested inside it, shallowest first.
    pub fn walk(&self) -> Vec<&ParsedArchive<'a>> {
        let mut out = vec![self];
        let mut index = 0;
        while index < out.len() {
            let current = out[index];
            out.extend(current.nested.iter());
            index += 1;
        }
        out
    }
}

/// Superclass links for every class in a jar and its nested jars. Classes
/// from outside the jar, such as Minecraft or the JDK, end a chain.
pub struct Hierarchy {
    supers: HashMap<String, String>,
}

impl Hierarchy {
    pub fn build(root: &ParsedArchive) -> Self {
        let mut supers = HashMap::new();
        for archive in root.walk() {
            for parsed in &archive.classes {
                if let Ok(Some(super_name)) = parsed.class.super_name() {
                    supers.insert(parsed.name.clone(), super_name.into_owned());
                }
            }
        }
        Self { supers }
    }

    /// True when `name` is one of `ancestors` or extends one, as far as the
    /// jar's own classes show.
    pub fn extends_any(&self, name: &str, ancestors: &[&str]) -> bool {
        let mut seen = HashSet::new();
        let mut current = name;
        loop {
            if ancestors.contains(&current) {
                return true;
            }
            // A cycle cannot occur in classes the JVM loads, but a crafted
            // jar can contain one.
            if !seen.insert(current) {
                return false;
            }
            match self.supers.get(current) {
                Some(parent) => current = parent,
                None => return false,
            }
        }
    }
}
