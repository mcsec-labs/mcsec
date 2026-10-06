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

/// Versions of libraries bundled in a jar and its nested jars, keyed by
/// Maven coordinates as `group:artifact`.
#[derive(Debug, Default)]
pub struct Libraries {
    by_coordinates: HashMap<String, String>,
    /// File names of nested jars without the extension, which Jar-in-Jar
    /// loaders store as `<artifact>-<version>`.
    nested_jars: Vec<String>,
}

impl Libraries {
    pub fn build(root: &ParsedArchive) -> Self {
        let mut libraries = Self::default();
        for archive in root.walk() {
            if let Some(name) = archive.archive.path.last() {
                let file = name.rsplit('/').next().unwrap_or(name);
                if let Some(stem) = file.strip_suffix(".jar") {
                    libraries.nested_jars.push(stem.to_owned());
                }
            }
            for entry in &archive.archive.entries {
                let Some(coordinates) = entry
                    .name
                    .strip_prefix("META-INF/maven/")
                    .and_then(|rest| rest.strip_suffix("/pom.properties"))
                    .and_then(|rest| rest.split_once('/'))
                else {
                    continue;
                };
                let version = String::from_utf8_lossy(&entry.data)
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("version=").map(str::to_owned));
                if let Some(version) = version {
                    libraries
                        .by_coordinates
                        .entry(format!("{}:{}", coordinates.0, coordinates.1))
                        .or_insert(version);
                }
            }
        }
        libraries
    }

    /// The bundled version of `group:artifact`, from its Maven metadata or
    /// else from a nested jar's file name.
    pub fn version(&self, coordinates: &str) -> Option<&str> {
        if let Some(version) = self.by_coordinates.get(coordinates) {
            return Some(version);
        }
        let artifact = coordinates.rsplit(':').next()?;
        self.nested_jars.iter().find_map(|stem| {
            stem.strip_prefix(artifact)?
                .strip_prefix('-')
                .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        })
    }
}

/// Compares dotted version numbers by their numeric parts, so `1.4.18` is
/// newer than `1.4.9`. A suffix such as `-SNAPSHOT` is ignored, and missing
/// parts count as zero.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| -> Vec<u64> {
        v.split(['-', '+'])
            .next()
            .unwrap_or("")
            .split('.')
            .map(|part| {
                let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().unwrap_or(0)
            })
            .collect()
    };
    let (a, b) = (parts(a), parts(b));
    let length = a.len().max(b.len());
    let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    (0..length)
        .map(|i| at(&a, i).cmp(&at(&b, i)))
        .find(|order| order.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::compare_versions;
    use std::cmp::Ordering;

    #[test]
    fn compares_versions_numerically() {
        assert_eq!(compare_versions("1.4.18", "1.4.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.33", "2.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0", "2"), Ordering::Equal);
        assert_eq!(compare_versions("5.0.0-RC1", "5.0"), Ordering::Equal);
        assert_eq!(compare_versions("4.0.2", "5.0"), Ordering::Less);
    }
}
