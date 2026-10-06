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
    interfaces: HashMap<String, Vec<String>>,
}

impl Hierarchy {
    pub fn build(root: &ParsedArchive) -> Self {
        let mut supers = HashMap::new();
        let mut interfaces = HashMap::new();
        for archive in root.walk() {
            for parsed in &archive.classes {
                if let Ok(Some(super_name)) = parsed.class.super_name() {
                    supers.insert(parsed.name.clone(), super_name.into_owned());
                }
                let pool = &parsed.class.constant_pool;
                let names: Vec<String> = parsed
                    .class
                    .interfaces
                    .iter()
                    .filter_map(|&index| pool.class_name(index).ok().map(|n| n.into_owned()))
                    .collect();
                if !names.is_empty() {
                    interfaces.insert(parsed.name.clone(), names);
                }
            }
        }
        Self { supers, interfaces }
    }

    /// True when `name` is `ancestor`, or extends or implements it through
    /// any chain of superclasses and interfaces the jar's own classes show.
    pub fn is_subtype(&self, name: &str, ancestor: &str) -> bool {
        let mut seen = HashSet::new();
        let mut pending = vec![name];
        while let Some(current) = pending.pop() {
            if current == ancestor {
                return true;
            }
            if !seen.insert(current) {
                continue;
            }
            pending.extend(self.supers.get(current).map(String::as_str));
            pending.extend(
                self.interfaces
                    .get(current)
                    .into_iter()
                    .flatten()
                    .map(String::as_str),
            );
        }
        false
    }

    /// True when `name` is one of `ancestors` or extends one, as far as the
    /// jar's own classes show. A class also matches a copy of an ancestor
    /// that shading moved under another package, such as
    /// `com/example/shadow/io/netty/buffer/ByteBuf` for
    /// `io/netty/buffer/ByteBuf`.
    pub fn extends_any(&self, name: &str, ancestors: &[&str]) -> bool {
        let mut seen = HashSet::new();
        let mut current = name;
        loop {
            if ancestors.iter().any(|a| same_or_relocated(current, a)) {
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

    /// The superclass of a class in the jar.
    pub fn super_of(&self, name: &str) -> Option<&str> {
        self.supers.get(name).map(String::as_str)
    }
}

/// True when `name` is `original`, or `original` under a package prefix
/// that shading added.
pub fn same_or_relocated(name: &str, original: &str) -> bool {
    name == original
        || name
            .strip_suffix(original)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

/// Every class in a jar and its nested jars, by internal name. When a name
/// appears more than once, as in multi-release jars, the first copy wins.
pub struct Classes<'r, 'a> {
    by_name: HashMap<&'r str, &'r ParsedClass<'a>>,
    /// Classes declaring a method with a body, by (name, descriptor).
    implementations: HashMap<(String, String), Vec<&'r str>>,
}

impl<'r, 'a> Classes<'r, 'a> {
    pub fn build(root: &'r ParsedArchive<'a>) -> Self {
        let mut by_name = HashMap::new();
        let mut implementations: HashMap<(String, String), Vec<&'r str>> = HashMap::new();
        for archive in root.walk() {
            for parsed in &archive.classes {
                // The first copy of a class wins, and only its methods are
                // indexed.
                if by_name.contains_key(parsed.name.as_str()) {
                    continue;
                }
                by_name.insert(parsed.name.as_str(), parsed);
                let pool = &parsed.class.constant_pool;
                for method in &parsed.class.methods {
                    let (Ok(name), Ok(descriptor), Ok(Some(_))) = (
                        method.name(pool),
                        method.descriptor(pool),
                        method.code(pool),
                    ) else {
                        continue;
                    };
                    implementations
                        .entry((name.into_owned(), descriptor.into_owned()))
                        .or_default()
                        .push(parsed.name.as_str());
                }
            }
        }
        Self {
            by_name,
            implementations,
        }
    }

    pub fn get(&self, name: &str) -> Option<&'r ParsedClass<'a>> {
        self.by_name.get(name).copied()
    }

    /// Classes in the jar that declare a method with this name and
    /// descriptor and a body.
    pub fn implementations(&self, name: &str, descriptor: &str) -> &[&'r str] {
        self.implementations
            .get(&(name.to_owned(), descriptor.to_owned()))
            .map_or(&[], Vec::as_slice)
    }
}

/// Byte arrays that static initializers store in static fields, keyed as
/// `owner.name`. Covers the code compilers emit for array literals, a
/// `newarray` filled by constant `bastore`s.
#[derive(Debug, Default)]
pub struct Constants {
    byte_arrays: HashMap<String, Vec<u8>>,
}

impl Constants {
    pub fn build(root: &ParsedArchive) -> Self {
        let mut constants = Self::default();
        for archive in root.walk() {
            for parsed in &archive.classes {
                constants.read_static_initializer(parsed);
            }
        }
        constants
    }

    pub fn byte_array(&self, owner: &str, name: &str) -> Option<&[u8]> {
        self.byte_arrays
            .get(&format!("{owner}.{name}"))
            .map(Vec::as_slice)
    }

    fn read_static_initializer(&mut self, parsed: &ParsedClass) {
        use crate::class_file::{Operand, op};

        /// Bound on array length, so a crafted initializer cannot allocate
        /// without limit.
        const MAX_LENGTH: i32 = 1 << 16;
        const T_BYTE: u8 = 8;

        #[derive(Clone)]
        enum Slot {
            Int(i32),
            Array(usize),
        }

        let class = &parsed.class;
        let pool = &class.constant_pool;
        let Some(clinit) = class
            .methods
            .iter()
            .find(|m| m.name(pool).is_ok_and(|n| n == "<clinit>"))
        else {
            return;
        };
        let Ok(Some(code)) = clinit.code(pool) else {
            return;
        };
        let mut arrays: Vec<Vec<u8>> = Vec::new();
        let mut stack: Vec<Slot> = Vec::new();
        // Follows only the instructions of array literals. Any other
        // instruction clears the stack, which is empty between statements,
        // so literals later in the initializer are still read.
        for ins in code.instructions() {
            let Ok(ins) = ins else {
                return;
            };
            match (ins.opcode, &ins.operand) {
                (op::ICONST_M1..=op::ICONST_5, _) => {
                    stack.push(Slot::Int(i32::from(ins.opcode) - i32::from(op::ICONST_0)))
                }
                (op::BIPUSH | op::SIPUSH, Operand::Immediate(value)) => {
                    stack.push(Slot::Int(*value))
                }
                (op::NEWARRAY, Operand::ArrayType(T_BYTE)) => match stack.pop() {
                    Some(Slot::Int(length)) if (0..=MAX_LENGTH).contains(&length) => {
                        arrays.push(vec![0; length as usize]);
                        stack.push(Slot::Array(arrays.len() - 1));
                    }
                    _ => stack.clear(),
                },
                (op::DUP, _) => match stack.last().cloned() {
                    Some(top) => stack.push(top),
                    None => stack.clear(),
                },
                (op::BASTORE, _) => {
                    let (Some(Slot::Int(value)), Some(Slot::Int(index)), Some(Slot::Array(a))) =
                        (stack.pop(), stack.pop(), stack.pop())
                    else {
                        stack.clear();
                        continue;
                    };
                    match usize::try_from(index)
                        .ok()
                        .and_then(|i| arrays[a].get_mut(i))
                    {
                        Some(byte) => *byte = value as u8,
                        None => stack.clear(),
                    }
                }
                (op::PUTSTATIC, Operand::Constant(index)) => {
                    let value = stack.pop();
                    if let (Some(Slot::Array(a)), Ok(field)) = (value, pool.member_ref(*index))
                        && field.class_name == parsed.name
                    {
                        self.byte_arrays
                            .entry(format!("{}.{}", field.class_name, field.name))
                            .or_insert_with(|| arrays[a].clone());
                    }
                }
                _ => stack.clear(),
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
    fn matches_relocated_names() {
        use super::same_or_relocated;
        let original = "io/netty/buffer/ByteBuf";
        assert!(same_or_relocated(original, original));
        assert!(same_or_relocated(
            "dev/x/shadow/io/netty/buffer/ByteBuf",
            original
        ));
        assert!(!same_or_relocated(
            "dev/x/shadowio/netty/buffer/ByteBuf",
            original
        ));
        assert!(!same_or_relocated("io/netty/buffer/ByteBufUtil", original));
    }

    #[test]
    fn compares_versions_numerically() {
        assert_eq!(compare_versions("1.4.18", "1.4.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.33", "2.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0", "2"), Ordering::Equal);
        assert_eq!(compare_versions("5.0.0-RC1", "5.0"), Ordering::Equal);
        assert_eq!(compare_versions("4.0.2", "5.0"), Ordering::Less);
    }
}
