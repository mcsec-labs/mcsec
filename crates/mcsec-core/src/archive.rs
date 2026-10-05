//! Reading jars and the archives nested inside them.
//!
//! Entries are read into memory and never written to disk, so entry names
//! are only labels. Path traversal names and symlink entries have no effect.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::ScanError;
use crate::hash::FileHashes;
use crate::limits::ScanLimits;
use crate::zip_reader::{OpenError, ZipReader};

/// Magic bytes at the start of a zip local file header.
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";

/// Magic bytes at the start of a class file.
const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// Lowest class file major version, from JDK 1.0.2. Mach-O universal
/// binaries share the class file magic but store their architecture count
/// in the same position, which is always far below this.
const MIN_CLASS_MAJOR_VERSION: u16 = 45;

/// What an entry's content is, judged by its bytes rather than its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Class,
    Archive,
    Resource,
}

fn is_class(data: &[u8]) -> bool {
    data.len() >= 8
        && data.starts_with(&CLASS_MAGIC)
        && u16::from_be_bytes([data[6], data[7]]) >= MIN_CLASS_MAJOR_VERSION
}

/// One file entry from an archive, with its uncompressed bytes.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

impl Entry {
    /// False when class content is stored under another extension, or a
    /// `.class` name holds something else. Both hide code from tools that
    /// trust file names.
    pub fn name_matches_content(&self) -> bool {
        let named_class = self.name.to_ascii_lowercase().ends_with(".class");
        named_class == (self.kind == EntryKind::Class)
    }
}

/// An entry that could not be read, kept so the report shows what was not
/// analyzed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreadableEntry {
    pub name: String,
    pub reason: String,
}

/// Structural oddities that legitimate build tools do not produce. Each is a
/// signal for rules, not a finding on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Anomaly {
    /// More than one entry has this name. Every copy is read and analyzed.
    DuplicateName { name: String },
    /// The entry's bytes do not match its stored CRC. The JVM loads such
    /// entries anyway, so they are analyzed like any other.
    ChecksumMismatch { name: String },
    /// Class content under another name, or a `.class` name over other content.
    MisnamedEntry { name: String },
    /// Bytes before the start of the archive, which zip readers skip.
    PrependedData { size: u64 },
}

/// A jar or nested archive with all of its entries read.
#[derive(Debug, Clone)]
pub struct Archive {
    /// Entry names leading from the input jar to this archive. Empty for the
    /// input jar.
    pub path: Vec<String>,
    pub hashes: FileHashes,
    pub size: u64,
    /// Every file entry, including the raw bytes of nested archives.
    pub entries: Vec<Entry>,
    /// Nested archives that opened successfully, in entry order.
    pub nested: Vec<Archive>,
    pub unreadable: Vec<UnreadableEntry>,
    pub anomalies: Vec<Anomaly>,
}

impl Archive {
    pub fn classes(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.kind == EntryKind::Class)
    }

    /// This archive followed by every archive nested inside it, shallowest first.
    pub fn walk(&self) -> Vec<&Archive> {
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

/// Reads a jar and every archive nested in it, within `limits`.
pub fn read_archive(bytes: &[u8], limits: &ScanLimits) -> Result<Archive, ScanError> {
    let size = bytes.len() as u64;
    if size > limits.max_input_size {
        return Err(ScanError::InputTooLarge {
            size,
            limit: limits.max_input_size,
        });
    }

    let reader = match ZipReader::open(bytes, limits.max_entries) {
        Ok(reader) => reader,
        Err(OpenError::TooManyEntries) => {
            return Err(ScanError::TooManyEntries {
                limit: limits.max_entries,
            });
        }
        Err(OpenError::Invalid(reason)) => return Err(ScanError::InvalidArchive { reason }),
    };
    let mut budget = Budget::new(limits);
    read_opened(&reader, bytes, Vec::new(), 0, &mut budget)
}

/// Running totals checked against the limits across every nesting level.
struct Budget<'a> {
    limits: &'a ScanLimits,
    total_bytes: u64,
    entries: u64,
}

impl<'a> Budget<'a> {
    fn new(limits: &'a ScanLimits) -> Self {
        Self {
            limits,
            total_bytes: 0,
            entries: 0,
        }
    }

    fn remaining_bytes(&self) -> u64 {
        self.limits.max_total_size.saturating_sub(self.total_bytes)
    }

    fn remaining_entries(&self) -> u64 {
        self.limits.max_entries.saturating_sub(self.entries)
    }

    fn too_many_entries(&self) -> ScanError {
        ScanError::TooManyEntries {
            limit: self.limits.max_entries,
        }
    }
}

fn read_opened(
    reader: &ZipReader,
    bytes: &[u8],
    path: Vec<String>,
    depth: u32,
    budget: &mut Budget,
) -> Result<Archive, ScanError> {
    budget.entries += reader.records.len() as u64;
    if budget.entries > budget.limits.max_entries {
        return Err(budget.too_many_entries());
    }

    let mut entries = Vec::new();
    let mut unreadable = Vec::new();
    let mut anomalies = Vec::new();
    if reader.base_offset > 0 {
        anomalies.push(Anomaly::PrependedData {
            size: reader.base_offset,
        });
    }

    let mut name_counts: HashMap<&str, u32> = HashMap::new();
    for record in &reader.records {
        let count = name_counts.entry(record.name.as_str()).or_default();
        *count += 1;
        if *count == 2 {
            anomalies.push(Anomaly::DuplicateName {
                name: record.name.clone(),
            });
        }
    }

    for record in reader.records.iter().filter(|r| !r.is_dir()) {
        let entry_limit = budget.limits.max_entry_size;
        let too_large = || ScanError::EntryTooLarge {
            archive_path: path.clone(),
            entry: record.name.clone(),
            limit: entry_limit,
        };
        if record.uncompressed_size > entry_limit {
            return Err(too_large());
        }

        // The declared size can be forged, so the read itself is capped one
        // byte past whichever limit is closer. Reaching that extra byte
        // proves the limit was exceeded.
        let read_cap = entry_limit.min(budget.remaining_bytes());
        let data = match reader.read(record, read_cap) {
            Ok(data) => data,
            Err(reason) => {
                unreadable.push(UnreadableEntry {
                    name: record.name.clone(),
                    reason,
                });
                continue;
            }
        };

        let read_size = data.len() as u64;
        if read_size > entry_limit {
            return Err(too_large());
        }
        budget.total_bytes += read_size;
        if budget.total_bytes > budget.limits.max_total_size {
            return Err(ScanError::TotalSizeExceeded {
                limit: budget.limits.max_total_size,
            });
        }

        if crc32fast::hash(&data) != record.crc32 {
            anomalies.push(Anomaly::ChecksumMismatch {
                name: record.name.clone(),
            });
        }
        let kind = if is_class(&data) {
            EntryKind::Class
        } else {
            EntryKind::Resource
        };
        entries.push(Entry {
            name: record.name.clone(),
            kind,
            data,
        });
    }

    // Every non-class entry is tried as an archive, because a nested jar can
    // be renamed or have bytes prepended to hide its zip header.
    let mut nested = Vec::new();
    for entry in &mut entries {
        if entry.kind == EntryKind::Class {
            continue;
        }
        let inner = match ZipReader::open(&entry.data, budget.remaining_entries()) {
            Ok(inner) => inner,
            Err(OpenError::TooManyEntries) => return Err(budget.too_many_entries()),
            Err(OpenError::Invalid(reason)) => {
                // Only entries that claim to be zips are worth noting. Other
                // resources fail here as expected.
                if entry.data.starts_with(&ZIP_MAGIC) {
                    unreadable.push(UnreadableEntry {
                        name: entry.name.clone(),
                        reason: format!("not a readable zip archive: {reason}"),
                    });
                }
                continue;
            }
        };

        let mut nested_path = path.clone();
        nested_path.push(entry.name.clone());
        if depth + 1 > budget.limits.max_nesting_depth {
            return Err(ScanError::NestingTooDeep {
                archive_path: nested_path,
                limit: budget.limits.max_nesting_depth,
            });
        }

        let archive = read_opened(&inner, &entry.data, nested_path, depth + 1, budget)?;
        nested.push(archive);
        entry.kind = EntryKind::Archive;
    }

    anomalies.extend(
        entries
            .iter()
            .filter(|e| !e.name_matches_content())
            .map(|e| Anomaly::MisnamedEntry {
                name: e.name.clone(),
            }),
    );

    Ok(Archive {
        path,
        hashes: FileHashes::compute(bytes),
        size: bytes.len() as u64,
        entries,
        nested,
        unreadable,
        anomalies,
    })
}
