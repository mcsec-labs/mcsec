//! Reading jars and the archives nested inside them.
//!
//! Entries are read into memory and never written to disk, so entry names
//! are only labels. Path traversal names and symlink entries have no effect.

use std::io::{Cursor, Read};

use serde::Serialize;
use zip::ZipArchive;

use crate::error::ScanError;
use crate::hash::FileHashes;
use crate::limits::ScanLimits;

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

impl EntryKind {
    fn detect(data: &[u8]) -> Self {
        if data.starts_with(&CLASS_MAGIC) && data.len() >= 8 {
            let major_version = u16::from_be_bytes([data[6], data[7]]);
            if major_version >= MIN_CLASS_MAJOR_VERSION {
                return Self::Class;
            }
        }
        if data.starts_with(&ZIP_MAGIC) {
            return Self::Archive;
        }
        Self::Resource
    }
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

    let zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|source| ScanError::InvalidArchive { source })?;
    let mut budget = Budget::new(limits);
    read_opened(zip, bytes, Vec::new(), 0, &mut budget)
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
}

fn read_opened(
    mut zip: ZipArchive<Cursor<&[u8]>>,
    bytes: &[u8],
    path: Vec<String>,
    depth: u32,
    budget: &mut Budget,
) -> Result<Archive, ScanError> {
    // Counted from the central directory before reading anything, so an
    // archive with a huge entry count is rejected without iterating it.
    budget.entries += zip.len() as u64;
    if budget.entries > budget.limits.max_entries {
        return Err(ScanError::TooManyEntries {
            limit: budget.limits.max_entries,
        });
    }

    let mut entries = Vec::new();
    let mut unreadable = Vec::new();

    for index in 0..zip.len() {
        let indexed_name = zip.name_for_index(index).unwrap_or_default().to_owned();
        let mut file = match zip.by_index(index) {
            Ok(file) => file,
            Err(error) => {
                unreadable.push(UnreadableEntry {
                    name: indexed_name,
                    reason: error.to_string(),
                });
                continue;
            }
        };
        if file.is_dir() {
            continue;
        }

        let name = file.name().to_owned();
        let entry_limit = budget.limits.max_entry_size;
        if file.size() > entry_limit {
            return Err(ScanError::EntryTooLarge {
                archive_path: path,
                entry: name,
                limit: entry_limit,
            });
        }

        // The declared size can be forged, so the read itself is capped one
        // byte past whichever limit is closer. Reaching that extra byte
        // proves the limit was exceeded.
        let read_cap = entry_limit.min(budget.remaining_bytes());
        let mut data = Vec::with_capacity(file.size().min(read_cap) as usize);
        if let Err(error) = (&mut file).take(read_cap + 1).read_to_end(&mut data) {
            unreadable.push(UnreadableEntry {
                name,
                reason: error.to_string(),
            });
            continue;
        }

        let read_size = data.len() as u64;
        if read_size > entry_limit {
            return Err(ScanError::EntryTooLarge {
                archive_path: path,
                entry: name,
                limit: entry_limit,
            });
        }
        budget.total_bytes += read_size;
        if budget.total_bytes > budget.limits.max_total_size {
            return Err(ScanError::TotalSizeExceeded {
                limit: budget.limits.max_total_size,
            });
        }

        let kind = EntryKind::detect(&data);
        entries.push(Entry { name, kind, data });
    }

    let mut nested = Vec::new();
    for entry in entries.iter().filter(|e| e.kind == EntryKind::Archive) {
        let mut nested_path = path.clone();
        nested_path.push(entry.name.clone());

        if depth + 1 > budget.limits.max_nesting_depth {
            return Err(ScanError::NestingTooDeep {
                archive_path: nested_path,
                limit: budget.limits.max_nesting_depth,
            });
        }

        // Zip magic alone does not make a valid archive. Data files that
        // happen to start with it are kept as entries and noted here.
        match ZipArchive::new(Cursor::new(entry.data.as_slice())) {
            Ok(inner) => {
                nested.push(read_opened(
                    inner,
                    &entry.data,
                    nested_path,
                    depth + 1,
                    budget,
                )?);
            }
            Err(error) => unreadable.push(UnreadableEntry {
                name: entry.name.clone(),
                reason: format!("not a readable zip archive: {error}"),
            }),
        }
    }

    Ok(Archive {
        path,
        hashes: FileHashes::compute(bytes),
        size: bytes.len() as u64,
        entries,
        nested,
        unreadable,
    })
}
