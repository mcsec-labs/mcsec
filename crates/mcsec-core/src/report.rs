//! The serialized result of one scan.

use serde::Serialize;

use crate::SCANNER_VERSION;
use crate::archive::{Archive, EntryKind, UnreadableEntry};
use crate::finding::Finding;
use crate::hash::FileHashes;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub scanner_version: String,
    pub archive: ArchiveSummary,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(archive: &Archive, findings: Vec<Finding>) -> Self {
        Self {
            scanner_version: SCANNER_VERSION.to_owned(),
            archive: ArchiveSummary::from(archive),
            findings,
        }
    }
}

/// An archive's contents without the entry bytes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveSummary {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    pub hashes: FileHashes,
    pub size: u64,
    pub class_count: usize,
    pub resource_count: usize,
    /// Entries whose name disagrees with their content about being a class.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mismatched_names: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<UnreadableEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nested: Vec<ArchiveSummary>,
}

impl From<&Archive> for ArchiveSummary {
    fn from(archive: &Archive) -> Self {
        let count = |kind| archive.entries.iter().filter(|e| e.kind == kind).count();
        Self {
            path: archive.path.clone(),
            hashes: archive.hashes.clone(),
            size: archive.size,
            class_count: count(EntryKind::Class),
            resource_count: count(EntryKind::Resource),
            mismatched_names: archive
                .entries
                .iter()
                .filter(|e| !e.name_matches_content())
                .map(|e| e.name.clone())
                .collect(),
            unreadable: archive.unreadable.clone(),
            nested: archive.nested.iter().map(ArchiveSummary::from).collect(),
        }
    }
}
