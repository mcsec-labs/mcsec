//! The serialized result of one scan.

use serde::Serialize;

use crate::SCANNER_VERSION;
use crate::analysis::ParsedArchive;
use crate::archive::{Anomaly, EntryKind, UnreadableEntry};
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
    pub fn new(parsed: &ParsedArchive, findings: Vec<Finding>) -> Self {
        Self {
            scanner_version: SCANNER_VERSION.to_owned(),
            archive: ArchiveSummary::from(parsed),
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<Anomaly>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<UnreadableEntry>,
    /// Class entries that failed to parse or decode. The JVM would also
    /// refuse to load most of these, so they point to a scanner gap or to a
    /// class built to break analysis tools.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unparsed_classes: Vec<UnreadableEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nested: Vec<ArchiveSummary>,
}

impl From<&ParsedArchive<'_>> for ArchiveSummary {
    fn from(parsed: &ParsedArchive) -> Self {
        let archive = parsed.archive;
        let count = |kind| archive.entries.iter().filter(|e| e.kind == kind).count();
        Self {
            path: archive.path.clone(),
            hashes: archive.hashes.clone(),
            size: archive.size,
            class_count: count(EntryKind::Class),
            resource_count: count(EntryKind::Resource),
            anomalies: archive.anomalies.clone(),
            unreadable: archive.unreadable.clone(),
            unparsed_classes: parsed.unparsed.clone(),
            nested: parsed.nested.iter().map(ArchiveSummary::from).collect(),
        }
    }
}
