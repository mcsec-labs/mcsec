//! Findings produced by detection rules.
//!
//! Every finding carries the exact location that triggered it and, for
//! data flow rules, each step from source to sink, so nothing in a report is
//! asserted without the code behind it.

use serde::Serialize;

/// How serious a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Notice,
    Warning,
    Critical,
}

/// A method identified by name and JVM descriptor, since overloads share a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodRef {
    pub name: String,
    pub descriptor: String,
}

/// Where in a jar something was found. Fields narrow from archive down to
/// bytecode offset, and each is set only as far as the rule can resolve.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// Entry names leading from the input jar to the archive holding the
    /// code. Empty for the input jar.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub archive_path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// Internal JVM name, for example `net/example/Mod`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<MethodRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode_offset: Option<u32>,
}

/// One step in the chain of evidence behind a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceStep {
    pub description: String,
    pub location: Location,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable ID of the rule that fired, linking to its source and docs.
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub location: Location,
    /// Source to sink steps for data flow rules. Empty for single location rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceStep>,
}
