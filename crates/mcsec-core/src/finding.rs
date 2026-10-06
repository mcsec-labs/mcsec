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

/// Where the data a data flow finding is about comes from. Together with
/// [`Safeguard`] it decides the severity. Network data with no safeguard is
/// Critical, untraced data with no safeguard is Warning, and everything else
/// is a Notice whose origin and safeguard say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DataOrigin {
    /// Data a remote party controls, such as a packet.
    Network,
    /// Data whose source the analysis could not follow, such as a field set
    /// elsewhere.
    Untraced,
    /// A file on the player's or server's own disk.
    LocalFile,
    /// Whatever the method's caller passes in, where no caller in the jar
    /// passes untrusted data.
    Caller,
    /// A constant the mod embeds in its own code.
    EmbeddedTemplate,
}

/// What limits a dangerous operation, when something does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Safeguard {
    /// The code checks each class against an allowed set and rejects the
    /// rest, as judged from its bytecode.
    Allowlist,
    /// A call configures the operation to be safe, such as installing a
    /// filter.
    Setting,
    /// The bundled library version is safe by default.
    LibraryVersion,
    /// A subclass from outside the jar, whose code cannot be checked, may
    /// restrict it.
    UncheckedSubclass,
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
    /// SHA-1 of the class file holding the location, so the same library
    /// code bundled in many jars can be recognized as one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<DataOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safeguard: Option<Safeguard>,
    /// Source to sink steps for data flow rules. Empty for single location rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceStep>,
}
