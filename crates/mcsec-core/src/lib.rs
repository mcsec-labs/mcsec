//! Static analysis of Minecraft mod jars.
//!
//! Every input is untrusted. Jars are read into memory and parsed as data,
//! never executed and never written to disk. All reading is bounded by
//! [`ScanLimits`].

#![forbid(unsafe_code)]

pub mod archive;
pub mod class_file;
pub mod error;
pub mod finding;
pub mod hash;
pub mod limits;
pub mod report;
mod zip_reader;

pub use archive::{Anomaly, Archive, Entry, EntryKind, UnreadableEntry, read_archive};
pub use class_file::{ClassFile, ClassParseError};
pub use error::ScanError;
pub use finding::{EvidenceStep, Finding, Location, MethodRef, Severity};
pub use hash::FileHashes;
pub use limits::ScanLimits;
pub use report::{ArchiveSummary, ScanReport};

/// Version of the scanner, recorded in every report so results can be tied
/// to the code that produced them.
pub const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reads a jar from memory and produces its report.
pub fn scan_bytes(bytes: &[u8], limits: &ScanLimits) -> Result<ScanReport, ScanError> {
    let archive = read_archive(bytes, limits)?;
    Ok(ScanReport::new(&archive, Vec::new()))
}
