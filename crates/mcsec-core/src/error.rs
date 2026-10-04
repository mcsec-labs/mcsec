//! Errors that stop a scan.

use thiserror::Error;

/// Reasons a scan could not finish.
///
/// Limit errors abort the whole scan rather than skipping the entry, so a jar
/// built to exhaust the scanner is reported as unscannable instead of looking
/// clean. `archive_path` is the chain of nested entry names from the input
/// jar down to the archive involved, and is empty for the input jar itself.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("input is {size} bytes, over the limit of {limit}")]
    InputTooLarge { size: u64, limit: u64 },

    #[error("entry {entry:?} in {archive_path:?} is over the per-entry limit of {limit} bytes")]
    EntryTooLarge {
        archive_path: Vec<String>,
        entry: String,
        limit: u64,
    },

    #[error("uncompressed content is over the total limit of {limit} bytes")]
    TotalSizeExceeded { limit: u64 },

    #[error("archive holds more than the limit of {limit} entries")]
    TooManyEntries { limit: u64 },

    #[error("archive at {archive_path:?} is nested deeper than the limit of {limit}")]
    NestingTooDeep {
        archive_path: Vec<String>,
        limit: u32,
    },

    #[error("input is not a readable zip archive: {source}")]
    InvalidArchive {
        #[source]
        source: zip::result::ZipError,
    },
}
