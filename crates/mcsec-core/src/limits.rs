//! Resource limits applied while reading untrusted archives.

/// Bounds on how much work and memory one scan may use.
///
/// Sizes are uncompressed byte counts read from the entry streams, not the
/// sizes declared in zip headers, since headers can be forged. A nested jar's
/// bytes count once as an entry and again as each of its own entries, so a
/// recursive zip bomb exhausts the budget quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Largest input file accepted. Mods that bundle music, textures, or
    /// models run to several hundred megabytes.
    pub max_input_size: u64,
    /// Largest uncompressed size of a single entry. Mods ship single native
    /// libraries far larger than any class file, so this sits well above
    /// them.
    pub max_entry_size: u64,
    /// Largest uncompressed size of all entries combined, across every nesting level.
    pub max_total_size: u64,
    /// Most entries read across every nesting level.
    pub max_entries: u64,
    /// Deepest chain of archives inside archives. The input jar is depth zero.
    pub max_nesting_depth: u32,
}

impl Default for ScanLimits {
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            max_input_size: 512 * MIB,
            max_entry_size: 256 * MIB,
            max_total_size: 1024 * MIB,
            max_entries: 250_000,
            max_nesting_depth: 8,
        }
    }
}
