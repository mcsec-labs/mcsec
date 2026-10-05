//! Minimal zip reader that follows the rules of the JVM's `java.util.zip.ZipFile`,
//! which class loaders use to open jars.
//!
//! Matching the JVM matters more than matching the zip specification. Any
//! entry the JVM can load must be visible here, or a jar can hide code from
//! the scanner. So this reader:
//!
//! - Lists entries from the central directory, not the local headers, as the
//!   JVM does
//! - Keeps every entry when names repeat, since the copy a loader picks is
//!   not knowable from the archive alone
//! - Locates the central directory from the end record, so bytes prepended
//!   to the archive do not stop it from opening
//! - Reads entries whose CRC does not match, reporting the mismatch instead
//!   of refusing the entry

use std::io::Read;

use flate2::read::DeflateDecoder;

const END_SIGNATURE: u32 = 0x0605_4b50;
const END_SIZE: usize = 22;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_LOCATOR_SIZE: usize = 20;
const ZIP64_END_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_END_SIZE: usize = 56;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_SIZE: usize = 46;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const LOCAL_SIZE: usize = 30;
const ZIP64_EXTRA_ID: u16 = 0x0001;

/// Largest archive comment, which bounds how far back the end record can be.
const MAX_COMMENT_SIZE: usize = u16::MAX as usize;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
const FLAG_ENCRYPTED: u16 = 0x0001;

/// One central directory record.
#[derive(Debug, Clone)]
pub(crate) struct CentralRecord {
    pub name: String,
    flags: u16,
    method: u16,
    pub crc32: u32,
    compressed_size: u64,
    pub uncompressed_size: u64,
    local_header_offset: u64,
}

impl CentralRecord {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

#[derive(Debug)]
pub(crate) enum OpenError {
    /// Not a zip archive, or a structurally broken one.
    Invalid(String),
    /// Reading the central directory would pass the entry budget.
    TooManyEntries,
}

/// An opened archive over borrowed bytes.
#[derive(Debug)]
pub(crate) struct ZipReader<'a> {
    data: &'a [u8],
    /// Where offset zero of the archive falls in `data`. Non-zero when bytes
    /// were prepended to the archive.
    pub base_offset: u64,
    pub records: Vec<CentralRecord>,
}

impl<'a> ZipReader<'a> {
    /// Parses the end record and central directory. Fails with
    /// [`OpenError::TooManyEntries`] before allocating records when the
    /// archive declares more than `max_entries`.
    pub fn open(data: &'a [u8], max_entries: u64) -> Result<Self, OpenError> {
        let end = find_end(data).ok_or_else(|| invalid("no end of central directory record"))?;
        if end.total_entries > max_entries {
            return Err(OpenError::TooManyEntries);
        }

        // Same derivation as the JVM. The directory sits directly before the
        // end record, and the gap between where it is and where it claims to
        // be is the length of any prepended data.
        let central_start = end
            .position
            .checked_sub(end.central_size)
            .ok_or_else(|| invalid("central directory size runs past start of file"))?;
        let base_offset = central_start
            .checked_sub(end.central_offset)
            .ok_or_else(|| invalid("central directory offset runs past start of file"))?;

        // Each record is at least the fixed header size, so the directory's
        // byte length caps the count no matter what the end record declares.
        let capacity = end
            .total_entries
            .min(end.central_size / CENTRAL_SIZE as u64);
        let mut records = Vec::with_capacity(capacity as usize);
        let mut cursor = central_start as usize;
        let central_end = end.position as usize;
        while cursor + CENTRAL_SIZE <= central_end {
            if records.len() as u64 >= max_entries {
                return Err(OpenError::TooManyEntries);
            }
            let (record, next) = parse_central_record(data, cursor, central_end)?;
            records.push(record);
            cursor = next;
        }

        Ok(Self {
            data,
            base_offset,
            records,
        })
    }

    /// Reads one entry's uncompressed bytes, stopping after `cap + 1` bytes
    /// so the caller can tell an entry over the cap from one exactly at it.
    pub fn read(&self, record: &CentralRecord, cap: u64) -> Result<Vec<u8>, String> {
        if record.flags & FLAG_ENCRYPTED != 0 {
            return Err("encrypted entry".to_owned());
        }

        let local = self
            .base_offset
            .checked_add(record.local_header_offset)
            .map(|offset| offset as usize)
            .filter(|&offset| offset + LOCAL_SIZE <= self.data.len())
            .ok_or("local header offset is outside the file")?;
        if read_u32(self.data, local) != LOCAL_SIGNATURE {
            return Err("local header signature missing".to_owned());
        }
        let name_len = read_u16(self.data, local + 26) as usize;
        let extra_len = read_u16(self.data, local + 28) as usize;

        // The central directory's compressed size is authoritative, as in
        // the JVM. Local header sizes are often zero when a data descriptor
        // follows the entry.
        let start = local + LOCAL_SIZE + name_len + extra_len;
        let compressed = start
            .checked_add(record.compressed_size as usize)
            .filter(|&end| end <= self.data.len())
            .map(|end| &self.data[start..end])
            .ok_or("entry data runs past end of file")?;

        let mut out = Vec::with_capacity(record.uncompressed_size.min(cap) as usize);
        let limit = cap.saturating_add(1);
        let result = match record.method {
            METHOD_STORED => compressed.take(limit).read_to_end(&mut out),
            METHOD_DEFLATED => DeflateDecoder::new(compressed)
                .take(limit)
                .read_to_end(&mut out),
            method => return Err(format!("unsupported compression method {method}")),
        };
        result.map_err(|error| format!("decompression failed: {error}"))?;
        Ok(out)
    }
}

struct EndRecord {
    /// Position of the end record that the directory precedes. For zip64
    /// archives this is the zip64 end record.
    position: u64,
    total_entries: u64,
    central_size: u64,
    central_offset: u64,
}

/// Searches backward from the end of the file for an end record whose
/// directory fields are consistent with the file.
fn find_end(data: &[u8]) -> Option<EndRecord> {
    if data.len() < END_SIZE {
        return None;
    }
    let last = data.len() - END_SIZE;
    let first = last.saturating_sub(MAX_COMMENT_SIZE);

    for position in (first..=last).rev() {
        if read_u32(data, position) != END_SIGNATURE {
            continue;
        }
        let mut end = EndRecord {
            position: position as u64,
            total_entries: u64::from(read_u16(data, position + 10)),
            central_size: u64::from(read_u32(data, position + 12)),
            central_offset: u64::from(read_u32(data, position + 16)),
        };
        let needs_zip64 = end.total_entries == u64::from(u16::MAX)
            || end.central_size == u64::from(u32::MAX)
            || end.central_offset == u64::from(u32::MAX);
        if needs_zip64 && let Some(zip64) = read_zip64_end(data, position) {
            end = zip64;
        }
        // A stray signature inside a comment or entry data fails this check,
        // and the search continues backward.
        let Some(central_start) = end.position.checked_sub(end.central_size) else {
            continue;
        };
        if end.total_entries == 0 || read_u32(data, central_start as usize) == CENTRAL_SIGNATURE {
            return Some(end);
        }
    }
    None
}

/// Reads the zip64 end record through the locator that sits directly before
/// the regular end record.
fn read_zip64_end(data: &[u8], end_position: usize) -> Option<EndRecord> {
    let locator = end_position.checked_sub(ZIP64_LOCATOR_SIZE)?;
    if read_u32(data, locator) != ZIP64_LOCATOR_SIGNATURE {
        return None;
    }

    // The locator's offset ignores prepended data, so the record is also
    // checked at its fixed position directly before the locator.
    let stated = usize::try_from(read_u64(data, locator + 8)).ok();
    let adjacent = locator.checked_sub(ZIP64_END_SIZE);
    let position = [stated, adjacent]
        .into_iter()
        .flatten()
        .find(|&p| p + ZIP64_END_SIZE <= locator && read_u32(data, p) == ZIP64_END_SIGNATURE)?;

    Some(EndRecord {
        position: position as u64,
        total_entries: read_u64(data, position + 32),
        central_size: read_u64(data, position + 40),
        central_offset: read_u64(data, position + 48),
    })
}

/// Parses the record at `at` and returns it with the offset of the next one.
fn parse_central_record(
    data: &[u8],
    at: usize,
    central_end: usize,
) -> Result<(CentralRecord, usize), OpenError> {
    if read_u32(data, at) != CENTRAL_SIGNATURE {
        return Err(invalid("central directory record signature missing"));
    }
    let name_len = read_u16(data, at + 28) as usize;
    let extra_len = read_u16(data, at + 30) as usize;
    let comment_len = read_u16(data, at + 32) as usize;
    let name_start = at + CENTRAL_SIZE;
    let extra_start = name_start + name_len;
    let next = extra_start + extra_len + comment_len;
    if next > central_end {
        return Err(invalid("central directory record runs past the directory"));
    }

    let mut record = CentralRecord {
        name: String::from_utf8_lossy(&data[name_start..extra_start]).into_owned(),
        flags: read_u16(data, at + 8),
        method: read_u16(data, at + 10),
        crc32: read_u32(data, at + 16),
        compressed_size: u64::from(read_u32(data, at + 20)),
        uncompressed_size: u64::from(read_u32(data, at + 24)),
        local_header_offset: u64::from(read_u32(data, at + 42)),
    };
    apply_zip64_extra(&mut record, &data[extra_start..extra_start + extra_len]);
    Ok((record, next))
}

/// Replaces saturated 32-bit fields with their 64-bit values from the zip64
/// extra field. Values appear only for saturated fields, in a fixed order.
fn apply_zip64_extra(record: &mut CentralRecord, extra: &[u8]) {
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = read_u16(extra, cursor);
        let size = read_u16(extra, cursor + 2) as usize;
        let body_end = (cursor + 4 + size).min(extra.len());
        if id == ZIP64_EXTRA_ID {
            let mut field = cursor + 4;
            for value in [
                &mut record.uncompressed_size,
                &mut record.compressed_size,
                &mut record.local_header_offset,
            ] {
                if *value == u64::from(u32::MAX) && field + 8 <= body_end {
                    *value = read_u64(extra, field);
                    field += 8;
                }
            }
            return;
        }
        cursor = body_end;
    }
}

fn invalid(reason: &str) -> OpenError {
    OpenError::Invalid(reason.to_owned())
}

// Readers for little-endian fields. Callers bounds check the record before
// reading, and an out-of-range field reads as zero rather than panicking.
fn read_u16(data: &[u8], at: usize) -> u16 {
    data.get(at..at + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    data.get(at..at + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    data.get(at..at + 8).map_or(0, |b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}
