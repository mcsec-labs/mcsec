//! Archive reading against jars built in memory.

use std::io::{Cursor, Write};

use mcsec_core::{Anomaly, EntryKind, ScanError, ScanLimits, read_archive, scan_bytes};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Class file magic followed by minor version 0 and major version 65 (Java 21).
const CLASS_BYTES: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];

/// Signature that starts each central directory record.
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";

fn build_zip_with(entries: &[(&str, &[u8])], options: SimpleFileOptions) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Builds a zip from (name, bytes) pairs with deflate compression.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    build_zip_with(entries, SimpleFileOptions::default())
}

/// Builds a jar nested `depth` levels deep, each holding the next as `inner.jar`.
fn build_nested(depth: u32) -> Vec<u8> {
    let mut jar = build_zip(&[("Leaf.class", &CLASS_BYTES)]);
    for _ in 0..depth {
        jar = build_zip(&[("inner.jar", &jar)]);
    }
    jar
}

/// Replaces every occurrence of `from` with `to`, which must be the same length.
fn patch_all(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut found = false;
    let mut at = 0;
    while at + from.len() <= bytes.len() {
        if &bytes[at..at + from.len()] == from {
            bytes[at..at + from.len()].copy_from_slice(to);
            found = true;
            at += from.len();
        } else {
            at += 1;
        }
    }
    assert!(found, "pattern not found");
}

/// Offset of the first central directory record.
fn central_record(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .position(|w| w == CENTRAL_SIGNATURE)
        .unwrap()
}

#[test]
fn reads_classes_resources_and_nested_jars() {
    let inner = build_zip(&[("lib/Inner.class", &CLASS_BYTES)]);
    let outer = build_zip(&[
        ("net/example/Mod.class", &CLASS_BYTES),
        ("fabric.mod.json", b"{}"),
        ("META-INF/jars/lib.jar", &inner),
    ]);

    let archive = read_archive(&outer, &ScanLimits::default()).unwrap();
    assert_eq!(archive.classes().count(), 1);
    assert_eq!(archive.nested.len(), 1);
    assert!(archive.anomalies.is_empty());

    let nested = &archive.nested[0];
    assert_eq!(nested.path, vec!["META-INF/jars/lib.jar".to_owned()]);
    assert_eq!(nested.classes().count(), 1);
    assert_ne!(nested.hashes.sha1, archive.hashes.sha1);
    assert_eq!(archive.walk().len(), 2);
}

#[test]
fn reads_stored_entries() {
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let jar = build_zip_with(&[("Mod.class", &CLASS_BYTES)], stored);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.entries[0].data, CLASS_BYTES);
    assert!(archive.anomalies.is_empty());
}

/// Rewrites a zip that has no archive comment so its end record defers to a
/// zip64 end record and locator, with every directory field saturated.
fn convert_to_zip64(zip: &[u8]) -> Vec<u8> {
    let end = zip.len() - 22;
    assert_eq!(&zip[end..end + 4], b"PK\x05\x06");
    let field = |at: usize, len: usize| {
        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(&zip[end + at..end + at + len]);
        u64::from_le_bytes(buf)
    };
    let (entries, central_size, central_offset) = (field(10, 2), field(12, 4), field(16, 4));

    let mut out = zip[..end].to_vec();
    let zip64_end = out.len() as u64;
    out.extend(b"PK\x06\x06");
    out.extend(44u64.to_le_bytes());
    out.extend([45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend(entries.to_le_bytes());
    out.extend(entries.to_le_bytes());
    out.extend(central_size.to_le_bytes());
    out.extend(central_offset.to_le_bytes());

    out.extend(b"PK\x06\x07");
    out.extend(0u32.to_le_bytes());
    out.extend(zip64_end.to_le_bytes());
    out.extend(1u32.to_le_bytes());

    out.extend(b"PK\x05\x06");
    out.extend([0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    out.extend([0xFF; 8]);
    out.extend([0, 0]);
    out
}

#[test]
fn reads_zip64_archives() {
    let jar = convert_to_zip64(&build_zip(&[
        ("Mod.class", &CLASS_BYTES),
        ("data.bin", b"data"),
    ]));

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.classes().count(), 1);
}

#[test]
fn opens_archive_with_end_signature_in_comment() {
    // The decoy sits far enough from the end that the backward search finds
    // it before the real end record. Its fields are plausible, one entry in
    // a small directory just before it, so only the check for a directory
    // record signature at that position rejects it.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("Mod.class", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(&CLASS_BYTES).unwrap();
    let mut comment = b"PK\x05\x06".to_vec();
    comment.extend([0, 0, 0, 0, 1, 0, 1, 0]);
    comment.extend(10u32.to_le_bytes());
    comment.extend(0u32.to_le_bytes());
    comment.extend([0, 0]);
    comment.extend([0x7F; 24]);
    writer.set_raw_comment(comment.into_boxed_slice()).unwrap();
    let jar = writer.finish().unwrap().into_inner();

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.classes().count(), 1);
}

#[test]
fn reads_every_copy_of_duplicate_names() {
    // Built with distinct names of equal length, then renamed in place.
    let mut jar = build_zip(&[("A.class", &CLASS_BYTES), ("B.class", &CLASS_BYTES)]);
    patch_all(&mut jar, b"B.class", b"A.class");

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.classes().count(), 2);
    assert_eq!(
        archive.anomalies,
        vec![Anomaly::DuplicateName {
            name: "A.class".to_owned()
        }]
    );
}

#[test]
fn reads_entries_with_bad_checksums() {
    let mut jar = build_zip(&[("Evil.class", &CLASS_BYTES)]);
    let crc = crc32fast::hash(&CLASS_BYTES).to_le_bytes();
    patch_all(&mut jar, &crc, &[0, 0, 0, 0]);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.classes().count(), 1);
    assert!(archive.unreadable.is_empty());
    assert_eq!(
        archive.anomalies,
        vec![Anomaly::ChecksumMismatch {
            name: "Evil.class".to_owned()
        }]
    );
}

#[test]
fn finds_nested_jar_behind_prepended_bytes() {
    let mut hidden = b"JUNKJUNK".to_vec();
    hidden.extend(build_zip(&[("Hidden.class", &CLASS_BYTES)]));
    let jar = build_zip(&[("assets/data.bin", &hidden)]);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.entries[0].kind, EntryKind::Archive);
    assert_eq!(archive.nested.len(), 1);

    let nested = &archive.nested[0];
    assert_eq!(nested.classes().count(), 1);
    assert_eq!(nested.anomalies, vec![Anomaly::PrependedData { size: 8 }]);
}

#[test]
fn opens_input_with_prepended_bytes() {
    let mut jar = vec![0u8; 100];
    jar.extend(build_zip(&[("Mod.class", &CLASS_BYTES)]));

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.classes().count(), 1);
    assert_eq!(
        archive.anomalies,
        vec![Anomaly::PrependedData { size: 100 }]
    );
}

#[test]
fn notes_encrypted_and_unsupported_entries() {
    let mut encrypted = build_zip(&[("Mod.class", &CLASS_BYTES)]);
    let record = central_record(&encrypted);
    encrypted[record + 8] |= 0x01;

    let archive = read_archive(&encrypted, &ScanLimits::default()).unwrap();
    assert_eq!(archive.unreadable[0].reason, "encrypted entry");

    let mut unsupported = build_zip(&[("Mod.class", &CLASS_BYTES)]);
    let record = central_record(&unsupported);
    unsupported[record + 10] = 99;

    let archive = read_archive(&unsupported, &ScanLimits::default()).unwrap();
    assert_eq!(
        archive.unreadable[0].reason,
        "unsupported compression method 99"
    );
}

#[test]
fn truncated_input_never_panics() {
    let inner = build_zip(&[("Inner.class", &CLASS_BYTES)]);
    let jar = build_zip(&[("Mod.class", &CLASS_BYTES), ("lib.jar", &inner)]);

    for len in 0..jar.len() {
        let _ = read_archive(&jar[..len], &ScanLimits::default());
    }
}

#[test]
fn detects_kind_by_content_not_name() {
    let jar = build_zip(&[
        ("assets/payload.dat", &CLASS_BYTES),
        ("Fake.class", b"not a class"),
    ]);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    let kinds: Vec<_> = archive.entries.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EntryKind::Class, EntryKind::Resource]);
    assert_eq!(
        archive.anomalies,
        vec![
            Anomaly::MisnamedEntry {
                name: "assets/payload.dat".to_owned()
            },
            Anomaly::MisnamedEntry {
                name: "Fake.class".to_owned()
            },
        ]
    );
}

#[test]
fn mach_o_universal_binary_is_not_a_class() {
    // Universal binary header with two architectures. It shares the class
    // magic, but the version bytes hold the architecture count.
    let mach_o = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
    let jar = build_zip(&[("natives/libfoo.dylib", &mach_o)]);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert_eq!(archive.entries[0].kind, EntryKind::Resource);
}

#[test]
fn zip_magic_without_valid_archive_is_noted() {
    let jar = build_zip(&[("broken.jar", b"PK\x03\x04garbage")]);

    let archive = read_archive(&jar, &ScanLimits::default()).unwrap();
    assert!(archive.nested.is_empty());
    assert_eq!(archive.unreadable.len(), 1);
    assert_eq!(archive.unreadable[0].name, "broken.jar");
}

#[test]
fn rejects_nesting_past_limit() {
    let limits = ScanLimits {
        max_nesting_depth: 2,
        ..ScanLimits::default()
    };

    assert!(read_archive(&build_nested(2), &limits).is_ok());
    assert!(matches!(
        read_archive(&build_nested(3), &limits),
        Err(ScanError::NestingTooDeep { .. })
    ));
}

#[test]
fn rejects_oversize_entry() {
    let limits = ScanLimits {
        max_entry_size: 16,
        ..ScanLimits::default()
    };
    let jar = build_zip(&[("big.bin", &[0u8; 17])]);

    assert!(matches!(
        read_archive(&jar, &limits),
        Err(ScanError::EntryTooLarge { .. })
    ));
}

#[test]
fn rejects_total_size_past_limit() {
    let limits = ScanLimits {
        max_total_size: 100,
        ..ScanLimits::default()
    };
    let jar = build_zip(&[("a.bin", &[0u8; 60]), ("b.bin", &[0u8; 60])]);

    assert!(matches!(
        read_archive(&jar, &limits),
        Err(ScanError::TotalSizeExceeded { .. })
    ));
}

#[test]
fn rejects_too_many_entries() {
    let limits = ScanLimits {
        max_entries: 2,
        ..ScanLimits::default()
    };
    let jar = build_zip(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);

    assert!(matches!(
        read_archive(&jar, &limits),
        Err(ScanError::TooManyEntries { .. })
    ));
}

#[test]
fn rejects_too_many_entries_across_nesting() {
    let limits = ScanLimits {
        max_entries: 3,
        ..ScanLimits::default()
    };
    let inner = build_zip(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
    let jar = build_zip(&[("lib.jar", &inner)]);

    assert!(matches!(
        read_archive(&jar, &limits),
        Err(ScanError::TooManyEntries { .. })
    ));
}

#[test]
fn rejects_oversize_input() {
    let limits = ScanLimits {
        max_input_size: 10,
        ..ScanLimits::default()
    };
    let jar = build_zip(&[("a", b"1")]);

    assert!(matches!(
        read_archive(&jar, &limits),
        Err(ScanError::InputTooLarge { .. })
    ));
}

#[test]
fn rejects_non_zip_input() {
    assert!(matches!(
        read_archive(b"not a jar", &ScanLimits::default()),
        Err(ScanError::InvalidArchive { .. })
    ));
}

#[test]
fn report_serializes_with_camel_case_fields() {
    let jar = build_zip(&[("Mod.class", &CLASS_BYTES), ("data.bin", &CLASS_BYTES)]);
    let report = scan_bytes(&jar, &ScanLimits::default()).unwrap();
    let json = serde_json::to_value(&report).unwrap();

    assert_eq!(json["archive"]["classCount"], 2);
    assert_eq!(json["archive"]["anomalies"][0]["kind"], "misnamedEntry");
    assert_eq!(json["archive"]["anomalies"][0]["name"], "data.bin");
    assert!(json["archive"]["hashes"]["curseforgeFingerprint"].is_u64());
    assert!(json["findings"].as_array().unwrap().is_empty());
}
