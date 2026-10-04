//! Archive reading against jars built in memory.

use std::io::{Cursor, Write};

use mcsec_core::{EntryKind, ScanError, ScanLimits, read_archive, scan_bytes};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// Class file magic followed by minor version 0 and major version 65 (Java 21).
const CLASS_BYTES: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];

/// Builds a zip from (name, bytes) pairs.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Builds a jar nested `depth` levels deep, each holding the next as `inner.jar`.
fn build_nested(depth: u32) -> Vec<u8> {
    let mut jar = build_zip(&[("Leaf.class", &CLASS_BYTES)]);
    for _ in 0..depth {
        jar = build_zip(&[("inner.jar", &jar)]);
    }
    jar
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

    let nested = &archive.nested[0];
    assert_eq!(nested.path, vec!["META-INF/jars/lib.jar".to_owned()]);
    assert_eq!(nested.classes().count(), 1);
    assert_ne!(nested.hashes.sha1, archive.hashes.sha1);
    assert_eq!(archive.walk().len(), 2);
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
    assert!(archive.entries.iter().all(|e| !e.name_matches_content()));
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
    assert_eq!(json["archive"]["mismatchedNames"][0], "data.bin");
    assert!(json["archive"]["hashes"]["curseforgeFingerprint"].is_u64());
    assert!(json["findings"].as_array().unwrap().is_empty());
}
