//! Measures how rules generalize, using the variant corpus: small Java
//! programs that write the same bug many different ways, plus safe code
//! that must stay clean. Each method carries a marker comment such as
//! `// EXPECT critical` or `// EXPECT none`.
//!
//! A marker ending in KNOWN-GAP records the right answer for a case the
//! engine cannot reach yet. Those are counted and listed instead of failing,
//! and a gap that starts passing is reported so its marker can be updated.
//!
//! Needs the variants compiled first with scripts/build-variants.py, so it is
//! ignored by default. Run it with `cargo test --test variants -- --ignored`.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use mcsec_core::{ScanLimits, scan_bytes};

struct Expectation {
    severity: String,
    known_gap: bool,
}

/// Expectations by (internal class name, method name), from source markers,
/// with the Java release each class requires.
struct SourceFile {
    class: String,
    requires: u32,
    expectations: BTreeMap<String, Expectation>,
}

fn java_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            java_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "java") {
            out.push(path);
        }
    }
}

fn parse_source(path: &Path) -> SourceFile {
    let text = fs::read_to_string(path).unwrap();
    let requires = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("// REQUIRES java "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    let package = text
        .lines()
        .find_map(|line| line.strip_prefix("package "))
        .map(|p| p.trim_end_matches(';').replace('.', "/"))
        .unwrap_or_default();
    let class = format!("{package}/{}", path.file_stem().unwrap().to_string_lossy());

    let mut expectations = BTreeMap::new();
    let mut pending: Option<Expectation> = None;
    for line in text.lines().map(str::trim) {
        if let Some(marker) = line.strip_prefix("// EXPECT ") {
            let mut words = marker.split_whitespace();
            pending = Some(Expectation {
                severity: words.next().unwrap().to_owned(),
                known_gap: words.next() == Some("KNOWN-GAP"),
            });
        } else if pending.is_some() && line.contains('(') && !line.starts_with('@') {
            let before = &line[..line.find('(').unwrap()];
            let method = before.split_whitespace().last().unwrap().to_owned();
            expectations.insert(method, pending.take().unwrap());
        }
    }
    SourceFile {
        class,
        requires,
        expectations,
    }
}

fn class_files(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            class_files(&path, root, out);
        } else {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((name, fs::read(&path).unwrap()));
        }
    }
}

#[test]
#[ignore = "needs compiled variants, build them with scripts/build-variants.py"]
fn variants_match_expectations() {
    let variants = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/variants");
    let build = variants.join("build");
    assert!(
        build.is_dir(),
        "no compiled variants in {}",
        build.display()
    );

    let mut sources = Vec::new();
    for dir in fs::read_dir(&variants).unwrap().flatten() {
        let path = dir.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() && name != "build" && name != "stubs" {
            java_files(&path, &mut sources);
        }
    }
    let sources: Vec<SourceFile> = sources.iter().map(|p| parse_source(p)).collect();

    let mut failures = Vec::new();
    let mut releases: Vec<u32> = fs::read_dir(&build)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
        .collect();
    releases.sort_unstable();
    assert!(
        !releases.is_empty(),
        "no compiled releases in {}",
        build.display()
    );

    for release in releases {
        let root = build.join(release.to_string());
        let mut entries = Vec::new();
        class_files(&root, &root, &mut entries);
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let report = scan_bytes(&common::jar(&refs), &ScanLimits::default()).unwrap();

        let mut actual: BTreeMap<(String, String), String> = BTreeMap::new();
        for finding in &report.findings {
            let class = finding.location.class_name.clone().unwrap_or_default();
            let method = finding
                .location
                .method
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let severity = serde_json::to_value(finding.severity)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            actual.insert((class, method), severity);
        }

        let (mut ok, mut gaps, mut fixed_gaps) = (0, Vec::new(), Vec::new());
        for source in sources.iter().filter(|s| s.requires <= release) {
            for (method, expected) in &source.expectations {
                let key = (source.class.clone(), method.clone());
                let got = actual.remove(&key).unwrap_or_else(|| "none".to_owned());
                let label = format!("{}.{method}", source.class);
                match (got == expected.severity, expected.known_gap) {
                    (true, false) => ok += 1,
                    (true, true) => fixed_gaps.push(label),
                    (false, true) => gaps.push(format!(
                        "{label}: expected {}, got {got}",
                        expected.severity
                    )),
                    (false, false) => failures.push(format!(
                        "release {release}: {label}: expected {}, got {got}",
                        expected.severity
                    )),
                }
            }
        }
        for ((class, method), severity) in actual {
            if class.starts_with("variants/") {
                failures.push(format!(
                    "release {release}: {class}.{method}: unexpected {severity} finding, or a method without an EXPECT marker"
                ));
            }
        }

        println!("release {release}: {ok} correct, {} known gaps", gaps.len());
        for gap in &gaps {
            println!("    known gap {gap}");
        }
        for fixed in &fixed_gaps {
            println!("    FIXED gap {fixed}, remove its KNOWN-GAP marker");
        }
        assert!(
            fixed_gaps.is_empty(),
            "known gaps now pass, update their markers: {fixed_gaps:?}"
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
