//! Measures how rules generalize, using the variant corpus of small Java
//! programs that write the same bug many different ways, plus safe code
//! that must stay clean. Each method carries a marker comment such as
//! `// EXPECT critical` or `// EXPECT none`. Words after the severity name
//! the finding's origin or safeguard as the report spells them, such as
//! `// EXPECT notice localFile` or `// EXPECT notice allowlist`, and are
//! checked when present.
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
    /// Origin and safeguard names the finding must carry.
    basis: Vec<String>,
    known_gap: bool,
}

impl Expectation {
    fn describe(&self) -> String {
        std::iter::once(&self.severity)
            .chain(&self.basis)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn matches(&self, got: &[String]) -> bool {
        got.first() == Some(&self.severity) && self.basis.iter().all(|word| got.contains(word))
    }
}

/// Expectations by (internal class name, method name), from source markers,
/// with the Java release each class requires.
struct SourceFile {
    requires: u32,
    /// Expectations by (internal class name, method name). Methods of nested
    /// classes belong to names such as `Outer$Inner`.
    expectations: BTreeMap<(String, String), Expectation>,
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
    let outer = format!("{package}/{}", path.file_stem().unwrap().to_string_lossy());

    let mut expectations = BTreeMap::new();
    let mut pending: Option<Expectation> = None;
    // Nested classes open so far, each with the brace depth inside it.
    let mut nesting: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    for line in text.lines().map(str::trim) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let declared = words
            .windows(2)
            .find(|pair| matches!(pair[0], "class" | "interface" | "enum"))
            .map(|pair| pair[1].trim_end_matches('{').to_owned());
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        if let Some(name) = declared.filter(|_| !line.starts_with("//") && !line.starts_with('*')) {
            // The top level class is the file's own, and only classes
            // inside it get a nested name.
            if depth > 0 {
                nesting.push((name, depth + opens));
            }
        }
        depth = (depth + opens).saturating_sub(closes);
        while nesting.last().is_some_and(|(_, inside)| depth < *inside) {
            nesting.pop();
        }
        let class = std::iter::once(outer.as_str())
            .chain(nesting.iter().map(|(name, _)| name.as_str()))
            .collect::<Vec<_>>()
            .join("$");

        if let Some(marker) = line.strip_prefix("// EXPECT ") {
            let mut words: Vec<String> = marker.split_whitespace().map(str::to_owned).collect();
            let known_gap = words.last().is_some_and(|w| w == "KNOWN-GAP");
            if known_gap {
                words.pop();
            }
            let severity = words.remove(0);
            pending = Some(Expectation {
                severity,
                basis: words,
                known_gap,
            });
        } else if pending.is_some() && line.contains('(') && !line.starts_with('@') {
            let before = &line[..line.find('(').unwrap()];
            let method = before.split_whitespace().last().unwrap().to_owned();
            expectations.insert((class, method), pending.take().unwrap());
        }
    }
    SourceFile {
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

        // Severity first, then the origin and safeguard when present.
        let mut actual: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for finding in &report.findings {
            let class = finding.location.class_name.clone().unwrap_or_default();
            let method = finding
                .location
                .method
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let name = |value: serde_json::Value| value.as_str().map(str::to_owned);
            let words = [
                name(serde_json::to_value(finding.severity).unwrap()),
                finding
                    .origin
                    .and_then(|o| name(serde_json::to_value(o).unwrap())),
                finding
                    .safeguard
                    .and_then(|s| name(serde_json::to_value(s).unwrap())),
            ];
            actual.insert((class, method), words.into_iter().flatten().collect());
        }

        let (mut ok, mut gaps, mut fixed_gaps) = (0, Vec::new(), Vec::new());
        for source in sources.iter().filter(|s| s.requires <= release) {
            for ((class, method), expected) in &source.expectations {
                let key = (class.clone(), method.clone());
                let got = actual
                    .remove(&key)
                    .unwrap_or_else(|| vec!["none".to_owned()]);
                let label = format!("{class}.{method}");
                let (wanted, found) = (expected.describe(), got.join(" "));
                match (expected.matches(&got), expected.known_gap) {
                    (true, false) => ok += 1,
                    (true, true) => fixed_gaps.push(label),
                    (false, true) => gaps.push(format!("{label}: expected {wanted}, got {found}")),
                    (false, false) => failures.push(format!(
                        "release {release}: {label}: expected {wanted}, got {found}"
                    )),
                }
            }
        }
        for ((class, method), words) in actual {
            if class.starts_with("variants/") {
                failures.push(format!(
                    "release {release}: {class}.{method}: unexpected {} finding, or a method without an EXPECT marker",
                    words.join(" ")
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
