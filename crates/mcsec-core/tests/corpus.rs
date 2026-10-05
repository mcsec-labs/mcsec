//! The phase 1 exit test. Scans every ground truth jar in corpus/manifest.json
//! and requires exactly the findings each entry lists.
//!
//! Needs the jars downloaded first with scripts/fetch-corpus.py, so it is
//! ignored by default. Run it with `cargo test --test corpus -- --ignored`.

use std::path::PathBuf;

use mcsec_core::{FileHashes, ScanLimits, scan_bytes};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    role: String,
    file: String,
    sha1: String,
    expect: Vec<Expected>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Expected {
    rule: String,
    class: String,
    method: String,
    severity: String,
}

#[test]
#[ignore = "needs the corpus, download it with scripts/fetch-corpus.py"]
fn corpus_matches_ground_truth() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(corpus.join("manifest.json")).unwrap()).unwrap();

    let mut missing = Vec::new();
    let mut failures = Vec::new();
    for entry in &manifest.entries {
        let Ok(bytes) = std::fs::read(corpus.join("cache").join(&entry.file)) else {
            missing.push(entry.name.as_str());
            continue;
        };
        if FileHashes::compute(&bytes).sha1 != entry.sha1 {
            failures.push(format!(
                "{}: cached file does not match the manifest's SHA-1",
                entry.name
            ));
            continue;
        }

        let report = scan_bytes(&bytes, &ScanLimits::default())
            .unwrap_or_else(|error| panic!("{} failed to scan: {error}", entry.name));
        let mut actual: Vec<Expected> = report
            .findings
            .iter()
            .map(|finding| Expected {
                rule: finding.rule_id.clone(),
                class: finding.location.class_name.clone().unwrap_or_default(),
                method: finding
                    .location
                    .method
                    .as_ref()
                    .map(|m| m.name.clone())
                    .unwrap_or_default(),
                severity: serde_json::to_value(finding.severity)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            })
            .collect();
        actual.sort();
        let mut expected = entry.expect.clone();
        expected.sort();

        if actual == expected {
            println!("ok {} ({})", entry.name, entry.role);
        } else {
            failures.push(format!(
                "{} ({}):\n  expected {expected:#?}\n  actual {actual:#?}",
                entry.name, entry.role
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "jars missing from corpus/cache: {missing:?}"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
