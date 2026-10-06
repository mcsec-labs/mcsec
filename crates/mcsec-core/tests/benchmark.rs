//! The false positive gate. Scans popular and long tail mods and requires
//! every finding to carry a hand label in benchmark/labels.json. An unlabeled
//! finding fails the test until a person reviews it, and so does a label
//! whose finding no longer appears.
//!
//! The benchmark has two tiers. The gate tier in benchmark/manifest.json is
//! small enough to run with every test run. The extended tier in
//! benchmark/extended/manifest.json is far larger and runs before a rule
//! change ships, only when MCSEC_BENCHMARK_EXTENDED is set, so a run of every
//! ignored test does not include it. Both share one labels file.
//!
//! A label covers one piece of code, not one jar, identified by the class
//! file's SHA-1, the method, the rule, and what the finding claims, its
//! severity, origin, safeguard, and exposure. The same library bundled in many jars is reviewed once,
//! and a finding whose claim changes needs a new review.
//!
//! Prints precision per rule over distinct labeled code, and for the gate
//! tier recall from the ground truth corpus, under the rule set version that
//! produced them. Setting MCSEC_BENCHMARK_UNLABELED to a file path writes
//! the unlabeled findings there as JSON for review.
//!
//! Needs the jars downloaded first with scripts/fetch-corpus.py and the
//! tier's manifest, and the corpus for the gate tier, so it is ignored by
//! default. Run it with `cargo test --test benchmark -- --ignored --nocapture`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mcsec_core::rules::spec::rules_version;
use mcsec_core::{FileHashes, Finding, ScanLimits, Severity, scan_bytes};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Manifest {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    file: String,
    sha1: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    expect: Vec<Expected>,
}

#[derive(Deserialize)]
struct Expected {
    rule: String,
    class: String,
    method: String,
    severity: String,
}

#[derive(Deserialize)]
struct Labels {
    labels: Vec<Label>,
}

/// Where a labeled finding was first seen, so a reviewer can find it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Example {
    file: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    archive_path: Vec<String>,
    entry: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Label {
    rule: String,
    class_sha1: String,
    class: String,
    method: String,
    descriptor: String,
    severity: String,
    origin: Option<String>,
    safeguard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exposure: Option<String>,
    verdict: String,
    reason: String,
    /// The benchmark tiers this code appears in.
    tiers: Vec<String>,
    example: Example,
}

/// What identifies a labeled piece of code and the claim made about it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct Key {
    rule: String,
    class_sha1: String,
    class: String,
    method: String,
    descriptor: String,
    severity: String,
    origin: Option<String>,
    safeguard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exposure: Option<String>,
}

fn name_of<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

impl Key {
    fn of(finding: &Finding) -> Self {
        let location = &finding.location;
        let method = location.method.as_ref();
        Self {
            rule: finding.rule_id.clone(),
            class_sha1: finding.class_sha1.clone().unwrap_or_default(),
            class: location.class_name.clone().unwrap_or_default(),
            method: method.map(|m| m.name.clone()).unwrap_or_default(),
            descriptor: method.map(|m| m.descriptor.clone()).unwrap_or_default(),
            severity: name_of(finding.severity),
            origin: finding.origin.map(name_of),
            safeguard: finding.safeguard.map(name_of),
            exposure: finding.exposure.map(name_of),
        }
    }

    fn of_label(label: &Label) -> Self {
        Self {
            rule: label.rule.clone(),
            class_sha1: label.class_sha1.clone(),
            class: label.class.clone(),
            method: label.method.clone(),
            descriptor: label.descriptor.clone(),
            severity: label.severity.clone(),
            origin: label.origin.clone(),
            safeguard: label.safeguard.clone(),
            exposure: label.exposure.clone(),
        }
    }

    fn describe(&self) -> String {
        let claim = [
            Some(&self.severity),
            self.origin.as_ref(),
            self.safeguard.as_ref(),
            self.exposure.as_ref(),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
        format!(
            "{claim} {} in {}.{}{} (class {})",
            self.rule, self.class, self.method, self.descriptor, self.class_sha1
        )
    }
}

/// An unlabeled finding, written out for review.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Unlabeled<'f> {
    #[serde(flatten)]
    key: Key,
    example: Example,
    group: Option<String>,
    evidence: Vec<&'f str>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

/// Scans every cached jar a manifest lists, checking each SHA-1.
fn scan_manifest(dir: &Path) -> Vec<(Entry, Vec<Finding>)> {
    let manifest: Manifest = read_json(&dir.join("manifest.json"));
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    let mut scanned = Vec::new();
    for entry in manifest.entries {
        let Ok(bytes) = std::fs::read(dir.join("cache").join(&entry.file)) else {
            missing.push(entry.name);
            continue;
        };
        assert_eq!(
            FileHashes::compute(&bytes).sha1,
            entry.sha1,
            "{}: cached file does not match the manifest's SHA-1",
            entry.name
        );
        match scan_bytes(&bytes, &ScanLimits::default()) {
            Ok(report) => scanned.push((entry, report.findings)),
            Err(error) => failed.push(format!("{}: {error}", entry.name)),
        }
    }
    assert!(
        failed.is_empty(),
        "{} jars failed to scan:
{}",
        failed.len(),
        failed.join(
            "
"
        )
    );
    assert!(
        missing.is_empty(),
        "{} jars are not downloaded, run scripts/fetch-corpus.py {}: {missing:?}",
        missing.len(),
        dir.join("manifest.json").display()
    );
    scanned
}

/// Counts for one rule, over distinct labeled code.
#[derive(Default)]
struct RuleMetrics {
    true_positives: usize,
    false_positives: usize,
    accurate_notices: usize,
    inaccurate_notices: usize,
    expected_positives: usize,
    found_positives: usize,
}

fn ratio(part: usize, whole: usize) -> String {
    if whole == 0 {
        "n/a".to_owned()
    } else {
        format!(
            "{:.1}% ({part}/{whole})",
            part as f64 * 100.0 / whole as f64
        )
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Checks one tier against the labels and returns the metrics so far.
fn check_tier(tier: &str, dir: &Path) -> BTreeMap<String, RuleMetrics> {
    let labels: Labels = read_json(&root().join("benchmark/labels.json"));
    let mut problems = Vec::new();
    let mut labeled: BTreeMap<Key, &Label> = BTreeMap::new();
    for label in &labels.labels {
        let valid = match label.severity.as_str() {
            "critical" | "warning" => ["true-positive", "false-positive"],
            "notice" => ["accurate", "inaccurate"],
            other => panic!("label has unknown severity {other:?}"),
        };
        let key = Key::of_label(label);
        if !valid.contains(&label.verdict.as_str()) || label.reason.trim().is_empty() {
            problems.push(format!(
                "label for {} needs a verdict from {valid:?} and a reason",
                key.describe()
            ));
        }
        if labeled.insert(key.clone(), label).is_some() {
            problems.push(format!("duplicate label for {}", key.describe()));
        }
    }

    let mut metrics: BTreeMap<String, RuleMetrics> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut unlabeled: BTreeMap<Key, Unlabeled> = BTreeMap::new();
    let mut occurrences = 0usize;
    // Jars and findings per selection group, as (jars, flagged, notices).
    let mut groups: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let scanned = scan_manifest(dir);
    for (entry, findings) in &scanned {
        let group_name = entry
            .group
            .clone()
            .unwrap_or_else(|| "ungrouped".to_owned());
        let group = groups.entry(group_name).or_default();
        group.0 += 1;
        for finding in findings {
            occurrences += 1;
            match finding.severity {
                Severity::Notice => group.2 += 1,
                _ => group.1 += 1,
            }
            let key = Key::of(finding);
            if !seen.insert(key.clone()) {
                continue;
            }
            let Some(label) = labeled.get(&key) else {
                unlabeled.insert(
                    key.clone(),
                    Unlabeled {
                        key,
                        example: Example {
                            file: entry.file.clone(),
                            archive_path: finding.location.archive_path.clone(),
                            entry: finding.location.entry.clone().unwrap_or_default(),
                        },
                        group: entry.group.clone(),
                        evidence: finding
                            .evidence
                            .iter()
                            .map(|step| step.description.as_str())
                            .collect(),
                    },
                );
                continue;
            };
            if !label.tiers.iter().any(|t| t == tier) {
                problems.push(format!(
                    "label for {} does not list tier {tier}",
                    key.describe()
                ));
            }
            let counts = metrics.entry(key.rule.clone()).or_default();
            match label.verdict.as_str() {
                "true-positive" => counts.true_positives += 1,
                "false-positive" => counts.false_positives += 1,
                "accurate" => counts.accurate_notices += 1,
                _ => counts.inaccurate_notices += 1,
            }
        }
    }
    for (key, label) in &labeled {
        if label.tiers.iter().any(|t| t == tier) && !seen.contains(key) {
            problems.push(format!(
                "label without a finding in tier {tier}, update or remove it: {}, first seen in {}",
                key.describe(),
                label.example.file
            ));
        }
    }
    for key in unlabeled.keys() {
        problems.push(format!("unlabeled finding {}", key.describe()));
    }
    if let Ok(path) = std::env::var("MCSEC_BENCHMARK_UNLABELED") {
        let list: Vec<&Unlabeled> = unlabeled.values().collect();
        std::fs::write(&path, serde_json::to_string_pretty(&list).unwrap())
            .unwrap_or_else(|error| panic!("cannot write {path}: {error}"));
    }

    println!(
        "rules version {}, tier {tier}, {} jars, {occurrences} findings over {} distinct pieces of code",
        rules_version(),
        scanned.len(),
        seen.len()
    );
    for (group, (jars, flagged, notices)) in &groups {
        println!("    {group}: {jars} jars, {flagged} warnings or criticals, {notices} notices");
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    metrics
}

fn print_metrics(metrics: &BTreeMap<String, RuleMetrics>) {
    for (rule, counts) in metrics {
        let flagged = counts.true_positives + counts.false_positives;
        let notices = counts.accurate_notices + counts.inaccurate_notices;
        println!("{rule}");
        println!("    precision {}", ratio(counts.true_positives, flagged));
        if counts.expected_positives > 0 {
            println!(
                "    recall    {}",
                ratio(counts.found_positives, counts.expected_positives)
            );
        }
        println!(
            "    notices   {} accurate",
            ratio(counts.accurate_notices, notices)
        );
    }
}

#[test]
#[ignore = "needs the gate benchmark and corpus jars, download them with scripts/fetch-corpus.py"]
fn gate_findings_are_labeled() {
    let mut metrics = check_tier("gate", &root().join("benchmark"));

    // Recall comes from the ground truth corpus, where every vulnerable
    // finding is known in advance.
    for (entry, findings) in scan_manifest(&root().join("corpus")) {
        if !matches!(entry.role.as_deref(), Some("vulnerable" | "unfixed")) {
            continue;
        }
        for expected in entry
            .expect
            .iter()
            .filter(|e| e.severity == "critical" || e.severity == "warning")
        {
            let counts = metrics.entry(expected.rule.clone()).or_default();
            counts.expected_positives += 1;
            let found = findings.iter().any(|finding| {
                let location = &finding.location;
                finding.rule_id == expected.rule
                    && location.class_name.as_deref() == Some(expected.class.as_str())
                    && location.method.as_ref().map(|m| m.name.as_str())
                        == Some(expected.method.as_str())
                    && name_of(finding.severity) == expected.severity
            });
            if found {
                counts.found_positives += 1;
            }
        }
    }
    print_metrics(&metrics);
}

#[test]
#[ignore = "needs the extended benchmark jars, download them with scripts/fetch-corpus.py"]
fn extended_findings_are_labeled() {
    if std::env::var_os("MCSEC_BENCHMARK_EXTENDED").is_none() {
        println!("extended tier skipped, set MCSEC_BENCHMARK_EXTENDED=1 to run it");
        return;
    }
    let metrics = check_tier("extended", &root().join("benchmark/extended"));
    print_metrics(&metrics);
}
