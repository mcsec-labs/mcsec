//! Rule definition files and their compiled form.
//!
//! Rules are TOML files under `crates/mcsec-core/rules`, embedded at build
//! time. Each declares the sources of untrusted data, the sinks that are
//! dangerous with it, and the sanitizers that make a sink safe. The data
//! flow engine and [`super::flow`] do the rest, so a new bug class is a new
//! file.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::dataflow::Labels;

/// Rule files compiled into the scanner, as (file name, contents).
const RULE_FILES: &[(&str, &str)] = &[(
    "unsafe-deserialization.toml",
    include_str!("../../rules/unsafe-deserialization.toml"),
)];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RuleFile {
    id: String,
    name: String,
    cwe: String,
    explanation: String,
    fix: String,
    sources: BTreeMap<String, SourceFile>,
    sinks: Vec<SinkFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SourceFile {
    types: Vec<String>,
    parameter: String,
    receiver: String,
    call: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SinkFile {
    id: String,
    kind: SinkKind,
    #[serde(rename = "type")]
    stream_type: String,
    reads: Vec<String>,
    critical_sources: Vec<String>,
    creates: String,
    read: String,
    subclass: Option<String>,
    title: Titles,
    #[serde(default)]
    sanitizers: Vec<SanitizerFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SanitizerFile {
    call: String,
    target: String,
    note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SinkKind {
    /// An object the method creates over some data and then reads from.
    Stream,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Titles {
    pub critical: String,
    pub warning: String,
    pub notice: String,
}

/// A method named as `owner.name(descriptor)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSig {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
}

impl MethodSig {
    fn parse(text: &str) -> Result<Self, String> {
        let open = text
            .find('(')
            .ok_or_else(|| format!("{text:?} has no descriptor"))?;
        let dot = text[..open]
            .rfind('.')
            .ok_or_else(|| format!("{text:?} has no owner"))?;
        Ok(Self {
            owner: text[..dot].to_owned(),
            name: text[dot + 1..open].to_owned(),
            descriptor: text[open..].to_owned(),
        })
    }
}

/// Which value a sanitizer call applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Receiver,
    Argument(usize),
}

impl Target {
    fn parse(text: &str) -> Result<Self, String> {
        match text.split_once(' ') {
            None if text == "receiver" => Ok(Self::Receiver),
            Some(("argument", index)) => index
                .parse()
                .map(Self::Argument)
                .map_err(|_| format!("bad argument index in target {text:?}")),
            _ => Err(format!("unknown target {text:?}")),
        }
    }
}

#[derive(Debug)]
pub struct Source {
    pub id: String,
    pub label: Labels,
    pub types: Vec<String>,
    pub parameter: String,
    pub receiver: String,
    pub call: String,
}

#[derive(Debug)]
pub struct Sanitizer {
    pub call: MethodSig,
    pub target: Target,
    pub note: String,
}

#[derive(Debug)]
pub struct Sink {
    pub id: String,
    pub kind: SinkKind,
    pub stream_type: String,
    pub reads: Vec<MethodSig>,
    /// Labels that make a read Critical.
    pub critical: Labels,
    pub creates: String,
    pub read: String,
    pub subclass: Option<String>,
    pub title: Titles,
    pub sanitizers: Vec<Sanitizer>,
}

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub cwe: String,
    pub explanation: String,
    pub fix: String,
    pub sources: Vec<Source>,
    pub sinks: Vec<Sink>,
}

impl Rule {
    fn compile(file: RuleFile) -> Result<Self, String> {
        if file.sources.len() > 32 {
            return Err("a rule can declare at most 32 sources, one per label bit".to_owned());
        }
        let sources: Vec<Source> = file
            .sources
            .into_iter()
            .enumerate()
            .map(|(bit, (id, source))| Source {
                label: Labels(1 << bit),
                id,
                types: source.types,
                parameter: source.parameter,
                receiver: source.receiver,
                call: source.call,
            })
            .collect();

        let mut sinks = Vec::new();
        for sink in file.sinks {
            let mut critical = Labels::default();
            for id in &sink.critical_sources {
                let source = sources
                    .iter()
                    .find(|s| &s.id == id)
                    .ok_or_else(|| format!("sink {} names unknown source {id:?}", sink.id))?;
                critical.0 |= source.label.0;
            }
            let reads = sink
                .reads
                .iter()
                .map(|r| MethodSig::parse(r))
                .collect::<Result<_, _>>()?;
            let sanitizers = sink
                .sanitizers
                .into_iter()
                .map(|s| {
                    Ok(Sanitizer {
                        call: MethodSig::parse(&s.call)?,
                        target: Target::parse(&s.target)?,
                        note: s.note,
                    })
                })
                .collect::<Result<_, String>>()?;
            sinks.push(Sink {
                id: sink.id,
                kind: sink.kind,
                stream_type: sink.stream_type,
                reads,
                critical,
                creates: sink.creates,
                read: sink.read,
                subclass: sink.subclass,
                title: sink.title,
                sanitizers,
            });
        }

        Ok(Self {
            id: file.id,
            name: file.name,
            cwe: file.cwe,
            explanation: file.explanation,
            fix: file.fix,
            sources,
            sinks,
        })
    }
}

/// Parses and compiles rule files, naming the file in any error.
pub fn compile_all(files: &[(&str, &str)]) -> Result<Vec<Rule>, String> {
    files
        .iter()
        .map(|(name, text)| {
            let file: RuleFile = toml::from_str(text).map_err(|e| format!("{name}: {e}"))?;
            Rule::compile(file).map_err(|e| format!("{name}: {e}"))
        })
        .collect()
}

/// The rules compiled into the scanner, parsed once.
pub fn embedded() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    // The files are fixed at build time and checked by the test below, so a
    // failure here can only come from an edit that never passed tests.
    RULES.get_or_init(|| {
        compile_all(RULE_FILES).unwrap_or_else(|e| panic!("invalid embedded rule {e}"))
    })
}

/// Fills `{key}` placeholders in a message template.
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    values
        .iter()
        .fold(template.to_owned(), |text, (key, value)| {
            text.replace(&format!("{{{key}}}"), value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_compile() {
        let rules = compile_all(RULE_FILES).unwrap();
        assert_eq!(rules.len(), RULE_FILES.len());
    }

    #[test]
    fn parses_method_signatures_and_targets() {
        let sig = MethodSig::parse(
            "java/io/ObjectInputFilter$Config.setObjectInputFilter(Ljava/io/ObjectInputStream;)V",
        )
        .unwrap();
        assert_eq!(sig.owner, "java/io/ObjectInputFilter$Config");
        assert_eq!(sig.name, "setObjectInputFilter");
        assert_eq!(sig.descriptor, "(Ljava/io/ObjectInputStream;)V");
        assert!(MethodSig::parse("noDescriptor").is_err());

        assert_eq!(Target::parse("receiver"), Ok(Target::Receiver));
        assert_eq!(Target::parse("argument 2"), Ok(Target::Argument(2)));
        assert!(Target::parse("argument x").is_err());
        assert!(Target::parse("elsewhere").is_err());
    }

    #[test]
    fn rejects_bad_rule_files() {
        let unknown_field = "id='x'\nname='x'\ncwe='x'\nexplanation='x'\nfix='x'\nsinks=[]\nsurprise=1\n[sources]\n";
        assert!(
            compile_all(&[("bad.toml", unknown_field)])
                .unwrap_err()
                .starts_with("bad.toml")
        );
    }

    #[test]
    fn fills_templates() {
        assert_eq!(
            fill("Reads {owner}.{name}", &[("owner", "a/B"), ("name", "c")]),
            "Reads a/B.c"
        );
    }
}
