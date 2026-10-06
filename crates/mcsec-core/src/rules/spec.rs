//! Rule definition files and their compiled form.
//!
//! Rules are TOML files under `crates/mcsec-core/rules`, embedded at build
//! time. Each declares the sources of untrusted data, the sinks that are
//! dangerous with it, and the settings that make a sink safe or unsafe. The
//! data flow engine and [`super::flow`] do the rest, so a new bug class is a
//! new file.

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
    #[serde(default)]
    types: Vec<String>,
    calls: Vec<String>,
    data: Option<String>,
    #[serde(default)]
    default: Effect,
    critical_sources: Vec<String>,
    creates: Option<String>,
    read: String,
    subclass: Option<String>,
    outside: Option<String>,
    library: Option<Library>,
    title: Titles,
    #[serde(default)]
    settings: Vec<SettingFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SettingFile {
    call: String,
    target: String,
    effect: Effect,
    when: Option<ConditionFile>,
    note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ConditionFile {
    argument: usize,
    is: Option<String>,
    extends: Option<String>,
    not_extends: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SinkKind {
    /// An object the method creates over some data and then reads from.
    Stream,
    /// A call that takes the data as one of its arguments.
    Call,
}

/// Whether a setting, or a deserializer left at its defaults, accepts any
/// class the data names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    #[default]
    Unsafe,
    Safe,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Titles {
    pub critical: String,
    pub warning: String,
    pub notice: String,
}

/// A library whose defaults became safe in a later version.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Library {
    pub name: String,
    /// Maven coordinates as `group:artifact`.
    pub coordinates: String,
    /// The first version whose defaults are safe.
    pub safe_from: String,
}

/// A method named as `owner.name(descriptor)`, where a descriptor of `(*)`
/// matches every overload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSig {
    pub owner: String,
    pub name: String,
    pub descriptor: Option<String>,
}

impl MethodSig {
    fn parse(text: &str) -> Result<Self, String> {
        let open = text
            .find('(')
            .ok_or_else(|| format!("{text:?} has no descriptor"))?;
        let dot = text[..open]
            .rfind('.')
            .ok_or_else(|| format!("{text:?} has no owner"))?;
        let descriptor = &text[open..];
        Ok(Self {
            owner: text[..dot].to_owned(),
            name: text[dot + 1..open].to_owned(),
            descriptor: (descriptor != "(*)").then(|| descriptor.to_owned()),
        })
    }

    /// True when the name matches and the descriptor matches or is `(*)`.
    /// The owner is left to the caller, which checks it against the class
    /// hierarchy.
    pub fn matches_name(&self, name: &str, descriptor: &str) -> bool {
        self.name == name && self.descriptor.as_deref().is_none_or(|d| d == descriptor)
    }
}

/// Which value of a call a setting or sink refers to.
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

    /// Stack depth of the target below the top, just before a call taking
    /// `arguments` values. `None` when the call has no such argument.
    pub fn depth(self, arguments: usize) -> Option<usize> {
        match self {
            Self::Receiver => Some(arguments),
            Self::Argument(i) => arguments.checked_sub(i + 1),
        }
    }
}

/// A fixed value an argument must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Is {
    Int(i32),
    /// A static field, as `owner.name`.
    Static(String),
}

impl Is {
    fn parse(text: &str) -> Result<Self, String> {
        match text.split_once(' ') {
            Some(("int", value)) => value
                .parse()
                .map(Self::Int)
                .map_err(|_| format!("bad int in {text:?}")),
            Some(("field", field)) if field.contains('.') => Ok(Self::Static(field.to_owned())),
            _ => Err(format!(
                "unknown value {text:?}, expected \"int N\" or \"field owner.name\""
            )),
        }
    }
}

/// What a setting's argument must be for the setting to apply.
#[derive(Debug)]
pub struct Condition {
    pub argument: usize,
    pub is: Option<Is>,
    /// The argument was created in the method from this class or a subclass.
    pub extends: Option<String>,
    pub not_extends: Option<String>,
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

/// A call that configures a deserializer.
#[derive(Debug)]
pub struct Setting {
    pub call: MethodSig,
    pub target: Target,
    pub effect: Effect,
    pub condition: Option<Condition>,
    pub note: String,
}

#[derive(Debug)]
pub struct Sink {
    pub id: String,
    pub kind: SinkKind,
    /// Stream sinks: the types created and read from. Call sinks: the
    /// receiver types, empty for static calls.
    pub types: Vec<String>,
    pub calls: Vec<MethodSig>,
    /// Call sinks: the argument carrying the data.
    pub data: Option<Target>,
    pub default: Effect,
    /// Labels that make a use Critical.
    pub critical: Labels,
    pub creates: Option<String>,
    pub read: String,
    pub subclass: Option<String>,
    pub outside: Option<String>,
    pub library: Option<Library>,
    pub title: Titles,
    pub settings: Vec<Setting>,
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

impl Setting {
    fn compile(file: SettingFile) -> Result<Self, String> {
        let condition = file
            .when
            .map(|when| {
                Ok::<_, String>(Condition {
                    argument: when.argument,
                    is: when.is.as_deref().map(Is::parse).transpose()?,
                    extends: when.extends,
                    not_extends: when.not_extends,
                })
            })
            .transpose()?;
        Ok(Self {
            call: MethodSig::parse(&file.call)?,
            target: Target::parse(&file.target)?,
            effect: file.effect,
            condition,
            note: file.note,
        })
    }
}

impl Sink {
    fn compile(file: SinkFile, sources: &[Source]) -> Result<Self, String> {
        let id = &file.id;
        let mut critical = Labels::default();
        for source_id in &file.critical_sources {
            let source = sources
                .iter()
                .find(|s| &s.id == source_id)
                .ok_or_else(|| format!("sink {id} names unknown source {source_id:?}"))?;
            critical.0 |= source.label.0;
        }
        if file.calls.is_empty() {
            return Err(format!("sink {id} lists no calls"));
        }
        let data = file.data.as_deref().map(Target::parse).transpose()?;
        match file.kind {
            SinkKind::Stream if file.types.is_empty() || data.is_some() => {
                return Err(format!(
                    "stream sink {id} needs types and reads its data from the stream, not from data"
                ));
            }
            SinkKind::Call if !matches!(data, Some(Target::Argument(_))) => {
                return Err(format!("call sink {id} needs data = \"argument N\""));
            }
            _ => {}
        }
        if !file.types.is_empty() && file.creates.is_none() {
            return Err(format!("sink {id} has types but no creates text"));
        }
        if file.default == Effect::Safe && (file.types.is_empty() || file.library.is_some()) {
            return Err(format!(
                "sink {id} is safe by default, which needs receiver types and no library"
            ));
        }
        Ok(Self {
            calls: file
                .calls
                .iter()
                .map(|c| MethodSig::parse(c))
                .collect::<Result<_, _>>()?,
            settings: file
                .settings
                .into_iter()
                .map(Setting::compile)
                .collect::<Result<_, _>>()?,
            id: file.id,
            kind: file.kind,
            types: file.types,
            data,
            default: file.default,
            critical,
            creates: file.creates,
            read: file.read,
            subclass: file.subclass,
            outside: file.outside,
            library: file.library,
            title: file.title,
        })
    }
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
        let sinks = file
            .sinks
            .into_iter()
            .map(|sink| Sink::compile(sink, &sources))
            .collect::<Result<_, _>>()?;
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
    fn parses_method_signatures_targets_and_values() {
        let sig = MethodSig::parse(
            "java/io/ObjectInputFilter$Config.setObjectInputFilter(Ljava/io/ObjectInputStream;)V",
        )
        .unwrap();
        assert_eq!(sig.owner, "java/io/ObjectInputFilter$Config");
        assert_eq!(sig.name, "setObjectInputFilter");
        assert_eq!(
            sig.descriptor.as_deref(),
            Some("(Ljava/io/ObjectInputStream;)V")
        );
        assert!(MethodSig::parse("noDescriptor").is_err());

        let any = MethodSig::parse("a/B.load(*)").unwrap();
        assert!(any.matches_name("load", "(Ljava/lang/String;)Ljava/lang/Object;"));
        assert!(!any.matches_name("loadAs", "()V"));

        assert_eq!(Target::parse("receiver"), Ok(Target::Receiver));
        assert_eq!(Target::parse("argument 2"), Ok(Target::Argument(2)));
        assert!(Target::parse("argument x").is_err());
        assert!(Target::parse("elsewhere").is_err());
        assert_eq!(Target::Argument(0).depth(2), Some(1));
        assert_eq!(Target::Argument(2).depth(2), None);

        assert_eq!(Is::parse("int 0"), Ok(Is::Int(0)));
        assert_eq!(Is::parse("field a/B.C"), Ok(Is::Static("a/B.C".to_owned())));
        assert!(Is::parse("field nodot").is_err());
        assert!(Is::parse("string x").is_err());
    }

    #[test]
    fn rejects_bad_rule_files() {
        let header = "id='x'\nname='x'\ncwe='x'\nexplanation='x'\nfix='x'\n";
        let unknown_field = format!("{header}sinks=[]\nsurprise=1\n[sources]\n");
        assert!(
            compile_all(&[("bad.toml", &unknown_field)])
                .unwrap_err()
                .starts_with("bad.toml")
        );

        let call_without_data = format!(
            "{header}[sources]\n[[sinks]]\nid='s'\nkind='call'\ncalls=['a/B.c(*)']\n\
             critical-sources=[]\nread='r'\ntitle={{critical='c',warning='w',notice='n'}}\n"
        );
        let error = compile_all(&[("bad.toml", &call_without_data)]).unwrap_err();
        assert!(error.contains("needs data"), "{error}");
    }

    #[test]
    fn fills_templates() {
        assert_eq!(
            fill("Reads {owner}.{name}", &[("owner", "a/B"), ("name", "c")]),
            "Reads a/B.c"
        );
    }
}
