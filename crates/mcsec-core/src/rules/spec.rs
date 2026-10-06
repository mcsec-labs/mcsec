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
use sha2::{Digest, Sha256};

use crate::dataflow::Labels;
use crate::finding::DataOrigin;

/// How many sources a rule can declare. Each takes one label bit from the
/// lowest up, and the bits above them carry which side sent packet data.
pub(crate) const MAX_SOURCES: usize = 32;

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
    origin: SourceOrigin,
    #[serde(default)]
    types: Vec<String>,
    parameter: Option<String>,
    receiver: Option<String>,
    call: Option<String>,
    field: Option<String>,
    #[serde(default)]
    calls: Vec<String>,
    read: Option<String>,
    #[serde(default)]
    allocations: Vec<String>,
    opens: Option<String>,
    constant_prefix: Option<String>,
    copies: Option<String>,
    #[serde(default)]
    serializes: Vec<String>,
    writes: Option<String>,
}

/// The origins a rule's sources can declare. Caller and untraced data are
/// recognized by the engine rather than declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SourceOrigin {
    Network,
    LocalFile,
    EmbeddedTemplate,
    Serialized,
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
    creates: Option<String>,
    read: String,
    subclass: Option<String>,
    restriction: Option<Restriction>,
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

/// How to judge a subclass of a stream type by the method that decides
/// which classes it resolves. Each text takes `{type}`, the class judged.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Restriction {
    /// The deciding method, as `name(descriptor)`. Its first parameter
    /// carries the class being resolved.
    pub method: String,
    /// The override throws unless the class is one it looks up and finds.
    pub allowlist: String,
    /// The override checks every class against its allowed set, but throws
    /// for a missing one only on some paths, such as when a setting allows.
    pub conditional: String,
    /// The override throws only for classes it finds, so any class it does
    /// not know gets through.
    pub blocklist: String,
    /// The override never rejects a class based on which class it is.
    pub open: String,
    /// No class in the jar between the subclass and the stream type
    /// overrides the method.
    pub inherits: String,
    /// The subclass extends the stream type through a class outside the
    /// jar, whose code cannot be checked.
    pub unseen: String,
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

/// Where untrusted data enters, by any of four routes. A route is used when
/// its list is not empty, and each route has its own evidence text.
#[derive(Debug)]
pub struct Source {
    pub id: String,
    pub label: Labels,
    pub origin: DataOrigin,
    /// Values of these types or classes extending them, as parameters,
    /// receivers, fields, or results of calls on them.
    pub types: Vec<String>,
    pub parameter: String,
    pub receiver: String,
    pub call: String,
    pub field: String,
    /// Results of these calls.
    pub calls: Vec<MethodSig>,
    pub read: String,
    /// Objects of these classes, once created.
    pub allocations: Vec<String>,
    pub opens: String,
    /// Static byte arrays in the jar whose contents start with this prefix.
    pub constant_prefix: Vec<u8>,
    pub copies: String,
    /// Calls that write an object into the receiver's stream in a format
    /// that names its classes. What the stream holds afterward carries this
    /// source in place of what the object carried.
    pub serializes: Vec<MethodSig>,
    pub writes: String,
}

impl Source {
    fn compile(id: String, label: Labels, file: SourceFile) -> Result<Self, String> {
        let text =
            |present: bool, text: Option<String>, key: &str, route: &str| match (present, text) {
                (true, Some(text)) => Ok(text),
                (false, None) => Ok(String::new()),
                (true, None) => Err(format!("source {id} lists {route} but has no {key} text")),
                (false, Some(_)) => Err(format!("source {id} has a {key} text but no {route}")),
            };
        let typed = !file.types.is_empty();
        let constant_prefix = match &file.constant_prefix {
            Some(prefix) => hex::decode(prefix)
                .map_err(|e| format!("source {id} has a bad constant-prefix: {e}"))?,
            None => Vec::new(),
        };
        let source = Self {
            label,
            origin: match file.origin {
                SourceOrigin::Network => DataOrigin::Network,
                SourceOrigin::LocalFile => DataOrigin::LocalFile,
                SourceOrigin::EmbeddedTemplate => DataOrigin::EmbeddedTemplate,
                SourceOrigin::Serialized => DataOrigin::Serialized,
            },
            parameter: text(typed, file.parameter, "parameter", "types")?,
            receiver: text(typed, file.receiver, "receiver", "types")?,
            call: text(typed, file.call, "call", "types")?,
            field: text(typed, file.field, "field", "types")?,
            read: text(!file.calls.is_empty(), file.read, "read", "calls")?,
            opens: text(
                !file.allocations.is_empty(),
                file.opens,
                "opens",
                "allocations",
            )?,
            copies: text(
                file.constant_prefix.is_some(),
                file.copies,
                "copies",
                "constant-prefix",
            )?,
            writes: text(
                !file.serializes.is_empty(),
                file.writes,
                "writes",
                "serializes",
            )?,
            serializes: file
                .serializes
                .iter()
                .map(|c| MethodSig::parse(c))
                .collect::<Result<_, _>>()?,
            types: file.types,
            calls: file
                .calls
                .iter()
                .map(|c| MethodSig::parse(c))
                .collect::<Result<_, _>>()?,
            allocations: file.allocations,
            constant_prefix,
            id: id.clone(),
        };
        let routes = [
            !source.types.is_empty(),
            !source.calls.is_empty(),
            !source.allocations.is_empty(),
            !source.constant_prefix.is_empty(),
            !source.serializes.is_empty(),
        ];
        if !routes.contains(&true) {
            return Err(format!(
                "source {id} needs at least one of types, calls, allocations, constant-prefix, or serializes"
            ));
        }
        Ok(source)
    }
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
    pub creates: Option<String>,
    pub read: String,
    pub subclass: Option<String>,
    pub restriction: Option<Restriction>,
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
    fn compile(file: SinkFile) -> Result<Self, String> {
        let id = &file.id;
        if file.subclass.is_some() && file.restriction.is_some() {
            return Err(format!("sink {id} has both subclass and restriction"));
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
            creates: file.creates,
            read: file.read,
            subclass: file.subclass,
            restriction: file.restriction,
            outside: file.outside,
            library: file.library,
            title: file.title,
        })
    }
}

impl Rule {
    fn compile(file: RuleFile) -> Result<Self, String> {
        if file.sources.len() > MAX_SOURCES {
            return Err(format!(
                "a rule can declare at most {MAX_SOURCES} sources, one per label bit"
            ));
        }
        let sources: Vec<Source> = file
            .sources
            .into_iter()
            .enumerate()
            .map(|(bit, (id, source))| Source::compile(id, Labels(1 << bit), source))
            .collect::<Result<_, _>>()?;
        let sinks = file
            .sinks
            .into_iter()
            .map(Sink::compile)
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

/// Identifies the embedded rule set, as the start of a SHA-256 over every
/// rule file's name and contents in hex. Any edit to a rule changes it,
/// so benchmark results and reports can name the exact rules behind them.
pub fn rules_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let mut hasher = Sha256::new();
        for (name, text) in RULE_FILES {
            for part in [name.as_bytes(), text.as_bytes()] {
                hasher.update((part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
        }
        hex::encode(hasher.finalize())[..16].to_owned()
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
             read='r'\ntitle={{critical='c',warning='w',notice='n'}}\n"
        );
        let error = compile_all(&[("bad.toml", &call_without_data)]).unwrap_err();
        assert!(error.contains("needs data"), "{error}");
    }

    #[test]
    fn sources_need_matching_routes_and_texts() {
        let header = "id='x'\nname='x'\ncwe='x'\nexplanation='x'\nfix='x'\nsinks=[]\n";
        let compile =
            |source: &str| compile_all(&[("x.toml", &format!("{header}[sources.s]\n{source}"))]);

        let missing_text =
            compile("origin='network'\ntypes=['a/B']\nparameter='p'\nreceiver='r'\nfield='f'\n");
        assert!(missing_text.unwrap_err().contains("no call text"));
        let stray_text = compile("origin='local-file'\ncalls=['a/B.c(*)']\nread='r'\nopens='o'\n");
        assert!(stray_text.unwrap_err().contains("no allocations"));
        let no_route = compile("origin='network'\n");
        assert!(no_route.unwrap_err().contains("at least one"));
        assert!(compile("origin='embedded-template'\nconstant-prefix='zz'\ncopies='c'\n").is_err());

        let rules = compile("origin='embedded-template'\nconstant-prefix='aced0005'\ncopies='c'\n")
            .unwrap();
        let source = &rules[0].sources[0];
        assert_eq!(source.origin, DataOrigin::EmbeddedTemplate);
        assert_eq!(source.constant_prefix, [0xac, 0xed, 0x00, 0x05]);
    }

    #[test]
    fn fills_templates() {
        assert_eq!(
            fill("Reads {owner}.{name}", &[("owner", "a/B"), ("name", "c")]),
            "Reads a/B.c"
        );
    }
}
