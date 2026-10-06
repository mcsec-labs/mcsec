//! The unsafe deserialization rule against classes assembled byte by byte.
//! Each test writes the bytecode a compiler would produce for a small Java
//! method, so the data flow has to follow real stack and local behavior.

mod common;

use std::collections::HashMap;

use common::{ClassBuilder, jar};
use mcsec_core::class_file::op;
use mcsec_core::{DataOrigin, Finding, ScanLimits, Severity, scan_bytes};

const OIS: &str = "java/io/ObjectInputStream";
const BAIS: &str = "java/io/ByteArrayInputStream";
const BBIS: &str = "io/netty/buffer/ByteBufInputStream";
const BYTE_BUF: &str = "io/netty/buffer/ByteBuf";
const READ_OBJECT: &str = "()Ljava/lang/Object;";
const PUBLIC: u16 = 0x0001;
const PUBLIC_STATIC: u16 = 0x0009;

/// A tiny assembler that resolves branch labels to relative offsets.
#[derive(Default)]
struct Asm {
    code: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    fixups: Vec<(usize, &'static str)>,
}

impl Asm {
    fn op(&mut self, opcode: u8) -> &mut Self {
        self.code.push(opcode);
        self
    }

    fn index(&mut self, opcode: u8, index: u16) -> &mut Self {
        self.code.push(opcode);
        self.code.extend(index.to_be_bytes());
        self
    }

    fn local(&mut self, opcode: u8, slot: u8) -> &mut Self {
        self.code.extend([opcode, slot]);
        self
    }

    fn invoke_interface(&mut self, index: u16) -> &mut Self {
        self.index(op::INVOKEINTERFACE, index);
        self.code.extend([1, 0]);
        self
    }

    fn branch(&mut self, opcode: u8, label: &'static str) -> &mut Self {
        self.fixups.push((self.code.len(), label));
        self.code.extend([opcode, 0, 0]);
        self
    }

    fn label(&mut self, name: &'static str) -> &mut Self {
        self.labels.insert(name, self.code.len());
        self
    }

    fn at(&self, name: &str) -> u32 {
        self.labels[name] as u32
    }

    fn finish(&mut self) -> Vec<u8> {
        for &(at, label) in &self.fixups {
            let delta = (self.labels[label] as i64 - at as i64) as i16;
            self.code[at + 1..at + 3].copy_from_slice(&delta.to_be_bytes());
        }
        self.code.clone()
    }
}

/// Constant pool indexes the tests use, registered once per class.
struct Pool {
    ois: u16,
    ois_init: u16,
    read_object: u16,
    bais: u16,
    bais_init: u16,
    bbis: u16,
    bbis_init: u16,
    readable_bytes: u16,
    read_bytes: u16,
}

impl Pool {
    fn new(b: &mut ClassBuilder) -> Self {
        Self {
            ois: b.class(OIS),
            ois_init: b.method_ref(OIS, "<init>", "(Ljava/io/InputStream;)V"),
            read_object: b.method_ref(OIS, "readObject", READ_OBJECT),
            bais: b.class(BAIS),
            bais_init: b.method_ref(BAIS, "<init>", "([B)V"),
            bbis: b.class(BBIS),
            bbis_init: b.method_ref(BBIS, "<init>", "(Lio/netty/buffer/ByteBuf;)V"),
            readable_bytes: b.method_ref(BYTE_BUF, "readableBytes", "()I"),
            read_bytes: b.method_ref(BYTE_BUF, "readBytes", "([B)Lio/netty/buffer/ByteBuf;"),
        }
    }

    /// `new ObjectInputStream(<stream in local slot>).readObject()`
    fn read_from_local(&self, asm: &mut Asm, slot: u8) {
        asm.index(op::NEW, self.ois)
            .op(op::DUP)
            .local(op::ALOAD, slot)
            .index(op::INVOKESPECIAL, self.ois_init)
            .label("read")
            .index(op::INVOKEVIRTUAL, self.read_object)
            .op(op::POP);
    }

    /// `new ByteBufInputStream(<ByteBuf in local slot>)`, stored in `into`.
    fn wrap_buffer(&self, asm: &mut Asm, buffer: u8, into: u8) {
        asm.index(op::NEW, self.bbis)
            .op(op::DUP)
            .local(op::ALOAD, buffer)
            .index(op::INVOKESPECIAL, self.bbis_init)
            .local(op::ASTORE, into);
    }
}

fn class(b: ClassBuilder, name: &str) -> Vec<u8> {
    b.build(name)
}

fn method(b: &mut ClassBuilder, access: u16, name: &str, descriptor: &str, code: &[u8]) {
    let attribute = b.code_attribute(code);
    b.method_with_access(access, name, descriptor, &[attribute]);
}

fn scan(entries: &[(&str, &[u8])]) -> Vec<Finding> {
    scan_bytes(&jar(entries), &ScanLimits::default())
        .unwrap()
        .findings
}

fn only(findings: &[Finding]) -> &Finding {
    assert_eq!(findings.len(), 1, "expected one finding, got {findings:#?}");
    &findings[0]
}

fn scan_one(b: ClassBuilder) -> Vec<Finding> {
    let bytes = class(b, "net/example/Packet");
    scan(&[("net/example/Packet.class", &bytes)])
}

#[test]
fn network_parameter_reaching_the_stream_is_critical() {
    // static void fromBytes(ByteBuf buf) {
    //     new ObjectInputStream(new ByteBufInputStream(buf)).readObject(); }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    pool.wrap_buffer(&mut asm, 0, 1);
    pool.read_from_local(&mut asm, 1);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );

    let findings = scan_one(b);
    let finding = only(&findings);
    assert_eq!(finding.rule_id, "unsafe-deserialization");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.location.method.as_ref().unwrap().name, "fromBytes");
    assert_eq!(finding.location.bytecode_offset, Some(asm.at("read")));
    assert_eq!(
        finding.evidence[0].description,
        "Receives network data as a parameter of type io/netty/buffer/ByteBuf"
    );
}

#[test]
fn network_parameter_not_reaching_the_stream_is_judged_by_the_other() {
    // static void fromBytes(ByteBuf buf, InputStream file) {
    //     new ObjectInputStream(file).readObject(); }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    pool.read_from_local(&mut asm, 1);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;Ljava/io/InputStream;)V",
        &code,
    );

    // The stream comes from the second parameter, so the network buffer
    // in the first does not make it Critical.
    let findings = scan_one(b);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Notice);
    assert_eq!(finding.origin, Some(DataOrigin::Caller));
}

#[test]
fn data_copied_into_an_array_is_critical() {
    // static void fromBytes(ByteBuf buf) {
    //     byte[] bytes = new byte[buf.readableBytes()];
    //     buf.readBytes(bytes);
    //     new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject(); }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.local(op::ALOAD, 0)
        .index(op::INVOKEVIRTUAL, pool.readable_bytes)
        .local(op::NEWARRAY, 8)
        .local(op::ASTORE, 1)
        .local(op::ALOAD, 0)
        .local(op::ALOAD, 1)
        .index(op::INVOKEVIRTUAL, pool.read_bytes)
        .op(op::POP)
        .index(op::NEW, pool.bais)
        .op(op::DUP)
        .local(op::ALOAD, 1)
        .index(op::INVOKESPECIAL, pool.bais_init)
        .local(op::ASTORE, 2);
    pool.read_from_local(&mut asm, 2);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );

    assert_eq!(only(&scan_one(b)).severity, Severity::Critical);
}

#[test]
fn reading_into_a_discarded_array_is_not_reported() {
    // The Advent of Ascension shape. Packet data goes into a temporary array
    // that is thrown away, and a different array nothing ever writes is
    // deserialized, which reads only zeros and creates no class.
    //     byte[] bytes = new byte[16];
    //     buf.readBytes(new byte[buf.readableBytes()]);
    //     new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.local(op::BIPUSH, 16)
        .local(op::NEWARRAY, 8)
        .local(op::ASTORE, 1)
        .local(op::ALOAD, 0)
        .local(op::ALOAD, 0)
        .index(op::INVOKEVIRTUAL, pool.readable_bytes)
        .local(op::NEWARRAY, 8)
        .index(op::INVOKEVIRTUAL, pool.read_bytes)
        .op(op::POP)
        .index(op::NEW, pool.bais)
        .op(op::DUP)
        .local(op::ALOAD, 1)
        .index(op::INVOKESPECIAL, pool.bais_init)
        .local(op::ASTORE, 2);
    pool.read_from_local(&mut asm, 2);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );

    let findings = scan_one(b);
    assert!(
        findings.is_empty(),
        "expected no finding, got {findings:#?}"
    );
}

#[test]
fn network_data_on_one_branch_is_critical() {
    // static void read(ByteBuf buf, InputStream file, boolean fromNetwork) {
    //     InputStream in = fromNetwork ? new ByteBufInputStream(buf) : file;
    //     new ObjectInputStream(in).readObject(); }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.local(op::ILOAD, 2).branch(op::IFEQ, "file");
    pool.wrap_buffer(&mut asm, 0, 3);
    asm.branch(op::GOTO, "join")
        .label("file")
        .local(op::ALOAD, 1)
        .local(op::ASTORE, 3)
        .label("join");
    pool.read_from_local(&mut asm, 3);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "read",
        "(Lio/netty/buffer/ByteBuf;Ljava/io/InputStream;Z)V",
        &code,
    );

    assert_eq!(only(&scan_one(b)).severity, Severity::Critical);
}

#[test]
fn network_data_arriving_on_a_later_loop_pass_is_critical() {
    // The stream is clean on the first pass and network data on the next,
    // so the analysis has to revisit the loop body after the back edge.
    // static void read(ByteBuf buf, InputStream file, boolean more) {
    //     InputStream in = file;
    //     while (more) {
    //         new ObjectInputStream(in).readObject();
    //         in = new ByteBufInputStream(buf); } }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.local(op::ALOAD, 1)
        .local(op::ASTORE, 3)
        .label("head")
        .local(op::ILOAD, 2)
        .branch(op::IFEQ, "end");
    pool.read_from_local(&mut asm, 3);
    pool.wrap_buffer(&mut asm, 0, 3);
    asm.branch(op::GOTO, "head").label("end").op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "read",
        "(Lio/netty/buffer/ByteBuf;Ljava/io/InputStream;Z)V",
        &code,
    );

    assert_eq!(only(&scan_one(b)).severity, Severity::Critical);
}

#[test]
fn network_data_reaching_an_exception_handler_is_critical() {
    // static void read(ByteBuf buf) {
    //     InputStream in = new ByteBufInputStream(buf);
    //     try { buf.readableBytes(); }
    //     catch (Throwable t) { new ObjectInputStream(in).readObject(); } }
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    pool.wrap_buffer(&mut asm, 0, 1);
    asm.label("try")
        .local(op::ALOAD, 0)
        .index(op::INVOKEVIRTUAL, pool.readable_bytes)
        .op(op::POP)
        .label("try_end")
        .op(op::RETURN)
        .label("handler")
        .local(op::ASTORE, 2);
    pool.read_from_local(&mut asm, 1);
    asm.op(op::RETURN);
    let code = asm.finish();
    let handlers = [(
        asm.at("try") as u16,
        asm.at("try_end") as u16,
        asm.at("handler") as u16,
        0,
    )];
    let attribute = b.code_attribute_with_handlers(&code, &handlers);
    b.method_with_access(
        PUBLIC_STATIC,
        "read",
        "(Lio/netty/buffer/ByteBuf;)V",
        &[attribute],
    );

    assert_eq!(only(&scan_one(b)).severity, Severity::Critical);
}

#[test]
fn stream_from_the_caller_is_notice() {
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    pool.read_from_local(&mut asm, 0);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "load",
        "(Ljava/io/InputStream;)V",
        &code,
    );

    let findings = scan_one(b);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Notice);
    assert_eq!(finding.origin, Some(DataOrigin::Caller));
}

#[test]
fn reading_through_the_object_input_interface_is_detected() {
    // ObjectInput in = new ObjectInputStream(new ByteBufInputStream(buf)); in.readObject();
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let read = b.interface_method_ref("java/io/ObjectInput", "readObject", READ_OBJECT);
    let mut asm = Asm::default();
    pool.wrap_buffer(&mut asm, 0, 1);
    asm.index(op::NEW, pool.ois)
        .op(op::DUP)
        .local(op::ALOAD, 1)
        .index(op::INVOKESPECIAL, pool.ois_init)
        .local(op::ASTORE, 2)
        .local(op::ALOAD, 2)
        .invoke_interface(read)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "readData",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );

    assert_eq!(only(&scan_one(b)).severity, Severity::Critical);
}

#[test]
fn packet_buffer_subclass_is_critical() {
    // A Fabric mod's own packet buffer reading its own bytes:
    //     byte[] bytes = this.method_10795();
    //     new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let read_array = b.method_ref("net/example/ExtendedBuffer", "method_10795", "()[B");
    let mut asm = Asm::default();
    asm.local(op::ALOAD, 0)
        .index(op::INVOKEVIRTUAL, read_array)
        .local(op::ASTORE, 1)
        .index(op::NEW, pool.bais)
        .op(op::DUP)
        .local(op::ALOAD, 1)
        .index(op::INVOKESPECIAL, pool.bais_init)
        .local(op::ASTORE, 2);
    pool.read_from_local(&mut asm, 2);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(&mut b, PUBLIC, "readBigInt", "()V", &code);
    let bytes = b.build_extending("net/example/ExtendedBuffer", "net/minecraft/class_2540");

    let findings = scan(&[("net/example/ExtendedBuffer.class", &bytes)]);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(
        finding.evidence[0].description,
        "Runs on network data, as net/example/ExtendedBuffer is a network type"
    );
}

#[test]
fn serialization_hooks_are_not_flagged() {
    // A custom readObject(ObjectInputStream) receives a stream and never creates one.
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let default_read = b.method_ref(OIS, "defaultReadObject", "()V");
    let mut asm = Asm::default();
    asm.local(op::ALOAD, 1)
        .index(op::INVOKEVIRTUAL, default_read)
        .local(op::ALOAD, 1)
        .index(op::INVOKEVIRTUAL, pool.read_object)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC,
        "readObject",
        "(Ljava/io/ObjectInputStream;)V",
        &code,
    );

    assert!(scan_one(b).is_empty());
}

#[test]
fn creating_a_stream_without_reading_is_not_flagged() {
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.index(op::NEW, pool.ois)
        .op(op::DUP)
        .local(op::ALOAD, 0)
        .index(op::INVOKESPECIAL, pool.ois_init)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "open",
        "(Ljava/io/InputStream;)V",
        &code,
    );

    assert!(scan_one(b).is_empty());
}

#[test]
fn subclass_without_a_resolve_class_override_is_judged_as_plain() {
    // A subclass that overrides nothing restricts nothing, however it is
    // named. Allowlisting overrides are covered by the variant corpus.
    let safe_stream = ClassBuilder::new().build_extending("net/example/SafeStream", OIS);
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let safe = b.class("net/example/SafeStream");
    let safe_init = b.method_ref(
        "net/example/SafeStream",
        "<init>",
        "(Ljava/io/InputStream;)V",
    );
    let safe_read = b.method_ref("net/example/SafeStream", "readObject", READ_OBJECT);
    let mut asm = Asm::default();
    pool.wrap_buffer(&mut asm, 0, 1);
    asm.index(op::NEW, safe)
        .op(op::DUP)
        .local(op::ALOAD, 1)
        .index(op::INVOKESPECIAL, safe_init)
        .index(op::INVOKEVIRTUAL, safe_read)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );
    let packet = class(b, "net/example/Packet");

    let findings = scan(&[
        ("net/example/SafeStream.class", &safe_stream),
        ("net/example/Packet.class", &packet),
    ]);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Critical);
    assert!(has_evidence(finding, "without overriding resolveClass"));
}

/// `ObjectInputStream` over network data in slot 2 and one over a parameter
/// in slot 3, with a filter set on the stream in `filtered_slot` and a read
/// from the stream in `read_slot`.
fn two_streams(filtered_slot: u8, read_slot: u8) -> Vec<Finding> {
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let set_filter = b.method_ref(
        OIS,
        "setObjectInputFilter",
        "(Ljava/io/ObjectInputFilter;)V",
    );
    let mut asm = Asm::default();
    pool.wrap_buffer(&mut asm, 0, 4);
    for (slot, source) in [(2, 4), (3, 1)] {
        asm.index(op::NEW, pool.ois)
            .op(op::DUP)
            .local(op::ALOAD, source)
            .index(op::INVOKESPECIAL, pool.ois_init)
            .local(op::ASTORE, slot);
    }
    asm.local(op::ALOAD, filtered_slot)
        .op(op::ACONST_NULL)
        .index(op::INVOKEVIRTUAL, set_filter)
        .local(op::ALOAD, read_slot)
        .index(op::INVOKEVIRTUAL, pool.read_object)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "fromBytes",
        "(Lio/netty/buffer/ByteBuf;Ljava/io/InputStream;)V",
        &code,
    );
    scan_one(b)
}

#[test]
fn object_input_filter_is_notice() {
    assert_eq!(only(&two_streams(2, 2)).severity, Severity::Notice);
}

#[test]
fn filter_on_a_different_stream_does_not_count() {
    assert_eq!(only(&two_streams(3, 2)).severity, Severity::Critical);
}

#[test]
fn findings_in_nested_jars_carry_their_path() {
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    pool.read_from_local(&mut asm, 0);
    asm.op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "load",
        "(Ljava/io/InputStream;)V",
        &code,
    );
    let packet = class(b, "lib/Packet");
    let inner = jar(&[("lib/Packet.class", &packet)]);

    let findings = scan(&[("META-INF/jars/lib.jar", &inner)]);
    let finding = only(&findings);
    assert_eq!(
        finding.location.archive_path,
        vec!["META-INF/jars/lib.jar".to_owned()]
    );
    assert_eq!(finding.location.entry.as_deref(), Some("lib/Packet.class"));
}

#[test]
fn superclass_cycles_do_not_hang() {
    let a = ClassBuilder::new().build_extending("net/example/A", "net/example/B");
    let cycle = ClassBuilder::new().build_extending("net/example/B", "net/example/A");
    let mut b = ClassBuilder::new();
    let a_class = b.class("net/example/A");
    let a_read = b.method_ref("net/example/A", "readObject", READ_OBJECT);
    let mut asm = Asm::default();
    asm.index(op::NEW, a_class)
        .index(op::INVOKEVIRTUAL, a_read)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(&mut b, PUBLIC_STATIC, "load", "()V", &code);
    let user = class(b, "net/example/User");

    let findings = scan(&[
        ("net/example/A.class", &a),
        ("net/example/B.class", &cycle),
        ("net/example/User.class", &user),
    ]);
    assert!(findings.is_empty());
}

#[test]
fn malformed_stacks_do_not_panic() {
    // Pops from an empty stack, a read with no stream, and a loop back to
    // the start. The JVM would reject this, and the scan must survive it.
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let mut asm = Asm::default();
    asm.label("top")
        .op(op::POP2)
        .op(op::DUP2_X2)
        .index(op::INVOKEVIRTUAL, pool.read_object)
        .op(op::SWAP)
        .branch(op::GOTO, "top");
    let code = asm.finish();
    method(&mut b, PUBLIC_STATIC, "broken", "()V", &code);

    assert!(scan_one(b).is_empty());
}

/// `static void load(ByteBuf buf) { new Yaml().load(new ByteBufInputStream(buf)); }`
fn yaml_loader() -> Vec<u8> {
    const YAML: &str = "org/yaml/snakeyaml/Yaml";
    let mut b = ClassBuilder::new();
    let pool = Pool::new(&mut b);
    let yaml = b.class(YAML);
    let yaml_init = b.method_ref(YAML, "<init>", "()V");
    let load = b.method_ref(YAML, "load", "(Ljava/io/InputStream;)Ljava/lang/Object;");
    let mut asm = Asm::default();
    asm.index(op::NEW, yaml)
        .op(op::DUP)
        .index(op::INVOKESPECIAL, yaml_init)
        .index(op::NEW, pool.bbis)
        .op(op::DUP)
        .local(op::ALOAD, 0)
        .index(op::INVOKESPECIAL, pool.bbis_init)
        .index(op::INVOKEVIRTUAL, load)
        .op(op::POP)
        .op(op::RETURN);
    let code = asm.finish();
    method(
        &mut b,
        PUBLIC_STATIC,
        "load",
        "(Lio/netty/buffer/ByteBuf;)V",
        &code,
    );
    class(b, "net/example/Packet")
}

fn has_evidence(finding: &Finding, text: &str) -> bool {
    finding
        .evidence
        .iter()
        .any(|step| step.description.contains(text))
}

#[test]
fn bundled_library_version_decides_unsafe_defaults() {
    let loader = yaml_loader();
    let entry = "net/example/Packet.class";
    let pom_path = "META-INF/maven/org.yaml/snakeyaml/pom.properties";
    let pom = |version: &str| {
        format!("groupId=org.yaml\nartifactId=snakeyaml\nversion={version}\n").into_bytes()
    };

    let unknown = scan(&[(entry, &loader)]);
    assert_eq!(only(&unknown).severity, Severity::Critical);
    assert!(has_evidence(&unknown[0], "no bundled copy"));

    let old = scan(&[(entry, &loader), (pom_path, &pom("1.33"))]);
    assert_eq!(only(&old).severity, Severity::Critical);
    assert!(has_evidence(&old[0], "Bundles SnakeYAML 1.33"));

    let new = scan(&[(entry, &loader), (pom_path, &pom("2.2"))]);
    assert_eq!(only(&new).severity, Severity::Notice);
    assert!(has_evidence(&new[0], "Bundles SnakeYAML 2.2"));

    // Jar-in-Jar loaders store the library as a nested jar named by version.
    let library = jar(&[("readme.txt", b"snakeyaml")]);
    let nested = scan(&[
        (entry, &loader),
        ("META-INF/jars/snakeyaml-2.2.jar", &library),
    ]);
    assert_eq!(only(&nested).severity, Severity::Notice);
}
