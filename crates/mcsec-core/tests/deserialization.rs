//! The unsafe deserialization rule against classes assembled byte by byte.

mod common;

use common::{ClassBuilder, jar};
use mcsec_core::class_file::op;
use mcsec_core::{Finding, ScanLimits, Severity, scan_bytes};

const OIS: &str = "java/io/ObjectInputStream";
const READ_OBJECT: &str = "()Ljava/lang/Object;";

/// One method's bytecode, built from constant pool indexes as it goes.
struct Method {
    name: &'static str,
    descriptor: &'static str,
    code: Vec<u8>,
}

impl Method {
    fn new(name: &'static str, descriptor: &'static str) -> Self {
        Self {
            name,
            descriptor,
            code: Vec::new(),
        }
    }

    fn op(mut self, opcode: u8) -> Self {
        self.code.push(opcode);
        self
    }

    fn op_index(mut self, opcode: u8, index: u16) -> Self {
        self.code.push(opcode);
        self.code.extend(index.to_be_bytes());
        self
    }

    fn invoke_interface(mut self, index: u16) -> Self {
        self.code.push(op::INVOKEINTERFACE);
        self.code.extend(index.to_be_bytes());
        self.code.extend([1, 0]);
        self
    }
}

/// `new <stream>(aload_1)` followed by `readObject`, the BleedingPipe shape.
fn deserialize(
    b: &mut ClassBuilder,
    stream: &str,
    descriptor: &'static str,
    name: &'static str,
) -> Method {
    let class = b.class(stream);
    let init = b.method_ref(stream, "<init>", "(Ljava/io/InputStream;)V");
    let read = b.method_ref(stream, "readObject", READ_OBJECT);
    Method::new(name, descriptor)
        .op_index(op::NEW, class)
        .op(op::DUP)
        .op(op::ALOAD_1)
        .op_index(op::INVOKESPECIAL, init)
        .op_index(op::INVOKEVIRTUAL, read)
        .op(op::POP)
        .op(op::RETURN)
}

fn class_with(mut b: ClassBuilder, methods: Vec<Method>, name: &str, super_name: &str) -> Vec<u8> {
    for method in methods {
        b.method_with_descriptor(method.name, method.descriptor, &method.code);
    }
    b.build_extending(name, super_name)
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

#[test]
fn network_parameter_is_critical() {
    let mut b = ClassBuilder::new();
    let method = deserialize(&mut b, OIS, "(Lio/netty/buffer/ByteBuf;)V", "fromBytes");
    let class = class_with(
        b,
        vec![method],
        "net/example/PacketConfig",
        "java/lang/Object",
    );

    let findings = scan(&[("net/example/PacketConfig.class", &class)]);
    let finding = only(&findings);
    assert_eq!(finding.rule_id, "unsafe-deserialization");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(
        finding.location.class_name.as_deref(),
        Some("net/example/PacketConfig")
    );
    assert_eq!(finding.location.method.as_ref().unwrap().name, "fromBytes");
    assert_eq!(finding.location.bytecode_offset, Some(8));
    assert_eq!(
        finding.evidence[0].description,
        "Receives network data as a parameter of type io/netty/buffer/ByteBuf"
    );
}

#[test]
fn unknown_source_is_warning() {
    let mut b = ClassBuilder::new();
    let method = deserialize(&mut b, OIS, "(Ljava/io/InputStream;)V", "load");
    let class = class_with(b, vec![method], "net/example/Saves", "java/lang/Object");

    let findings = scan(&[("net/example/Saves.class", &class)]);
    assert_eq!(only(&findings).severity, Severity::Warning);
}

#[test]
fn reading_through_the_object_input_interface_is_detected() {
    let mut b = ClassBuilder::new();
    let class_index = b.class(OIS);
    let init = b.method_ref(OIS, "<init>", "(Ljava/io/InputStream;)V");
    let read = b.interface_method_ref("java/io/ObjectInput", "readObject", READ_OBJECT);
    let method = Method::new("readData", "(Ljava/io/InputStream;)V")
        .op_index(op::NEW, class_index)
        .op(op::DUP)
        .op(op::ALOAD_1)
        .op_index(op::INVOKESPECIAL, init)
        .invoke_interface(read)
        .op(op::RETURN);
    let class = class_with(b, vec![method], "net/example/Packet", "java/lang/Object");

    let findings = scan(&[("net/example/Packet.class", &class)]);
    assert_eq!(only(&findings).severity, Severity::Warning);
}

#[test]
fn network_call_in_the_method_is_critical() {
    let mut b = ClassBuilder::new();
    let read_bytes = b.method_ref(
        "io/netty/buffer/ByteBuf",
        "readBytes",
        "([B)Lio/netty/buffer/ByteBuf;",
    );
    let mut method = deserialize(&mut b, OIS, "()V", "decode");
    let mut code = vec![op::INVOKEVIRTUAL];
    code.extend(read_bytes.to_be_bytes());
    code.extend(method.code);
    method.code = code;
    let class = class_with(b, vec![method], "net/example/Codec", "java/lang/Object");

    let findings = scan(&[("net/example/Codec.class", &class)]);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(
        finding.evidence[0].description,
        "Reads network data through io/netty/buffer/ByteBuf"
    );
}

#[test]
fn packet_buffer_subclass_is_critical() {
    // A Fabric mod's own packet buffer, read through its own method.
    let mut b = ClassBuilder::new();
    let read_bytes = b.method_ref("net/example/ExtendedBuffer", "method_10795", "()[B");
    let mut method = deserialize(&mut b, OIS, "()V", "readBigInt");
    let mut code = vec![op::INVOKEVIRTUAL];
    code.extend(read_bytes.to_be_bytes());
    code.extend(method.code);
    method.code = code;
    let class = class_with(
        b,
        vec![method],
        "net/example/ExtendedBuffer",
        "net/minecraft/class_2540",
    );

    let findings = scan(&[("net/example/ExtendedBuffer.class", &class)]);
    assert_eq!(only(&findings).severity, Severity::Critical);
}

#[test]
fn serialization_hooks_are_not_flagged() {
    // A custom readObject(ObjectInputStream) receives a stream and never creates one.
    let mut b = ClassBuilder::new();
    let default_read = b.method_ref(OIS, "defaultReadObject", "()V");
    let read = b.method_ref(OIS, "readObject", READ_OBJECT);
    let method = Method::new("readObject", "(Ljava/io/ObjectInputStream;)V")
        .op(op::ALOAD_1)
        .op_index(op::INVOKEVIRTUAL, default_read)
        .op(op::ALOAD_1)
        .op_index(op::INVOKEVIRTUAL, read)
        .op(op::RETURN);
    let class = class_with(b, vec![method], "net/example/Cache", "java/lang/Object");

    assert!(scan(&[("net/example/Cache.class", &class)]).is_empty());
}

#[test]
fn creating_a_stream_without_reading_is_not_flagged() {
    let mut b = ClassBuilder::new();
    let class_index = b.class(OIS);
    let method = Method::new("open", "()V")
        .op_index(op::NEW, class_index)
        .op(op::RETURN);
    let class = class_with(b, vec![method], "net/example/Open", "java/lang/Object");

    assert!(scan(&[("net/example/Open.class", &class)]).is_empty());
}

#[test]
fn allowlisting_subclass_is_notice() {
    let safe_stream = ClassBuilder::new().build_extending("net/example/SafeStream", OIS);
    let mut b = ClassBuilder::new();
    let method = deserialize(
        &mut b,
        "net/example/SafeStream",
        "(Lio/netty/buffer/ByteBuf;)V",
        "fromBytes",
    );
    let class = class_with(b, vec![method], "net/example/Packet", "java/lang/Object");

    let findings = scan(&[
        ("net/example/SafeStream.class", &safe_stream),
        ("net/example/Packet.class", &class),
    ]);
    let finding = only(&findings);
    assert_eq!(finding.severity, Severity::Notice);
    assert!(
        finding
            .evidence
            .iter()
            .any(|e| e.description.contains("may restrict the classes"))
    );
}

#[test]
fn object_input_filter_is_notice() {
    let mut b = ClassBuilder::new();
    let filter = b.method_ref(
        OIS,
        "setObjectInputFilter",
        "(Ljava/io/ObjectInputFilter;)V",
    );
    let mut method = deserialize(&mut b, OIS, "(Lio/netty/buffer/ByteBuf;)V", "fromBytes");
    // Insert the filter call before readObject at offset 8.
    let mut code = method.code[..8].to_vec();
    code.push(op::INVOKEVIRTUAL);
    code.extend(filter.to_be_bytes());
    code.extend(&method.code[8..]);
    method.code = code;
    let class = class_with(b, vec![method], "net/example/Packet", "java/lang/Object");

    let findings = scan(&[("net/example/Packet.class", &class)]);
    assert_eq!(only(&findings).severity, Severity::Notice);
}

#[test]
fn findings_in_nested_jars_carry_their_path() {
    let mut b = ClassBuilder::new();
    let method = deserialize(&mut b, OIS, "(Lio/netty/buffer/ByteBuf;)V", "fromBytes");
    let class = class_with(b, vec![method], "lib/Packet", "java/lang/Object");
    let inner = jar(&[("lib/Packet.class", &class)]);

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
    let b_class = ClassBuilder::new().build_extending("net/example/B", "net/example/A");
    let mut b = ClassBuilder::new();
    let method = deserialize(&mut b, "net/example/A", "()V", "load");
    let class = class_with(b, vec![method], "net/example/User", "java/lang/Object");

    let findings = scan(&[
        ("net/example/A.class", &a),
        ("net/example/B.class", &b_class),
        ("net/example/User.class", &class),
    ]);
    assert!(findings.is_empty());
}
