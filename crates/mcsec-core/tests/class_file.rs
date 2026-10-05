//! Class file parsing against classes assembled byte by byte.

use std::borrow::Cow;
use std::io::{Cursor, Write};

use mcsec_core::class_file::{
    ClassFile, ClassParseError, Constant, MemberKind, Operand, decode_modified_utf8, op,
};
use mcsec_core::{ScanLimits, scan_bytes};

mod common;
use common::ClassBuilder;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// A class whose one method loads a string and calls `readObject`.
fn sample_class() -> (Vec<u8>, u16, u16) {
    let mut builder = ClassBuilder::new();
    let url = builder.string("http://example.invalid/");
    let read_object = builder.method_ref(
        "java/io/ObjectInputStream",
        "readObject",
        "()Ljava/lang/Object;",
    );
    let constant = builder.attribute("ConstantValue", &url.to_be_bytes());
    builder.field("URL", "Ljava/lang/String;", &[constant]);

    let mut bytecode = vec![op::LDC, url as u8, op::POP, op::ALOAD_0, op::INVOKEVIRTUAL];
    bytecode.extend(read_object.to_be_bytes());
    bytecode.push(op::ARETURN);
    builder.method_with_code("load", &bytecode);
    (builder.build("net/example/Sample"), url, read_object)
}

fn decode(bytecode: &[u8]) -> Vec<Result<mcsec_core::class_file::Instruction, ClassParseError>> {
    let mut builder = ClassBuilder::new();
    builder.method_with_code("run", bytecode);
    let bytes = builder.build("Test");
    let class = ClassFile::parse(&bytes).unwrap();
    let code = class.methods[0]
        .code(&class.constant_pool)
        .unwrap()
        .unwrap();
    code.instructions().collect()
}

#[test]
fn parses_names_members_and_code() {
    let (bytes, url, read_object) = sample_class();
    let class = ClassFile::parse(&bytes).unwrap();
    let pool = &class.constant_pool;

    assert_eq!(class.major_version, 65);
    assert_eq!(class.name().unwrap(), "net/example/Sample");
    assert_eq!(class.super_name().unwrap().unwrap(), "java/lang/Object");
    assert_eq!(
        class.interface_names().unwrap(),
        vec!["java/io/Serializable"]
    );

    let field = &class.fields[0];
    assert_eq!(field.name(pool).unwrap(), "URL");
    assert_eq!(field.constant_value(pool).unwrap(), Some(url));
    assert_eq!(pool.string(url).unwrap(), "http://example.invalid/");

    let method = &class.methods[0];
    assert_eq!(method.name(pool).unwrap(), "load");
    let code = method.code(pool).unwrap().unwrap();
    let instructions: Vec<_> = code.instructions().map(Result::unwrap).collect();
    let summary: Vec<_> = instructions
        .iter()
        .map(|i| (i.offset, i.mnemonic(), i.operand.clone()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (0, "ldc", Operand::Constant(url)),
            (2, "pop", Operand::None),
            (3, "aload_0", Operand::None),
            (4, "invokevirtual", Operand::Constant(read_object)),
            (7, "areturn", Operand::None),
        ]
    );

    let target = pool.member_ref(read_object).unwrap();
    assert_eq!(target.kind, MemberKind::Method);
    assert_eq!(target.class_name, "java/io/ObjectInputStream");
    assert_eq!(target.name, "readObject");
    assert_eq!(target.descriptor, "()Ljava/lang/Object;");
    class.check_code().unwrap();
}

#[test]
fn eight_byte_constants_take_two_slots() {
    let mut builder = ClassBuilder::new();
    let long = builder.long(0x0123_4567_89AB_CDEF);
    let after = builder.utf8("after");
    let bytes = builder.build("Test");
    let class = ClassFile::parse(&bytes).unwrap();

    assert_eq!(after, long + 2);
    assert_eq!(
        class.constant_pool.get(long),
        Some(&Constant::Long(0x0123_4567_89AB_CDEF))
    );
    assert_eq!(class.constant_pool.get(long + 1), Some(&Constant::Unusable));
    assert_eq!(class.constant_pool.utf8(after).unwrap(), "after");
}

#[test]
fn rejects_lookups_of_the_wrong_kind() {
    let (bytes, url, _) = sample_class();
    let class = ClassFile::parse(&bytes).unwrap();

    assert_eq!(
        class.constant_pool.class_name(url),
        Err(ClassParseError::BadConstantRef {
            index: url,
            expected: "Class"
        })
    );
    assert!(class.constant_pool.utf8(u16::MAX).is_err());
}

#[test]
fn decodes_modified_utf8() {
    assert!(matches!(
        decode_modified_utf8(b"plain"),
        Cow::Borrowed("plain")
    ));
    assert_eq!(decode_modified_utf8(b"a\xC0\x80b"), "a\0b");
    // U+1F600 as two separately encoded surrogate halves.
    assert_eq!(
        decode_modified_utf8(b"\xED\xA0\xBD\xED\xB8\x80"),
        "\u{1F600}"
    );
    assert_eq!(decode_modified_utf8(b"\xED\xA0\xBDx"), "\u{FFFD}x");
    assert_eq!(decode_modified_utf8(b"\xC0\x80\xFF"), "\0\u{FFFD}");
}

#[test]
fn switch_padding_depends_on_offset() {
    for leading_nops in 0..4u32 {
        let mut bytecode = vec![op::NOP; leading_nops as usize];
        let start = leading_nops;
        bytecode.push(op::TABLESWITCH);
        let padding = (4 - (start + 1) % 4) % 4;
        bytecode.extend(vec![0; padding as usize]);
        bytecode.extend(20i32.to_be_bytes());
        bytecode.extend(1i32.to_be_bytes());
        bytecode.extend(2i32.to_be_bytes());
        bytecode.extend(24i32.to_be_bytes());
        bytecode.extend(28i32.to_be_bytes());
        let after_table = bytecode.len() as u32;
        bytecode.push(op::LOOKUPSWITCH);
        let padding = (4 - (after_table + 1) % 4) % 4;
        bytecode.extend(vec![0; padding as usize]);
        bytecode.extend(8i32.to_be_bytes());
        bytecode.extend(1i32.to_be_bytes());
        bytecode.extend((-5i32).to_be_bytes());
        bytecode.extend(12i32.to_be_bytes());
        let after_lookup = bytecode.len() as u32;
        bytecode.push(op::RETURN);

        let instructions: Vec<_> = decode(&bytecode).into_iter().map(Result::unwrap).collect();
        let table = &instructions[leading_nops as usize];
        assert_eq!(table.offset, start);
        assert_eq!(
            table.operand,
            Operand::TableSwitch {
                default: i64::from(start) + 20,
                low: 1,
                targets: vec![i64::from(start) + 24, i64::from(start) + 28],
            }
        );
        let lookup = &instructions[leading_nops as usize + 1];
        assert_eq!(lookup.offset, after_table);
        assert_eq!(
            lookup.operand,
            Operand::LookupSwitch {
                default: i64::from(after_table) + 8,
                pairs: vec![(-5, i64::from(after_table) + 12)],
            }
        );
        assert_eq!(instructions.last().unwrap().offset, after_lookup);
    }
}

#[test]
fn decodes_wide_forms() {
    let bytecode = [
        op::WIDE,
        op::ILOAD,
        0x01,
        0x2C,
        op::WIDE,
        op::IINC,
        0x01,
        0x2C,
        0xFC,
        0x18,
        op::RETURN,
    ];
    let instructions: Vec<_> = decode(&bytecode).into_iter().map(Result::unwrap).collect();

    assert_eq!(instructions[0].offset, 0);
    assert!(instructions[0].wide);
    assert_eq!(instructions[0].operand, Operand::Local(300));
    assert_eq!(instructions[1].offset, 4);
    assert_eq!(
        instructions[1].operand,
        Operand::Iinc {
            local: 300,
            delta: -1000
        }
    );
    assert_eq!(instructions[2].offset, 10);
}

#[test]
fn rejects_malformed_bytecode() {
    let last_error = |bytecode: &[u8]| decode(bytecode).pop().unwrap().unwrap_err();

    assert_eq!(
        last_error(&[op::NOP, 0xCB]),
        ClassParseError::BadOpcode {
            opcode: 0xCB,
            offset: 1
        }
    );
    assert_eq!(
        last_error(&[op::WIDE, op::NOP]),
        ClassParseError::BadOpcode {
            opcode: op::NOP,
            offset: 0
        }
    );
    assert_eq!(
        last_error(&[op::SIPUSH, 0x01]),
        ClassParseError::TruncatedInstruction { offset: 0 }
    );

    // A range of every i32 must be rejected before anything is allocated for it.
    let mut huge_table = vec![op::TABLESWITCH, 0, 0, 0];
    huge_table.extend(0i32.to_be_bytes());
    huge_table.extend(i32::MIN.to_be_bytes());
    huge_table.extend(i32::MAX.to_be_bytes());
    assert_eq!(
        last_error(&huge_table),
        ClassParseError::TruncatedInstruction { offset: 0 }
    );

    let mut negative_lookup = vec![op::LOOKUPSWITCH, 0, 0, 0];
    negative_lookup.extend(0i32.to_be_bytes());
    negative_lookup.extend((-1i32).to_be_bytes());
    assert_eq!(
        last_error(&negative_lookup),
        ClassParseError::TruncatedInstruction { offset: 0 }
    );
}

#[test]
fn rejects_malformed_class_structure() {
    let (bytes, _, _) = sample_class();

    assert_eq!(
        ClassFile::parse(b"\xCA\xFE\xBA\xBF").unwrap_err(),
        ClassParseError::BadMagic
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ClassFile::parse(&trailing).unwrap_err(),
        ClassParseError::TrailingBytes { count: 1 }
    );

    // The first pool entry's tag sits right after the pool count.
    let mut bad_tag = bytes.clone();
    bad_tag[10] = 2;
    assert_eq!(
        ClassFile::parse(&bad_tag).unwrap_err(),
        ClassParseError::BadConstantTag { tag: 2, index: 1 }
    );

    // A Long in the last slot would put its second half outside the pool.
    let mut long_last = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65, 0, 2, 5];
    long_last.extend([0; 8]);
    assert_eq!(
        ClassFile::parse(&long_last).unwrap_err(),
        ClassParseError::BadConstantTag { tag: 5, index: 1 }
    );
}

#[test]
fn rejects_duplicate_code_attributes() {
    let mut builder = ClassBuilder::new();
    let first = builder.code_attribute(&[op::RETURN]);
    let second = builder.code_attribute(&[op::RETURN]);
    builder.method("run", "()V", &[first, second]);
    let bytes = builder.build("Test");
    let class = ClassFile::parse(&bytes).unwrap();

    assert_eq!(
        class.check_code().unwrap_err(),
        ClassParseError::DuplicateAttribute { name: "Code" }
    );
}

#[test]
fn malformed_input_never_panics() {
    let (bytes, _, _) = sample_class();
    let check = |data: &[u8]| {
        if let Ok(class) = ClassFile::parse(data) {
            let _ = class.check_code();
            let _ = class.name();
            let _ = class.interface_names();
            let _ = class.bootstrap_methods();
        }
    };

    for len in 0..bytes.len() {
        check(&bytes[..len]);
    }

    // Deterministic xorshift, so a failure reproduces exactly.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let mut mutated = bytes.clone();
        for _ in 0..1 + next() % 4 {
            let at = (next() % mutated.len() as u64) as usize;
            mutated[at] = next() as u8;
        }
        check(&mutated);
    }
}

#[test]
fn report_lists_classes_that_fail_to_parse() {
    let (good, _, _) = sample_class();
    let mut bad = good.clone();
    bad.push(0);

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in [("Good.class", &good), ("Bad.class", &bad)] {
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    let jar = writer.finish().unwrap().into_inner();

    let report = scan_bytes(&jar, &ScanLimits::default()).unwrap();
    let json = serde_json::to_value(&report).unwrap();
    let unparsed = json["archive"]["unparsedClasses"].as_array().unwrap();
    assert_eq!(unparsed.len(), 1);
    assert_eq!(unparsed[0]["name"], "Bad.class");
    assert_eq!(
        unparsed[0]["reason"],
        "extra data after the end of the class file (1 bytes)"
    );
}
