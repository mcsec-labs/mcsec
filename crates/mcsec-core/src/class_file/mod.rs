//! Parsing JVM class files.
//!
//! Strict about the structures the JVM checks when loading a class, which
//! are the constant pool, fields, methods, and `Code` attributes. Lenient
//! about attributes the JVM ignores or checks late, since obfuscators put
//! malformed ones there to crash analysis tools while the class still loads.
//! Those are kept as raw bytes and parsed only when asked for.
//!
//! Parsing borrows from the class bytes and copies nothing up front.

mod bytecode;
mod constant_pool;
mod reader;

use std::borrow::Cow;

use thiserror::Error;

pub use bytecode::{Instruction, Instructions, Operand, mnemonic, op};
pub use constant_pool::{Constant, ConstantPool, MemberKind, MemberRef, decode_modified_utf8};
use reader::ByteReader;

const MAGIC: u32 = 0xCAFE_BABE;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClassParseError {
    #[error("not a class file")]
    BadMagic,
    #[error("unexpected end of data at offset {offset}")]
    Truncated { offset: usize },
    #[error("extra data after the end of the class file ({count} bytes)")]
    TrailingBytes { count: usize },
    #[error("invalid constant pool tag {tag} at index {index}")]
    BadConstantTag { tag: u8, index: u16 },
    #[error("constant pool index {index} is not a {expected}")]
    BadConstantRef { index: u16, expected: &'static str },
    #[error("more than one {name} attribute")]
    DuplicateAttribute { name: &'static str },
    #[error("invalid opcode {opcode:#04x} at code offset {offset}")]
    BadOpcode { opcode: u8, offset: usize },
    #[error("instruction at code offset {offset} runs past the end of the code")]
    TruncatedInstruction { offset: usize },
}

/// An attribute with its body left unparsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub name_index: u16,
    pub data: &'a [u8],
}

fn parse_attributes<'a>(
    reader: &mut ByteReader<'a>,
) -> Result<Vec<Attribute<'a>>, ClassParseError> {
    let count = reader.u16()? as usize;
    // An attribute header is a name index and a length, six bytes.
    let mut attributes = Vec::with_capacity(reader.capacity_for(count, 6));
    for _ in 0..count {
        let name_index = reader.u16()?;
        let len = reader.u32()? as usize;
        attributes.push(Attribute {
            name_index,
            data: reader.bytes(len)?,
        });
    }
    Ok(attributes)
}

/// The single attribute named `name`, failing like the JVM when there is
/// more than one.
fn find_attribute<'a>(
    attributes: &[Attribute<'a>],
    pool: &ConstantPool<'a>,
    name: &'static str,
) -> Result<Option<Attribute<'a>>, ClassParseError> {
    let mut found = None;
    for attribute in attributes {
        if pool.utf8_bytes(attribute.name_index).ok() == Some(name.as_bytes()) {
            if found.is_some() {
                return Err(ClassParseError::DuplicateAttribute { name });
            }
            found = Some(*attribute);
        }
    }
    Ok(found)
}

fn parse_members<'a>(reader: &mut ByteReader<'a>) -> Result<Vec<Member<'a>>, ClassParseError> {
    let count = reader.u16()? as usize;
    // A field or method is at least its flags, name, descriptor, and
    // attribute count, eight bytes.
    let mut members = Vec::with_capacity(reader.capacity_for(count, 8));
    for _ in 0..count {
        members.push(Member::parse(reader)?);
    }
    Ok(members)
}

/// A field or method.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> Member<'a> {
    fn parse(reader: &mut ByteReader<'a>) -> Result<Self, ClassParseError> {
        Ok(Self {
            access_flags: reader.u16()?,
            name_index: reader.u16()?,
            descriptor_index: reader.u16()?,
            attributes: parse_attributes(reader)?,
        })
    }

    pub fn name(&self, pool: &ConstantPool<'a>) -> Result<Cow<'a, str>, ClassParseError> {
        pool.utf8(self.name_index)
    }

    pub fn descriptor(&self, pool: &ConstantPool<'a>) -> Result<Cow<'a, str>, ClassParseError> {
        pool.utf8(self.descriptor_index)
    }

    /// The method body. `None` for abstract and native methods, and for fields.
    pub fn code(&self, pool: &ConstantPool<'a>) -> Result<Option<Code<'a>>, ClassParseError> {
        find_attribute(&self.attributes, pool, "Code")?
            .map(|attribute| Code::parse(attribute.data))
            .transpose()
    }

    /// Constant pool index of a field's compile time constant, which holds
    /// the value of `static final` primitives and strings.
    pub fn constant_value(&self, pool: &ConstantPool<'a>) -> Result<Option<u16>, ClassParseError> {
        find_attribute(&self.attributes, pool, "ConstantValue")?
            .map(|attribute| ByteReader::new(attribute.data).u16())
            .transpose()
    }
}

/// One entry in a method's exception table. Offsets are into the method's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub start: u16,
    pub end: u16,
    pub handler: u16,
    /// Constant pool index of the caught class, or zero for any exception.
    pub catch_type: u16,
}

/// A method's `Code` attribute.
#[derive(Debug, Clone)]
pub struct Code<'a> {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: &'a [u8],
    pub exception_table: Vec<ExceptionHandler>,
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> Code<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ClassParseError> {
        let mut reader = ByteReader::new(data);
        let max_stack = reader.u16()?;
        let max_locals = reader.u16()?;
        let code_len = reader.u32()? as usize;
        let bytecode = reader.bytes(code_len)?;

        let count = reader.u16()? as usize;
        let mut exception_table = Vec::with_capacity(reader.capacity_for(count, 8));
        for _ in 0..count {
            exception_table.push(ExceptionHandler {
                start: reader.u16()?,
                end: reader.u16()?,
                handler: reader.u16()?,
                catch_type: reader.u16()?,
            });
        }

        Ok(Self {
            max_stack,
            max_locals,
            bytecode,
            exception_table,
            attributes: parse_attributes(&mut reader)?,
        })
    }

    pub fn instructions(&self) -> Instructions<'a> {
        Instructions::new(self.bytecode)
    }
}

/// One `BootstrapMethods` entry, which `invokedynamic` and dynamic constants
/// refer to by position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapMethod {
    /// Constant pool index of a MethodHandle.
    pub method_ref: u16,
    /// Constant pool indexes of the static arguments.
    pub arguments: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ClassFile<'a> {
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: ConstantPool<'a>,
    pub access_flags: u16,
    pub this_class: u16,
    /// Zero only for `java/lang/Object` and module descriptors.
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<Member<'a>>,
    pub methods: Vec<Member<'a>>,
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> ClassFile<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ClassParseError> {
        let mut reader = ByteReader::new(data);
        if reader.u32().ok() != Some(MAGIC) {
            return Err(ClassParseError::BadMagic);
        }
        let minor_version = reader.u16()?;
        let major_version = reader.u16()?;
        let constant_pool = ConstantPool::parse(&mut reader)?;
        let access_flags = reader.u16()?;
        let this_class = reader.u16()?;
        let super_class = reader.u16()?;

        let count = reader.u16()? as usize;
        let mut interfaces = Vec::with_capacity(reader.capacity_for(count, 2));
        for _ in 0..count {
            interfaces.push(reader.u16()?);
        }

        let fields = parse_members(&mut reader)?;
        let methods = parse_members(&mut reader)?;
        let attributes = parse_attributes(&mut reader)?;

        // The JVM rejects classes with bytes after the last attribute.
        if reader.remaining() > 0 {
            return Err(ClassParseError::TrailingBytes {
                count: reader.remaining(),
            });
        }

        Ok(Self {
            minor_version,
            major_version,
            constant_pool,
            access_flags,
            this_class,
            super_class,
            interfaces,
            fields,
            methods,
            attributes,
        })
    }

    /// Internal JVM name, for example `net/example/Mod`.
    pub fn name(&self) -> Result<Cow<'a, str>, ClassParseError> {
        self.constant_pool.class_name(self.this_class)
    }

    pub fn super_name(&self) -> Result<Option<Cow<'a, str>>, ClassParseError> {
        if self.super_class == 0 {
            return Ok(None);
        }
        self.constant_pool.class_name(self.super_class).map(Some)
    }

    pub fn interface_names(&self) -> Result<Vec<Cow<'a, str>>, ClassParseError> {
        self.interfaces
            .iter()
            .map(|&index| self.constant_pool.class_name(index))
            .collect()
    }

    pub fn bootstrap_methods(&self) -> Result<Vec<BootstrapMethod>, ClassParseError> {
        let Some(attribute) =
            find_attribute(&self.attributes, &self.constant_pool, "BootstrapMethods")?
        else {
            return Ok(Vec::new());
        };
        let mut reader = ByteReader::new(attribute.data);
        let count = reader.u16()? as usize;
        let mut methods = Vec::with_capacity(reader.capacity_for(count, 4));
        for _ in 0..count {
            let method_ref = reader.u16()?;
            let argument_count = reader.u16()? as usize;
            let mut arguments = Vec::with_capacity(reader.capacity_for(argument_count, 2));
            for _ in 0..argument_count {
                arguments.push(reader.u16()?);
            }
            methods.push(BootstrapMethod {
                method_ref,
                arguments,
            });
        }
        Ok(methods)
    }

    /// Parses every method body and decodes all of its instructions. This is
    /// the full depth of checking the scanner relies on.
    pub fn check_code(&self) -> Result<(), ClassParseError> {
        for method in &self.methods {
            if let Some(code) = method.code(&self.constant_pool)? {
                for instruction in code.instructions() {
                    instruction?;
                }
            }
        }
        Ok(())
    }
}
