//! The constant pool and typed lookups into it.

use std::borrow::Cow;

use super::ClassParseError;
use super::reader::ByteReader;

/// One constant pool slot. Index references are left unresolved until
/// looked up, so a malformed reference only fails the lookup that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constant<'a> {
    /// Raw modified UTF-8 bytes. Decoded on lookup.
    Utf8(&'a [u8]),
    Integer(i32),
    /// IEEE 754 bits.
    Float(u32),
    Long(i64),
    /// IEEE 754 bits.
    Double(u64),
    Class {
        name_index: u16,
    },
    String {
        string_index: u16,
    },
    Fieldref {
        class_index: u16,
        name_and_type_index: u16,
    },
    Methodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_method_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_method_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    /// Index zero, and the slot after each Long or Double.
    Unusable,
}

/// Which kind of member a reference points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Field,
    Method,
    InterfaceMethod,
}

/// A resolved field or method reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRef<'a> {
    pub kind: MemberKind,
    /// Internal JVM name, for example `java/io/ObjectInputStream`.
    pub class_name: Cow<'a, str>,
    pub name: Cow<'a, str>,
    pub descriptor: Cow<'a, str>,
}

#[derive(Debug, Clone)]
pub struct ConstantPool<'a> {
    entries: Vec<Constant<'a>>,
}

impl<'a> ConstantPool<'a> {
    pub(crate) fn parse(reader: &mut ByteReader<'a>) -> Result<Self, ClassParseError> {
        let count = reader.u16()?;
        // The smallest constant is three bytes, a tag and one index.
        let mut entries = Vec::with_capacity(reader.capacity_for(count as usize, 3) + 1);
        entries.push(Constant::Unusable);

        while entries.len() < count as usize {
            let index = entries.len() as u16;
            let tag = reader.u8()?;
            let constant = match tag {
                1 => {
                    let len = reader.u16()? as usize;
                    Constant::Utf8(reader.bytes(len)?)
                }
                3 => Constant::Integer(reader.i32()?),
                4 => Constant::Float(reader.u32()?),
                5 | 6 => {
                    // Eight byte constants take two slots, and the second
                    // slot must still be inside the pool.
                    if index as usize + 1 >= count as usize {
                        return Err(ClassParseError::BadConstantTag { tag, index });
                    }
                    let high = u64::from(reader.u32()?);
                    let bits = (high << 32) | u64::from(reader.u32()?);
                    entries.push(if tag == 5 {
                        Constant::Long(bits as i64)
                    } else {
                        Constant::Double(bits)
                    });
                    entries.push(Constant::Unusable);
                    continue;
                }
                7 => Constant::Class {
                    name_index: reader.u16()?,
                },
                8 => Constant::String {
                    string_index: reader.u16()?,
                },
                9 => Constant::Fieldref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                10 => Constant::Methodref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                11 => Constant::InterfaceMethodref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                12 => Constant::NameAndType {
                    name_index: reader.u16()?,
                    descriptor_index: reader.u16()?,
                },
                15 => Constant::MethodHandle {
                    reference_kind: reader.u8()?,
                    reference_index: reader.u16()?,
                },
                16 => Constant::MethodType {
                    descriptor_index: reader.u16()?,
                },
                17 => Constant::Dynamic {
                    bootstrap_method_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                18 => Constant::InvokeDynamic {
                    bootstrap_method_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                19 => Constant::Module {
                    name_index: reader.u16()?,
                },
                20 => Constant::Package {
                    name_index: reader.u16()?,
                },
                _ => return Err(ClassParseError::BadConstantTag { tag, index }),
            };
            entries.push(constant);
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.len() <= 1
    }

    pub fn get(&self, index: u16) -> Option<&Constant<'a>> {
        self.entries.get(index as usize)
    }

    /// Every slot with its index, including unusable ones.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &Constant<'a>)> {
        self.entries.iter().enumerate().map(|(i, c)| (i as u16, c))
    }

    fn bad_ref(index: u16, expected: &'static str) -> ClassParseError {
        ClassParseError::BadConstantRef { index, expected }
    }

    /// Raw modified UTF-8 bytes, for comparisons that need no decoding.
    pub fn utf8_bytes(&self, index: u16) -> Result<&'a [u8], ClassParseError> {
        match self.get(index) {
            Some(Constant::Utf8(bytes)) => Ok(bytes),
            _ => Err(Self::bad_ref(index, "Utf8")),
        }
    }

    pub fn utf8(&self, index: u16) -> Result<Cow<'a, str>, ClassParseError> {
        self.utf8_bytes(index).map(decode_modified_utf8)
    }

    pub fn class_name(&self, index: u16) -> Result<Cow<'a, str>, ClassParseError> {
        match self.get(index) {
            Some(&Constant::Class { name_index }) => self.utf8(name_index),
            _ => Err(Self::bad_ref(index, "Class")),
        }
    }

    /// The text of a String constant, as loaded by `ldc`.
    pub fn string(&self, index: u16) -> Result<Cow<'a, str>, ClassParseError> {
        match self.get(index) {
            Some(&Constant::String { string_index }) => self.utf8(string_index),
            _ => Err(Self::bad_ref(index, "String")),
        }
    }

    pub fn name_and_type(
        &self,
        index: u16,
    ) -> Result<(Cow<'a, str>, Cow<'a, str>), ClassParseError> {
        match self.get(index) {
            Some(&Constant::NameAndType {
                name_index,
                descriptor_index,
            }) => Ok((self.utf8(name_index)?, self.utf8(descriptor_index)?)),
            _ => Err(Self::bad_ref(index, "NameAndType")),
        }
    }

    pub fn member_ref(&self, index: u16) -> Result<MemberRef<'a>, ClassParseError> {
        let (kind, class_index, name_and_type_index) = match self.get(index) {
            Some(&Constant::Fieldref {
                class_index,
                name_and_type_index,
            }) => (MemberKind::Field, class_index, name_and_type_index),
            Some(&Constant::Methodref {
                class_index,
                name_and_type_index,
            }) => (MemberKind::Method, class_index, name_and_type_index),
            Some(&Constant::InterfaceMethodref {
                class_index,
                name_and_type_index,
            }) => (
                MemberKind::InterfaceMethod,
                class_index,
                name_and_type_index,
            ),
            _ => return Err(Self::bad_ref(index, "member reference")),
        };
        let (name, descriptor) = self.name_and_type(name_and_type_index)?;
        Ok(MemberRef {
            kind,
            class_name: self.class_name(class_index)?,
            name,
            descriptor,
        })
    }
}

/// Decodes the JVM's modified UTF-8. Most strings are also valid standard
/// UTF-8 and are borrowed as is. The rest use the two forms standard UTF-8
/// rejects, a two byte encoding of NUL and supplementary characters stored
/// as separately encoded surrogate halves. Those are decoded through UTF-16,
/// which joins the halves. Malformed bytes and unpaired surrogates become
/// U+FFFD.
pub fn decode_modified_utf8(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(text);
    }

    const REPLACEMENT: u16 = 0xFFFD;
    let continuation = |b: Option<&u8>| {
        b.filter(|&&b| b & 0xC0 == 0x80)
            .map(|&b| u16::from(b & 0x3F))
    };

    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(u16::from(b));
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            match continuation(bytes.get(i + 1)) {
                Some(low) => {
                    units.push((u16::from(b & 0x1F) << 6) | low);
                    i += 2;
                }
                None => {
                    units.push(REPLACEMENT);
                    i += 1;
                }
            }
        } else if b & 0xF0 == 0xE0 {
            match (
                continuation(bytes.get(i + 1)),
                continuation(bytes.get(i + 2)),
            ) {
                (Some(mid), Some(low)) => {
                    units.push((u16::from(b & 0x0F) << 12) | (mid << 6) | low);
                    i += 3;
                }
                _ => {
                    units.push(REPLACEMENT);
                    i += 1;
                }
            }
        } else {
            units.push(REPLACEMENT);
            i += 1;
        }
    }
    Cow::Owned(String::from_utf16_lossy(&units))
}
