//! Decoding a method's bytecode into instructions with their offsets.

use super::ClassParseError;
use super::reader::ByteReader;

macro_rules! opcodes {
    ($($name:ident = $value:literal, $mnemonic:literal;)*) => {
        /// Opcode values, named as in the JVM specification.
        pub mod op {
            $(pub const $name: u8 = $value;)*
        }

        /// The mnemonic `javap` prints for an opcode, or `None` for byte
        /// values that are not valid in a class file.
        pub fn mnemonic(opcode: u8) -> Option<&'static str> {
            match opcode {
                $($value => Some($mnemonic),)*
                _ => None,
            }
        }
    };
}

opcodes! {
    NOP = 0x00, "nop"; ACONST_NULL = 0x01, "aconst_null"; ICONST_M1 = 0x02, "iconst_m1";
    ICONST_0 = 0x03, "iconst_0"; ICONST_1 = 0x04, "iconst_1"; ICONST_2 = 0x05, "iconst_2";
    ICONST_3 = 0x06, "iconst_3"; ICONST_4 = 0x07, "iconst_4"; ICONST_5 = 0x08, "iconst_5";
    LCONST_0 = 0x09, "lconst_0"; LCONST_1 = 0x0a, "lconst_1"; FCONST_0 = 0x0b, "fconst_0";
    FCONST_1 = 0x0c, "fconst_1"; FCONST_2 = 0x0d, "fconst_2"; DCONST_0 = 0x0e, "dconst_0";
    DCONST_1 = 0x0f, "dconst_1"; BIPUSH = 0x10, "bipush"; SIPUSH = 0x11, "sipush";
    LDC = 0x12, "ldc"; LDC_W = 0x13, "ldc_w"; LDC2_W = 0x14, "ldc2_w";
    ILOAD = 0x15, "iload"; LLOAD = 0x16, "lload"; FLOAD = 0x17, "fload";
    DLOAD = 0x18, "dload"; ALOAD = 0x19, "aload"; ILOAD_0 = 0x1a, "iload_0";
    ILOAD_1 = 0x1b, "iload_1"; ILOAD_2 = 0x1c, "iload_2"; ILOAD_3 = 0x1d, "iload_3";
    LLOAD_0 = 0x1e, "lload_0"; LLOAD_1 = 0x1f, "lload_1"; LLOAD_2 = 0x20, "lload_2";
    LLOAD_3 = 0x21, "lload_3"; FLOAD_0 = 0x22, "fload_0"; FLOAD_1 = 0x23, "fload_1";
    FLOAD_2 = 0x24, "fload_2"; FLOAD_3 = 0x25, "fload_3"; DLOAD_0 = 0x26, "dload_0";
    DLOAD_1 = 0x27, "dload_1"; DLOAD_2 = 0x28, "dload_2"; DLOAD_3 = 0x29, "dload_3";
    ALOAD_0 = 0x2a, "aload_0"; ALOAD_1 = 0x2b, "aload_1"; ALOAD_2 = 0x2c, "aload_2";
    ALOAD_3 = 0x2d, "aload_3"; IALOAD = 0x2e, "iaload"; LALOAD = 0x2f, "laload";
    FALOAD = 0x30, "faload"; DALOAD = 0x31, "daload"; AALOAD = 0x32, "aaload";
    BALOAD = 0x33, "baload"; CALOAD = 0x34, "caload"; SALOAD = 0x35, "saload";
    ISTORE = 0x36, "istore"; LSTORE = 0x37, "lstore"; FSTORE = 0x38, "fstore";
    DSTORE = 0x39, "dstore"; ASTORE = 0x3a, "astore"; ISTORE_0 = 0x3b, "istore_0";
    ISTORE_1 = 0x3c, "istore_1"; ISTORE_2 = 0x3d, "istore_2"; ISTORE_3 = 0x3e, "istore_3";
    LSTORE_0 = 0x3f, "lstore_0"; LSTORE_1 = 0x40, "lstore_1"; LSTORE_2 = 0x41, "lstore_2";
    LSTORE_3 = 0x42, "lstore_3"; FSTORE_0 = 0x43, "fstore_0"; FSTORE_1 = 0x44, "fstore_1";
    FSTORE_2 = 0x45, "fstore_2"; FSTORE_3 = 0x46, "fstore_3"; DSTORE_0 = 0x47, "dstore_0";
    DSTORE_1 = 0x48, "dstore_1"; DSTORE_2 = 0x49, "dstore_2"; DSTORE_3 = 0x4a, "dstore_3";
    ASTORE_0 = 0x4b, "astore_0"; ASTORE_1 = 0x4c, "astore_1"; ASTORE_2 = 0x4d, "astore_2";
    ASTORE_3 = 0x4e, "astore_3"; IASTORE = 0x4f, "iastore"; LASTORE = 0x50, "lastore";
    FASTORE = 0x51, "fastore"; DASTORE = 0x52, "dastore"; AASTORE = 0x53, "aastore";
    BASTORE = 0x54, "bastore"; CASTORE = 0x55, "castore"; SASTORE = 0x56, "sastore";
    POP = 0x57, "pop"; POP2 = 0x58, "pop2"; DUP = 0x59, "dup";
    DUP_X1 = 0x5a, "dup_x1"; DUP_X2 = 0x5b, "dup_x2"; DUP2 = 0x5c, "dup2";
    DUP2_X1 = 0x5d, "dup2_x1"; DUP2_X2 = 0x5e, "dup2_x2"; SWAP = 0x5f, "swap";
    IADD = 0x60, "iadd"; LADD = 0x61, "ladd"; FADD = 0x62, "fadd";
    DADD = 0x63, "dadd"; ISUB = 0x64, "isub"; LSUB = 0x65, "lsub";
    FSUB = 0x66, "fsub"; DSUB = 0x67, "dsub"; IMUL = 0x68, "imul";
    LMUL = 0x69, "lmul"; FMUL = 0x6a, "fmul"; DMUL = 0x6b, "dmul";
    IDIV = 0x6c, "idiv"; LDIV = 0x6d, "ldiv"; FDIV = 0x6e, "fdiv";
    DDIV = 0x6f, "ddiv"; IREM = 0x70, "irem"; LREM = 0x71, "lrem";
    FREM = 0x72, "frem"; DREM = 0x73, "drem"; INEG = 0x74, "ineg";
    LNEG = 0x75, "lneg"; FNEG = 0x76, "fneg"; DNEG = 0x77, "dneg";
    ISHL = 0x78, "ishl"; LSHL = 0x79, "lshl"; ISHR = 0x7a, "ishr";
    LSHR = 0x7b, "lshr"; IUSHR = 0x7c, "iushr"; LUSHR = 0x7d, "lushr";
    IAND = 0x7e, "iand"; LAND = 0x7f, "land"; IOR = 0x80, "ior";
    LOR = 0x81, "lor"; IXOR = 0x82, "ixor"; LXOR = 0x83, "lxor";
    IINC = 0x84, "iinc"; I2L = 0x85, "i2l"; I2F = 0x86, "i2f";
    I2D = 0x87, "i2d"; L2I = 0x88, "l2i"; L2F = 0x89, "l2f";
    L2D = 0x8a, "l2d"; F2I = 0x8b, "f2i"; F2L = 0x8c, "f2l";
    F2D = 0x8d, "f2d"; D2I = 0x8e, "d2i"; D2L = 0x8f, "d2l";
    D2F = 0x90, "d2f"; I2B = 0x91, "i2b"; I2C = 0x92, "i2c";
    I2S = 0x93, "i2s"; LCMP = 0x94, "lcmp"; FCMPL = 0x95, "fcmpl";
    FCMPG = 0x96, "fcmpg"; DCMPL = 0x97, "dcmpl"; DCMPG = 0x98, "dcmpg";
    IFEQ = 0x99, "ifeq"; IFNE = 0x9a, "ifne"; IFLT = 0x9b, "iflt";
    IFGE = 0x9c, "ifge"; IFGT = 0x9d, "ifgt"; IFLE = 0x9e, "ifle";
    IF_ICMPEQ = 0x9f, "if_icmpeq"; IF_ICMPNE = 0xa0, "if_icmpne"; IF_ICMPLT = 0xa1, "if_icmplt";
    IF_ICMPGE = 0xa2, "if_icmpge"; IF_ICMPGT = 0xa3, "if_icmpgt"; IF_ICMPLE = 0xa4, "if_icmple";
    IF_ACMPEQ = 0xa5, "if_acmpeq"; IF_ACMPNE = 0xa6, "if_acmpne"; GOTO = 0xa7, "goto";
    JSR = 0xa8, "jsr"; RET = 0xa9, "ret"; TABLESWITCH = 0xaa, "tableswitch";
    LOOKUPSWITCH = 0xab, "lookupswitch"; IRETURN = 0xac, "ireturn"; LRETURN = 0xad, "lreturn";
    FRETURN = 0xae, "freturn"; DRETURN = 0xaf, "dreturn"; ARETURN = 0xb0, "areturn";
    RETURN = 0xb1, "return"; GETSTATIC = 0xb2, "getstatic"; PUTSTATIC = 0xb3, "putstatic";
    GETFIELD = 0xb4, "getfield"; PUTFIELD = 0xb5, "putfield"; INVOKEVIRTUAL = 0xb6, "invokevirtual";
    INVOKESPECIAL = 0xb7, "invokespecial"; INVOKESTATIC = 0xb8, "invokestatic";
    INVOKEINTERFACE = 0xb9, "invokeinterface"; INVOKEDYNAMIC = 0xba, "invokedynamic";
    NEW = 0xbb, "new"; NEWARRAY = 0xbc, "newarray"; ANEWARRAY = 0xbd, "anewarray";
    ARRAYLENGTH = 0xbe, "arraylength"; ATHROW = 0xbf, "athrow"; CHECKCAST = 0xc0, "checkcast";
    INSTANCEOF = 0xc1, "instanceof"; MONITORENTER = 0xc2, "monitorenter";
    MONITOREXIT = 0xc3, "monitorexit"; WIDE = 0xc4, "wide";
    MULTIANEWARRAY = 0xc5, "multianewarray"; IFNULL = 0xc6, "ifnull"; IFNONNULL = 0xc7, "ifnonnull";
    GOTO_W = 0xc8, "goto_w"; JSR_W = 0xc9, "jsr_w";
}

/// An instruction's operands. Branch targets are absolute offsets in the
/// method's code, widened so a malformed jump cannot overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    None,
    /// Immediate value pushed by `bipush` or `sipush`.
    Immediate(i32),
    /// Local variable slot.
    Local(u16),
    /// Constant pool index.
    Constant(u16),
    Branch(i64),
    Iinc {
        local: u16,
        delta: i16,
    },
    InvokeInterface {
        index: u16,
        count: u8,
    },
    /// Array element type code used by `newarray`.
    ArrayType(u8),
    MultiANewArray {
        index: u16,
        dimensions: u8,
    },
    TableSwitch {
        default: i64,
        low: i32,
        targets: Vec<i64>,
    },
    LookupSwitch {
        default: i64,
        pairs: Vec<(i32, i64)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Offset of the opcode, or of the `wide` prefix when there is one.
    pub offset: u32,
    pub opcode: u8,
    /// Set when a `wide` prefix widened the operands.
    pub wide: bool,
    pub operand: Operand,
}

impl Instruction {
    pub fn mnemonic(&self) -> &'static str {
        mnemonic(self.opcode).unwrap_or("invalid")
    }
}

/// Iterator over a method's instructions. Stops after the first error.
pub struct Instructions<'a> {
    code: &'a [u8],
    reader: ByteReader<'a>,
    failed: bool,
}

impl<'a> Instructions<'a> {
    pub(crate) fn new(code: &'a [u8]) -> Self {
        Self {
            code,
            reader: ByteReader::new(code),
            failed: false,
        }
    }

    fn decode(&mut self) -> Result<Instruction, ClassParseError> {
        let start = self.reader.pos();
        let truncated = |_| ClassParseError::TruncatedInstruction { offset: start };
        let reader = &mut self.reader;
        let mut opcode = reader.u8()?;
        let wide = opcode == op::WIDE;
        if wide {
            opcode = reader.u8().map_err(truncated)?;
        }
        let branch = |delta: i64| start as i64 + delta;

        let operand = match opcode {
            _ if wide => match opcode {
                op::ILOAD..=op::ALOAD | op::ISTORE..=op::ASTORE | op::RET => {
                    Operand::Local(reader.u16().map_err(truncated)?)
                }
                op::IINC => Operand::Iinc {
                    local: reader.u16().map_err(truncated)?,
                    delta: reader.i16().map_err(truncated)?,
                },
                _ => {
                    return Err(ClassParseError::BadOpcode {
                        opcode,
                        offset: start,
                    });
                }
            },
            op::BIPUSH => Operand::Immediate(reader.i8().map_err(truncated)?.into()),
            op::SIPUSH => Operand::Immediate(reader.i16().map_err(truncated)?.into()),
            op::LDC => Operand::Constant(reader.u8().map_err(truncated)?.into()),
            op::LDC_W
            | op::LDC2_W
            | op::GETSTATIC..=op::INVOKESTATIC
            | op::NEW
            | op::ANEWARRAY
            | op::CHECKCAST
            | op::INSTANCEOF => Operand::Constant(reader.u16().map_err(truncated)?),
            op::ILOAD..=op::ALOAD | op::ISTORE..=op::ASTORE | op::RET => {
                Operand::Local(reader.u8().map_err(truncated)?.into())
            }
            op::IINC => Operand::Iinc {
                local: reader.u8().map_err(truncated)?.into(),
                delta: reader.i8().map_err(truncated)?.into(),
            },
            op::IFEQ..=op::JSR | op::IFNULL | op::IFNONNULL => {
                Operand::Branch(branch(reader.i16().map_err(truncated)?.into()))
            }
            op::GOTO_W | op::JSR_W => {
                Operand::Branch(branch(reader.i32().map_err(truncated)?.into()))
            }
            op::INVOKEINTERFACE => {
                let index = reader.u16().map_err(truncated)?;
                let count = reader.u8().map_err(truncated)?;
                reader.skip(1).map_err(truncated)?;
                Operand::InvokeInterface { index, count }
            }
            op::INVOKEDYNAMIC => {
                let index = reader.u16().map_err(truncated)?;
                reader.skip(2).map_err(truncated)?;
                Operand::Constant(index)
            }
            op::NEWARRAY => Operand::ArrayType(reader.u8().map_err(truncated)?),
            op::MULTIANEWARRAY => Operand::MultiANewArray {
                index: reader.u16().map_err(truncated)?,
                dimensions: reader.u8().map_err(truncated)?,
            },
            op::TABLESWITCH | op::LOOKUPSWITCH => {
                // Operands start at the next multiple of four from the start
                // of the code, so padding depends on the opcode's offset.
                let padding = (4 - (start + 1) % 4) % 4;
                reader.skip(padding).map_err(truncated)?;
                let default = branch(reader.i32().map_err(truncated)?.into());
                if opcode == op::TABLESWITCH {
                    let low = reader.i32().map_err(truncated)?;
                    let high = reader.i32().map_err(truncated)?;
                    let count = i64::from(high) - i64::from(low) + 1;
                    if count < 0 || count as usize > reader.remaining() / 4 {
                        return Err(ClassParseError::TruncatedInstruction { offset: start });
                    }
                    let mut targets = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        targets.push(branch(reader.i32().map_err(truncated)?.into()));
                    }
                    Operand::TableSwitch {
                        default,
                        low,
                        targets,
                    }
                } else {
                    let count = reader.i32().map_err(truncated)?;
                    if count < 0 || count as usize > reader.remaining() / 8 {
                        return Err(ClassParseError::TruncatedInstruction { offset: start });
                    }
                    let mut pairs = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        let key = reader.i32().map_err(truncated)?;
                        pairs.push((key, branch(reader.i32().map_err(truncated)?.into())));
                    }
                    Operand::LookupSwitch { default, pairs }
                }
            }
            _ if mnemonic(opcode).is_some() => Operand::None,
            _ => {
                return Err(ClassParseError::BadOpcode {
                    opcode,
                    offset: start,
                });
            }
        };

        Ok(Instruction {
            offset: start as u32,
            opcode,
            wide,
            operand,
        })
    }
}

impl Iterator for Instructions<'_> {
    type Item = Result<Instruction, ClassParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.reader.pos() >= self.code.len() {
            return None;
        }
        let result = self.decode();
        self.failed = result.is_err();
        Some(result)
    }
}
