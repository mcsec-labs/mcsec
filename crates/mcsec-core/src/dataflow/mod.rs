//! Data flow over a method's bytecode.
//!
//! Simulates each instruction on abstract values that carry labels for where
//! they came from, such as network data, instead of real values. Labels are
//! merged where control flow joins and the simulation repeats until nothing
//! changes, so branches, loops, and exception handlers are all covered.
//!
//! A [`Policy`] decides which values are sources and with which labels. The
//! engine moves labels through the stack, locals, arrays, constructors, and
//! calls, and a rule reads the result through an observer that sees the
//! state before every instruction.

mod cfg;
mod descriptor;

use std::collections::VecDeque;
use std::rc::Rc;

pub use descriptor::{JvmType, MethodType, field_type};

use crate::class_file::{ClassFile, Constant, ConstantPool, Instruction, Member, Operand, op};
use cfg::Cfg;

const ACC_STATIC: u16 = 0x0008;

/// Bound on block visits per block, so a crafted method with a huge or
/// adversarial control flow graph cannot keep the analysis running.
const MAX_VISITS_PER_BLOCK: usize = 64;

/// A set of source kinds, as bits a policy assigns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Labels(pub u32);

impl Labels {
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, other: Labels) -> bool {
        self.0 & other.0 == other.0 && !other.is_empty()
    }
}

/// Where a value's labels first entered the method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub offset: u32,
    pub description: Rc<str>,
}

/// The `new` instruction that created an object or array. Copies of a
/// reference share it, so labels added through one copy reach the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alloc {
    pub offset: u32,
    /// Internal name of the class, or the array descriptor.
    pub class: Rc<str>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Value {
    pub labels: Labels,
    pub origin: Option<Origin>,
    pub alloc: Option<Alloc>,
    /// Long and double values, which take two slots.
    pub wide: bool,
}

impl Value {
    fn of_width(wide: bool) -> Self {
        Self {
            wide,
            ..Self::default()
        }
    }

    /// A new value computed from `inputs`, carrying all of their labels.
    fn derived<'v>(inputs: impl IntoIterator<Item = &'v Value>, wide: bool) -> Self {
        let mut out = Self::of_width(wide);
        for input in inputs {
            out.add(input.labels, input.origin.as_ref());
        }
        out
    }

    fn add(&mut self, labels: Labels, origin: Option<&Origin>) {
        if labels.is_empty() {
            return;
        }
        self.labels.0 |= labels.0;
        if self.origin.is_none() {
            self.origin = origin.cloned();
        }
    }

    /// Joins another value into this one. Returns true when anything changed.
    fn merge(&mut self, other: &Value) -> bool {
        let before = (
            self.labels,
            self.origin.is_some(),
            self.alloc.is_some(),
            self.wide,
        );
        self.add(other.labels, other.origin.as_ref());
        if self.alloc.is_none() {
            self.alloc = other.alloc.clone();
        }
        self.wide |= other.wide;
        before
            != (
                self.labels,
                self.origin.is_some(),
                self.alloc.is_some(),
                self.wide,
            )
    }
}

/// The locals and operand stack at one point in a method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub locals: Vec<Value>,
    pub stack: Vec<Value>,
}

impl Frame {
    /// The value `depth` entries below the top of the stack.
    pub fn peek(&self, depth: usize) -> Option<&Value> {
        self.stack
            .len()
            .checked_sub(depth + 1)
            .map(|i| &self.stack[i])
    }

    // Verified bytecode never pops an empty stack. Crafted bytecode can, so
    // an empty pop yields a blank value instead of stopping the analysis.
    fn pop(&mut self) -> Value {
        self.stack.pop().unwrap_or_default()
    }

    fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    fn local(&self, index: usize) -> Value {
        self.locals.get(index).cloned().unwrap_or_default()
    }

    fn set_local(&mut self, index: usize, value: Value) {
        if index >= self.locals.len() {
            self.locals.resize(index + 1, Value::default());
        }
        self.locals[index] = value;
    }

    fn top_is_wide(&self) -> bool {
        self.stack.last().is_some_and(|v| v.wide)
    }

    /// Adds labels to every copy of the object created at `alloc`.
    fn taint_alloc(&mut self, alloc: u32, labels: Labels, origin: Option<&Origin>) {
        for value in self.locals.iter_mut().chain(self.stack.iter_mut()) {
            if value.alloc.as_ref().is_some_and(|a| a.offset == alloc) {
                value.add(labels, origin);
            }
        }
    }

    fn merge(&mut self, other: &Frame) -> bool {
        let mut changed = false;
        if other.locals.len() > self.locals.len() {
            self.locals.resize(other.locals.len(), Value::default());
            changed = true;
        }
        for (mine, theirs) in self.locals.iter_mut().zip(&other.locals) {
            changed |= mine.merge(theirs);
        }
        // Verified bytecode has equal stack heights where flow joins. On
        // crafted bytecode the shorter stack wins so the merge stays bounded.
        if other.stack.len() < self.stack.len() {
            self.stack.truncate(other.stack.len());
            changed = true;
        }
        for (mine, theirs) in self.stack.iter_mut().zip(&other.stack) {
            changed |= mine.merge(theirs);
        }
        changed
    }
}

/// Decides which values are sources and with which labels.
pub trait Policy {
    /// Labels for a parameter of type `ty`, an internal name or array
    /// descriptor. `receiver` is set for `this`, whose type is the class
    /// being analyzed.
    fn parameter(&self, ty: &str, receiver: bool) -> Option<(Labels, String)>;
    /// Labels added to the result of calling a method.
    fn call(&self, owner: &str, name: &str, descriptor: &str) -> Option<(Labels, String)>;
    /// Labels for an object created with `new`.
    fn allocation(&self, class: &str) -> Option<(Labels, String)>;
}

/// The method and class an observer is looking at.
pub struct Site<'r, 'a> {
    pub pool: &'r ConstantPool<'a>,
    pub instruction: &'r Instruction,
}

/// Runs the data flow over one method and calls `observe` with the state
/// before every reachable instruction once the analysis has settled.
/// Returns false when the method has no body or its bytecode fails to decode.
pub fn analyze(
    class: &ClassFile,
    method: &Member,
    policy: &dyn Policy,
    observe: &mut dyn FnMut(&Site, &Frame),
) -> bool {
    let pool = &class.constant_pool;
    let Ok(Some(code)) = method.code(pool) else {
        return false;
    };
    let Ok(instructions) = code.instructions().collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    if instructions.is_empty() {
        return false;
    }
    let Ok(descriptor) = method.descriptor(pool) else {
        return false;
    };
    let class_name = class.name().map(|n| n.into_owned()).unwrap_or_default();

    let cfg = Cfg::build(&instructions, &code.exception_table);
    let entry = entry_frame(
        &class_name,
        method.access_flags & ACC_STATIC != 0,
        &descriptor,
        usize::from(code.max_locals),
        policy,
    );
    let engine = Engine { pool, policy };

    let mut block_in: Vec<Option<Frame>> = vec![None; cfg.blocks.len()];
    block_in[0] = Some(entry);
    let mut queued = vec![false; cfg.blocks.len()];
    let mut worklist = VecDeque::from([0usize]);
    queued[0] = true;
    let mut visits = 0usize;
    let budget = cfg.blocks.len().saturating_mul(MAX_VISITS_PER_BLOCK);

    while let Some(b) = worklist.pop_front() {
        queued[b] = false;
        visits += 1;
        if visits > budget {
            break;
        }
        let block = &cfg.blocks[b];
        let mut frame = block_in[b].clone().unwrap_or_default();
        let mut pending: Vec<(usize, Frame)> = Vec::new();
        for (instruction, handlers) in instructions[block.start..block.end]
            .iter()
            .zip(&cfg.handlers[block.start..block.end])
        {
            for &handler in handlers {
                pending.push((handler, handler_frame(&frame)));
            }
            engine.step(instruction, &mut frame);
        }
        for &successor in &block.successors {
            pending.push((successor, frame.clone()));
        }
        for (target, incoming) in pending {
            let changed = match &mut block_in[target] {
                Some(existing) => existing.merge(&incoming),
                slot @ None => {
                    *slot = Some(incoming);
                    true
                }
            };
            if changed && !queued[target] {
                queued[target] = true;
                worklist.push_back(target);
            }
        }
    }

    // Replay each block from its settled entry state for the observer.
    for (b, block) in cfg.blocks.iter().enumerate() {
        let Some(mut frame) = block_in[b].clone() else {
            continue;
        };
        for instruction in &instructions[block.start..block.end] {
            observe(&Site { pool, instruction }, &frame);
            engine.step(instruction, &mut frame);
        }
    }
    true
}

fn entry_frame(
    class_name: &str,
    is_static: bool,
    descriptor: &str,
    max_locals: usize,
    policy: &dyn Policy,
) -> Frame {
    let source = |ty: &str, receiver: bool| {
        let mut value = Value::default();
        if let Some((labels, description)) = policy.parameter(ty, receiver) {
            let origin = Origin {
                offset: 0,
                description: description.into(),
            };
            value.add(labels, Some(&origin));
        }
        value
    };
    let mut frame = Frame::default();
    let mut slot = 0;
    if !is_static {
        frame.set_local(0, source(class_name, true));
        slot = 1;
    }
    for param in MethodType::parse(descriptor).params {
        let mut value = match &param.reference {
            Some(ty) => source(ty, false),
            None => Value::default(),
        };
        value.wide = param.wide;
        frame.set_local(slot, value);
        slot += if param.wide { 2 } else { 1 };
    }
    if frame.locals.len() < max_locals {
        frame.locals.resize(max_locals, Value::default());
    }
    frame
}

/// The state entering an exception handler, which starts with only the
/// thrown exception on the stack.
fn handler_frame(frame: &Frame) -> Frame {
    Frame {
        locals: frame.locals.clone(),
        stack: vec![Value::default()],
    }
}

struct Engine<'r, 'a> {
    pool: &'r ConstantPool<'a>,
    policy: &'r dyn Policy,
}

impl Engine<'_, '_> {
    fn source(&self, found: Option<(Labels, String)>, offset: u32, value: &mut Value) {
        if let Some((labels, description)) = found {
            let origin = Origin {
                offset,
                description: description.into(),
            };
            value.add(labels, Some(&origin));
        }
    }

    fn step(&self, ins: &Instruction, f: &mut Frame) {
        let opcode = ins.opcode;
        match opcode {
            op::NOP | op::IINC | op::GOTO | op::GOTO_W | op::RET | op::RETURN => {}

            op::ACONST_NULL..=op::ICONST_5
            | op::FCONST_0..=op::FCONST_2
            | op::BIPUSH
            | op::SIPUSH => f.push(Value::of_width(false)),
            op::LCONST_0 | op::LCONST_1 | op::DCONST_0 | op::DCONST_1 => {
                f.push(Value::of_width(true))
            }
            op::LDC | op::LDC_W => f.push(Value::of_width(false)),
            op::LDC2_W => f.push(Value::of_width(true)),

            op::ILOAD..=op::ALOAD => {
                if let Operand::Local(n) = ins.operand {
                    let mut value = f.local(usize::from(n));
                    value.wide = matches!(opcode, op::LLOAD | op::DLOAD);
                    f.push(value);
                }
            }
            op::ILOAD_0..=op::ALOAD_3 => {
                let kind = (opcode - op::ILOAD_0) / 4;
                let mut value = f.local(usize::from((opcode - op::ILOAD_0) % 4));
                value.wide = matches!(kind, 1 | 3);
                f.push(value);
            }
            op::ISTORE..=op::ASTORE => {
                if let Operand::Local(n) = ins.operand {
                    store(f, usize::from(n), matches!(opcode, op::LSTORE | op::DSTORE));
                }
            }
            op::ISTORE_0..=op::ASTORE_3 => {
                let kind = (opcode - op::ISTORE_0) / 4;
                store(
                    f,
                    usize::from((opcode - op::ISTORE_0) % 4),
                    matches!(kind, 1 | 3),
                );
            }

            op::IALOAD..=op::SALOAD => {
                f.pop();
                let array = f.pop();
                let mut element =
                    Value::derived([&array], matches!(opcode, op::LALOAD | op::DALOAD));
                element.alloc = None;
                f.push(element);
            }
            op::IASTORE..=op::SASTORE => {
                let value = f.pop();
                f.pop();
                let array = f.pop();
                if let Some(alloc) = &array.alloc {
                    f.taint_alloc(alloc.offset, value.labels, value.origin.as_ref());
                }
            }

            op::POP => {
                f.pop();
            }
            op::POP2 => {
                // One long or double, or two narrower values.
                let first = f.pop();
                if !first.wide {
                    f.pop();
                }
            }
            op::DUP => {
                let top = f.stack.last().cloned().unwrap_or_default();
                f.push(top);
            }
            op::DUP_X1 => {
                let v1 = f.pop();
                let v2 = f.pop();
                f.stack.extend([v1.clone(), v2, v1]);
            }
            op::DUP_X2 => {
                let v1 = f.pop();
                if f.top_is_wide() {
                    let v2 = f.pop();
                    f.stack.extend([v1.clone(), v2, v1]);
                } else {
                    let v2 = f.pop();
                    let v3 = f.pop();
                    f.stack.extend([v1.clone(), v3, v2, v1]);
                }
            }
            op::DUP2 => {
                if f.top_is_wide() {
                    let top = f.stack.last().cloned().unwrap_or_default();
                    f.push(top);
                } else {
                    let v1 = f.pop();
                    let v2 = f.pop();
                    f.stack.extend([v2.clone(), v1.clone(), v2, v1]);
                }
            }
            op::DUP2_X1 => {
                if f.top_is_wide() {
                    let v1 = f.pop();
                    let v2 = f.pop();
                    f.stack.extend([v1.clone(), v2, v1]);
                } else {
                    let v1 = f.pop();
                    let v2 = f.pop();
                    let v3 = f.pop();
                    f.stack.extend([v2.clone(), v1.clone(), v3, v2, v1]);
                }
            }
            op::DUP2_X2 => {
                let v1 = f.pop();
                if v1.wide {
                    let v2 = f.pop();
                    if v2.wide {
                        f.stack.extend([v1.clone(), v2, v1]);
                    } else {
                        let v3 = f.pop();
                        f.stack.extend([v1.clone(), v3, v2, v1]);
                    }
                } else {
                    let v2 = f.pop();
                    let v3 = f.pop();
                    if v3.wide {
                        f.stack.extend([v2.clone(), v1.clone(), v3, v2, v1]);
                    } else {
                        let v4 = f.pop();
                        f.stack.extend([v2.clone(), v1.clone(), v4, v3, v2, v1]);
                    }
                }
            }
            op::SWAP => {
                let v1 = f.pop();
                let v2 = f.pop();
                f.stack.extend([v1, v2]);
            }

            // add, sub, mul, div, rem for int, long, float, double in turn
            op::IADD..=op::DREM => {
                let wide = matches!((opcode - op::IADD) % 4, 1 | 3);
                binary(f, wide);
            }
            op::INEG..=op::DNEG => {
                let operand = f.pop();
                let wide = matches!(opcode - op::INEG, 1 | 3);
                f.push(Value::derived([&operand], wide));
            }
            op::ISHL..=op::LUSHR => {
                let wide = (opcode - op::ISHL) % 2 == 1;
                binary(f, wide);
            }
            op::IAND..=op::LXOR => {
                let wide = (opcode - op::IAND) % 2 == 1;
                binary(f, wide);
            }
            op::I2L..=op::I2S => {
                let operand = f.pop();
                let wide = matches!(
                    opcode,
                    op::I2L | op::I2D | op::L2D | op::F2L | op::F2D | op::D2L
                );
                f.push(Value::derived([&operand], wide));
            }
            op::LCMP..=op::DCMPG => binary(f, false),

            op::IFEQ..=op::IFLE
            | op::IFNULL
            | op::IFNONNULL
            | op::TABLESWITCH
            | op::LOOKUPSWITCH => {
                f.pop();
            }
            op::IF_ICMPEQ..=op::IF_ACMPNE => {
                f.pop();
                f.pop();
            }
            op::JSR | op::JSR_W => f.push(Value::default()),
            op::IRETURN..=op::ARETURN | op::ATHROW | op::MONITORENTER | op::MONITOREXIT => {
                f.pop();
            }

            op::GETSTATIC => f.push(Value::of_width(self.field_is_wide(ins))),
            op::PUTSTATIC => {
                f.pop();
            }
            op::GETFIELD => {
                // A field read from a labeled object carries its labels.
                let object = f.pop();
                f.push(Value::derived([&object], self.field_is_wide(ins)));
            }
            op::PUTFIELD => {
                let value = f.pop();
                let object = f.pop();
                if let Some(alloc) = &object.alloc {
                    f.taint_alloc(alloc.offset, value.labels, value.origin.as_ref());
                }
            }

            op::INVOKEVIRTUAL
            | op::INVOKESPECIAL
            | op::INVOKESTATIC
            | op::INVOKEINTERFACE
            | op::INVOKEDYNAMIC => self.invoke(ins, f),

            op::NEW => {
                let class: Rc<str> = match ins.operand {
                    Operand::Constant(index) => self
                        .pool
                        .class_name(index)
                        .map(Into::into)
                        .unwrap_or_else(|_| "".into()),
                    _ => "".into(),
                };
                let mut value = Value {
                    alloc: Some(Alloc {
                        offset: ins.offset,
                        class: class.clone(),
                    }),
                    ..Value::default()
                };
                self.source(self.policy.allocation(&class), ins.offset, &mut value);
                f.push(value);
            }
            op::NEWARRAY | op::ANEWARRAY | op::MULTIANEWARRAY => {
                let dimensions = match ins.operand {
                    Operand::MultiANewArray { dimensions, .. } => dimensions,
                    _ => 1,
                };
                for _ in 0..dimensions {
                    f.pop();
                }
                f.push(Value {
                    alloc: Some(Alloc {
                        offset: ins.offset,
                        class: "[".into(),
                    }),
                    ..Value::default()
                });
            }
            op::ARRAYLENGTH | op::INSTANCEOF => {
                let operand = f.pop();
                f.push(Value::derived([&operand], false));
            }
            op::CHECKCAST => {}

            _ => {}
        }
    }

    fn field_is_wide(&self, ins: &Instruction) -> bool {
        match ins.operand {
            Operand::Constant(index) => self
                .pool
                .member_ref(index)
                .ok()
                .and_then(|field| field_type(&field.descriptor))
                .is_some_and(|t| t.wide),
            _ => false,
        }
    }

    fn invoke(&self, ins: &Instruction, f: &mut Frame) {
        let index = match ins.operand {
            Operand::Constant(index) | Operand::InvokeInterface { index, .. } => index,
            _ => return,
        };
        let (owner, name, descriptor) = if ins.opcode == op::INVOKEDYNAMIC {
            let Some(&Constant::InvokeDynamic {
                name_and_type_index,
                ..
            }) = self.pool.get(index)
            else {
                return;
            };
            let Ok((name, descriptor)) = self.pool.name_and_type(name_and_type_index) else {
                return;
            };
            (String::new(), name.into_owned(), descriptor.into_owned())
        } else {
            let Ok(target) = self.pool.member_ref(index) else {
                return;
            };
            (
                target.class_name.into_owned(),
                target.name.into_owned(),
                target.descriptor.into_owned(),
            )
        };

        let method = MethodType::parse(&descriptor);
        let mut args: Vec<Value> = method.params.iter().map(|_| f.pop()).collect();
        args.reverse();
        let receiver = match ins.opcode {
            op::INVOKESTATIC | op::INVOKEDYNAMIC => None,
            _ => Some(f.pop()),
        };

        if ins.opcode == op::INVOKESPECIAL && name == "<init>" {
            // A constructor fills in the object `new` created, so its
            // arguments' labels go to every copy of that object.
            if let Some(alloc) = receiver.as_ref().and_then(|r| r.alloc.clone()) {
                for arg in &args {
                    f.taint_alloc(alloc.offset, arg.labels, arg.origin.as_ref());
                }
            }
            return;
        }

        // Reading from a labeled object into an array argument, as in
        // `buf.readBytes(bytes)`, fills that array with labeled data.
        if let Some(receiver) = receiver.as_ref().filter(|r| !r.labels.is_empty()) {
            for (arg, param) in args.iter().zip(&method.params) {
                let is_array = param
                    .reference
                    .as_deref()
                    .is_some_and(|t| t.starts_with('['));
                if let (true, Some(alloc)) = (is_array, &arg.alloc) {
                    f.taint_alloc(alloc.offset, receiver.labels, receiver.origin.as_ref());
                }
            }
        }

        if let Some(returns) = method.returns {
            let mut result = Value::derived(receiver.iter().chain(&args), returns.wide);
            if !owner.is_empty() {
                self.source(
                    self.policy.call(&owner, &name, &descriptor),
                    ins.offset,
                    &mut result,
                );
            }
            f.push(result);
        }
    }
}

fn store(f: &mut Frame, index: usize, wide: bool) {
    let mut value = f.pop();
    value.wide = wide;
    f.set_local(index, value);
    if wide {
        f.set_local(index + 1, Value::default());
    }
}

fn binary(f: &mut Frame, wide: bool) {
    let right = f.pop();
    let left = f.pop();
    f.push(Value::derived([&left, &right], wide));
}
