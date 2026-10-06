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
mod lambda;

use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

pub use descriptor::{JvmType, MethodType, field_type};
pub use lambda::{LambdaTarget, lambda_target};

use crate::class_file::{ClassFile, Constant, ConstantPool, Instruction, Member, Operand, op};
use cfg::Cfg;

const ACC_STATIC: u16 = 0x0008;

/// Bound on block visits per block, so a crafted method with a huge or
/// adversarial control flow graph cannot keep the analysis running.
const MAX_VISITS_PER_BLOCK: usize = 64;

/// A set of source kinds, as bits a policy assigns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Labels(pub u64);

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
    /// The labels came with one of the method's parameters, so they are
    /// whatever the caller passed rather than something the method reads.
    pub parameter: bool,
}

/// The instruction that produced an object or array, a `new` or a call
/// returning it. Copies of a reference share it, so labels added through one
/// copy reach the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alloc {
    /// The instruction's offset, identifying the object it created most
    /// recently. With [`OLDER`] set it stands for every earlier object from
    /// that instruction instead, as in a loop that creates one per pass.
    pub offset: u32,
    /// Internal name of the class, or the array descriptor. For an object a
    /// call returned, its declared return type.
    pub class: Rc<str>,
    /// The method created the object itself with `new`, rather than getting
    /// it back from a call.
    pub made: bool,
}

/// Final JDK classes whose instances never change, so nothing written into
/// them needs following.
const IMMUTABLE: &[&str] = &[
    "java/lang/String",
    "java/lang/Integer",
    "java/lang/Long",
    "java/lang/Short",
    "java/lang/Byte",
    "java/lang/Character",
    "java/lang/Boolean",
    "java/lang/Double",
    "java/lang/Float",
    "java/lang/Class",
];

/// Marks an allocation offset as standing for the earlier objects from its
/// instruction. Offsets within a method never reach this bit.
pub const OLDER: u32 = 1 << 31;

impl Alloc {
    /// The offset of the instruction that created the object.
    pub fn site(&self) -> u32 {
        self.offset & !OLDER
    }
}

/// A value the bytecode pins down on every path, such as `iconst_0` or a
/// static field read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known {
    Int(i32),
    /// A static field, as `owner.name`.
    Static(Rc<str>),
    /// A class constant, as its internal name.
    Class(Rc<str>),
    /// The function object a lambda or method reference creates, by the
    /// constant pool index of its `invokedynamic` call site.
    Lambda(u16),
    /// The result of a static method that takes no arguments, as
    /// `owner.name`, such as a registry accessor.
    Call(Rc<str>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Value {
    pub labels: Labels,
    /// The method's own parameters this value is computed from, one bit per
    /// declared parameter index. Parameters past the 64th are not tracked.
    pub params: u64,
    /// The value is computed from the method's receiver.
    pub receiver: bool,
    pub origin: Option<Origin>,
    pub alloc: Option<Alloc>,
    /// The field this value was read from, as `owner.name`, for as long as
    /// it is the same object. A call that stores into that object, such as
    /// adding to a list, stores into the field.
    pub field: Option<Rc<str>>,
    /// Kept only while every path that reaches this point agrees on it.
    pub known: Option<Known>,
    /// The static type of the value, as an internal name or array
    /// descriptor, from a cast, a declared type, or the class it was created
    /// from. Kept only while every path agrees on it.
    pub ty: Option<Rc<str>>,
    /// The index of the declared parameter this value still is, unchanged,
    /// while every path agrees on it.
    pub param: Option<usize>,
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

    fn known(known: Known) -> Self {
        Self {
            known: Some(known),
            ..Self::default()
        }
    }

    /// A new value computed from `inputs`, carrying all of their labels and
    /// parameters.
    fn derived<'v>(inputs: impl IntoIterator<Item = &'v Value>, wide: bool) -> Self {
        let mut out = Self::of_width(wide);
        for input in inputs {
            out.absorb(input);
        }
        out
    }

    /// Adds another value's labels and parameters to this one.
    fn absorb(&mut self, other: &Value) {
        self.add(other.labels, other.origin.as_ref());
        self.params |= other.params;
        self.receiver |= other.receiver;
    }

    /// True when the value carries labels or comes from a parameter.
    pub fn carries_anything(&self) -> bool {
        !self.labels.is_empty() || self.params != 0
    }

    /// The method inputs this value is computed from.
    pub fn inputs(&self) -> Inputs {
        Inputs {
            params: self.params,
            receiver: self.receiver,
        }
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
            self.params,
            self.receiver,
            self.origin.is_some(),
            self.alloc.as_ref().map(|a| (a.offset, a.made)),
            self.field.is_some(),
            self.known.is_some(),
            self.ty.is_some(),
            self.param.is_some(),
            self.wide,
        );
        self.absorb(other);
        // Where paths bring different objects, one the method created
        // itself is kept, as the value is that object on at least one path.
        let replace = match (&self.alloc, &other.alloc) {
            (None, Some(_)) => true,
            (Some(mine), Some(theirs)) => !mine.made && theirs.made,
            _ => false,
        };
        if replace {
            self.alloc = other.alloc.clone();
        }
        if self.field.is_none() {
            self.field = other.field.clone();
        }
        if self.known != other.known {
            self.known = None;
        }
        if self.ty != other.ty {
            self.ty = None;
        }
        if self.param != other.param {
            self.param = None;
        }
        self.wide |= other.wide;
        before
            != (
                self.labels,
                self.params,
                self.receiver,
                self.origin.is_some(),
                self.alloc.as_ref().map(|a| (a.offset, a.made)),
                self.field.is_some(),
                self.known.is_some(),
                self.ty.is_some(),
                self.param.is_some(),
                self.wide,
            )
    }
}

/// The locals and operand stack at one point in a method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub locals: Vec<Value>,
    pub stack: Vec<Value>,
    /// Objects built around other objects, as (wrapper, wrapped) allocation
    /// offsets, such as an ObjectOutputStream over a ByteArrayOutputStream.
    /// Data written into a wrapper also reaches what it wraps.
    pub wraps: Vec<(u32, u32)>,
    /// Allocation offsets of objects that may have been written after they
    /// were created, or that left the method's hands where something else
    /// could write them, such as a call receiving them or a field store.
    pub written: Vec<u32>,
}

impl Frame {
    /// Makes room for a new object from the instruction at `site`. The
    /// object it created before joins the earlier ones, keeping what was
    /// recorded about it, and the new object starts with nothing recorded.
    fn retire(&mut self, site: u32) {
        let held = self
            .locals
            .iter()
            .chain(&self.stack)
            .any(|v| v.alloc.as_ref().is_some_and(|a| a.offset == site));
        let linked = self.wraps.iter().any(|&(w, i)| w == site || i == site);
        if !held && !linked && !self.written.contains(&site) {
            return;
        }
        let older = site | OLDER;
        for value in self.locals.iter_mut().chain(self.stack.iter_mut()) {
            if let Some(alloc) = value.alloc.as_mut()
                && alloc.offset == site
            {
                alloc.offset = older;
            }
        }
        let retired = |offset: u32| if offset == site { older } else { offset };
        let mut wraps: Vec<(u32, u32)> = Vec::with_capacity(self.wraps.len());
        for &(wrapper, wrapped) in &self.wraps {
            let link = (retired(wrapper), retired(wrapped));
            if !wraps.contains(&link) {
                wraps.push(link);
            }
        }
        self.wraps = wraps;
        if let Some(position) = self.written.iter().position(|o| *o == site) {
            self.written.remove(position);
            if !self.written.contains(&older) {
                self.written.push(older);
            }
        }
    }

    /// Records that the object created at `alloc`, and everything it wraps,
    /// may have been written.
    fn mark_written(&mut self, alloc: u32) {
        let mut pending = vec![alloc];
        while let Some(current) = pending.pop() {
            if self.written.contains(&current) {
                continue;
            }
            self.written.push(current);
            pending.extend(
                self.wraps
                    .iter()
                    .filter(|(wrapper, _)| *wrapper == current)
                    .map(|(_, wrapped)| *wrapped),
            );
        }
    }

    /// Only objects the method created are tracked, as only those can be
    /// shown to be empty, and only they can wrap other objects.
    fn mark_value_written(&mut self, value: &Value) {
        if let Some(alloc) = value.alloc.as_ref().filter(|a| a.made) {
            self.mark_written(alloc.offset);
        }
    }

    /// True when the object created at `alloc` is built only around arrays
    /// this method created and nothing has written since, so any data read
    /// from it is all zeros. Objects whose class no value here records do
    /// not count.
    pub fn holds_only_empty_arrays(&self, alloc: u32) -> bool {
        let mut pending = vec![alloc];
        let mut seen = Vec::new();
        while let Some(current) = pending.pop() {
            if seen.contains(&current) {
                continue;
            }
            seen.push(current);
            if self.written.contains(&current) {
                return false;
            }
            let inner: Vec<u32> = self
                .wraps
                .iter()
                .filter(|(wrapper, _)| *wrapper == current)
                .map(|(_, wrapped)| *wrapped)
                .collect();
            if inner.is_empty() {
                let is_array = self
                    .locals
                    .iter()
                    .chain(&self.stack)
                    .filter_map(|v| v.alloc.as_ref())
                    .find(|a| a.offset == current)
                    .is_some_and(|a| a.made && a.class.starts_with('['));
                if !is_array {
                    return false;
                }
            }
            pending.extend(inner);
        }
        true
    }

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

    /// Adds the labels and parameters of `from` to every copy of the object
    /// created at `alloc`.
    fn taint_alloc(&mut self, alloc: u32, from: &Value) {
        // Each object is tainted once, so cycles in the links end.
        let mut pending = vec![alloc];
        let mut done = Vec::new();
        while let Some(current) = pending.pop() {
            if done.contains(&current) {
                continue;
            }
            done.push(current);
            for value in self.locals.iter_mut().chain(self.stack.iter_mut()) {
                if value.alloc.as_ref().is_some_and(|a| a.offset == current) {
                    value.absorb(from);
                }
            }
            pending.extend(
                self.wraps
                    .iter()
                    .filter(|(wrapper, _)| *wrapper == current)
                    .map(|(_, wrapped)| *wrapped),
            );
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
        for link in &other.wraps {
            if !self.wraps.contains(link) {
                self.wraps.push(*link);
                changed = true;
            }
        }
        for alloc in &other.written {
            if !self.written.contains(alloc) {
                self.written.push(*alloc);
                changed = true;
            }
        }
        changed
    }
}

/// Which of a method's inputs a value is computed from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Inputs {
    /// One bit per declared parameter index.
    pub params: u64,
    pub receiver: bool,
}

impl Inputs {
    pub fn union(self, other: Inputs) -> Inputs {
        Inputs {
            params: self.params | other.params,
            receiver: self.receiver || other.receiver,
        }
    }
}

/// Decides which values are sources and with which labels.
pub trait Policy {
    /// Labels for a parameter of type `ty`, an internal name or array
    /// descriptor. `index` counts declared parameters from zero and is
    /// `None` for `this`, whose type is the class being analyzed.
    fn parameter(&self, index: Option<usize>, ty: &str) -> Option<(Labels, String)>;
    /// Labels added to the result of calling a method.
    /// `site` is the call's offset, the same on every pass over the method.
    fn call(
        &self,
        _site: u32,
        _owner: &str,
        _name: &str,
        _descriptor: &str,
    ) -> Option<(Labels, String)> {
        None
    }
    /// Labels for an object created with `new`.
    fn allocation(&self, _class: &str) -> Option<(Labels, String)> {
        None
    }
    /// Labels for a value read from a static field because of what the field
    /// was initialized with, such as an embedded constant.
    fn static_field(&self, _owner: &str, _name: &str) -> Option<(Labels, String)> {
        None
    }
    /// Labels for a value read from a field, static or not, because of its
    /// declared type or what code elsewhere stores in it.
    fn field(&self, _owner: &str, _name: &str, _descriptor: &str) -> Option<(Labels, String)> {
        None
    }
    /// The inputs a call's result is computed from, when known to be fewer
    /// than all of them. `site` is the call's offset, the same on every pass
    /// over the method, and `dispatches` is set for calls that can reach an
    /// override.
    fn result_inputs(
        &self,
        _site: u32,
        _owner: &str,
        _name: &str,
        _descriptor: &str,
        _dispatches: bool,
    ) -> Option<Inputs> {
        None
    }
    /// Labels returned by the body of the lambda or method reference made at
    /// the `invokedynamic` call site at constant pool `index`. A call handed
    /// that function object, such as a stream's `map`, can return them.
    fn lambda_result(&self, _index: u16) -> Option<(Labels, String)> {
        None
    }
    /// Labels for what a call writes into its receiver in place of what its
    /// arguments carry, such as a serializer recording an object's classes.
    fn serializes(&self, _owner: &str, _name: &str, _descriptor: &str) -> Option<(Labels, String)> {
        None
    }
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
    let Some(settled) = settle(class, method, policy) else {
        return false;
    };
    settled.replay(policy, &mut |site, frame| observe(site, frame));
    true
}

/// A method's instructions and control flow, with the settled state at the
/// start of every reachable block.
struct Settled<'p, 'a> {
    pool: &'p ConstantPool<'a>,
    instructions: Vec<Instruction>,
    cfg: Cfg,
    block_in: Vec<Option<Frame>>,
}

impl Settled<'_, '_> {
    /// Steps through each reachable block from its settled entry state,
    /// calling `observe` before every instruction. Returns the state at the
    /// end of each block.
    fn replay(
        &self,
        policy: &dyn Policy,
        observe: &mut dyn FnMut(&Site, &Frame),
    ) -> Vec<Option<Frame>> {
        let engine = Engine {
            pool: self.pool,
            policy,
        };
        let mut block_out = vec![None; self.cfg.blocks.len()];
        for (b, block) in self.cfg.blocks.iter().enumerate() {
            let Some(mut frame) = self.block_in[b].clone() else {
                continue;
            };
            for instruction in &self.instructions[block.start..block.end] {
                observe(
                    &Site {
                        pool: self.pool,
                        instruction,
                    },
                    &frame,
                );
                engine.step(instruction, &mut frame);
            }
            block_out[b] = Some(frame);
        }
        block_out
    }
}

/// Runs the data flow over one method until its state stops changing.
fn settle<'p, 'a>(
    class: &'p ClassFile<'a>,
    method: &Member,
    policy: &dyn Policy,
) -> Option<Settled<'p, 'a>> {
    let pool = &class.constant_pool;
    let code = method.code(pool).ok()??;
    let instructions = code.instructions().collect::<Result<Vec<_>, _>>().ok()?;
    if instructions.is_empty() {
        return None;
    }
    let descriptor = method.descriptor(pool).ok()?;
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

    Some(Settled {
        pool,
        instructions,
        cfg,
        block_in,
    })
}

/// Where one outcome of a branch can lead along normal control flow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reach {
    pub throws: bool,
    pub returns: bool,
}

/// A conditional branch on a value carrying the labels asked for, read as a
/// lookup. Comparisons that come out false or zero, null results, negative
/// indexes, inequality, and the default of a switch count as not found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub offset: u32,
    pub found: Reach,
    pub not_found: Reach,
}

/// A call whose arguments carry the labels asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabeledCall {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    /// Indexes of the labeled arguments, counting declared parameters.
    pub arguments: Vec<usize>,
}

/// A method settled under a policy, with the branches, calls, and returns
/// that involve one set of labels.
struct Lookups<'p, 'a> {
    settled: Settled<'p, 'a>,
    /// Offsets of conditional branches that test labeled values.
    tested: Vec<u32>,
    /// Offsets of returns that return a labeled value, or any value for
    /// returns of primitives and `void`.
    exits: Vec<u32>,
    calls: Vec<(u32, LabeledCall)>,
    /// Edges rerouted by jump threading, from (block, successor) to the
    /// block the edge really continues in.
    threaded: HashMap<(usize, usize), usize>,
}

impl<'p, 'a> Lookups<'p, 'a> {
    fn new(
        class: &'p ClassFile<'a>,
        method: &Member,
        policy: &dyn Policy,
        labels: Labels,
    ) -> Option<Self> {
        let settled = settle(class, method, policy)?;
        let labeled = |value: Option<&Value>| value.is_some_and(|v| v.labels.0 & labels.0 != 0);
        let (mut tested, mut exits, mut calls) = (Vec::new(), Vec::new(), Vec::new());
        let block_out = settled.replay(policy, &mut |site, frame| {
            let ins = site.instruction;
            match ins.opcode {
                op::IFEQ..=op::IFLE
                | op::IFNULL
                | op::IFNONNULL
                | op::TABLESWITCH
                | op::LOOKUPSWITCH
                    if labeled(frame.peek(0)) =>
                {
                    tested.push(ins.offset)
                }
                op::IF_ICMPEQ..=op::IF_ACMPNE
                    if labeled(frame.peek(0)) || labeled(frame.peek(1)) =>
                {
                    tested.push(ins.offset)
                }
                op::ARETURN if labeled(frame.peek(0)) => exits.push(ins.offset),
                op::IRETURN..=op::DRETURN | op::RETURN => exits.push(ins.offset),
                op::INVOKEVIRTUAL | op::INVOKESPECIAL | op::INVOKESTATIC | op::INVOKEINTERFACE => {
                    let index = match ins.operand {
                        Operand::Constant(index) | Operand::InvokeInterface { index, .. } => index,
                        _ => return,
                    };
                    let Ok(target) = site.pool.member_ref(index) else {
                        return;
                    };
                    let count = MethodType::parse(&target.descriptor).params.len();
                    let arguments: Vec<usize> = (0..count)
                        .filter(|i| labeled(frame.peek(count - 1 - i)))
                        .collect();
                    if !arguments.is_empty() {
                        calls.push((
                            ins.offset,
                            LabeledCall {
                                owner: target.class_name.into_owned(),
                                name: target.name.into_owned(),
                                descriptor: target.descriptor.into_owned(),
                                arguments,
                            },
                        ));
                    }
                }
                _ => {}
            }
        });
        let threaded = thread_edges(&settled, policy, &block_out);
        Some(Self {
            settled,
            tested,
            exits,
            calls,
            threaded,
        })
    }

    fn block_at(&self, offset: i64) -> Option<usize> {
        let instructions = &self.settled.instructions;
        self.settled
            .cfg
            .blocks
            .iter()
            .position(|b| i64::from(instructions[b.start].offset) == offset)
    }

    fn thread(&self, from: usize, to: usize) -> usize {
        self.threaded.get(&(from, to)).copied().unwrap_or(to)
    }

    /// For a block ending in a branch on a labeled value, the blocks each
    /// outcome continues in, as (found, not found).
    fn outcomes(&self, b: usize) -> Option<(Vec<usize>, Vec<usize>)> {
        let (instructions, cfg) = (&self.settled.instructions, &self.settled.cfg);
        let block = &cfg.blocks[b];
        let ins = &instructions[block.end - 1];
        if !self.tested.contains(&ins.offset) {
            return None;
        }
        let next = (block.end < instructions.len()).then_some(b + 1);
        let (found, not_found): (Vec<Option<usize>>, Vec<Option<usize>>) =
            match (ins.opcode, &ins.operand) {
                (
                    op::TABLESWITCH,
                    Operand::TableSwitch {
                        default, targets, ..
                    },
                ) => (
                    targets.iter().map(|t| self.block_at(*t)).collect(),
                    vec![self.block_at(*default)],
                ),
                (op::LOOKUPSWITCH, Operand::LookupSwitch { default, pairs }) => (
                    pairs.iter().map(|(_, t)| self.block_at(*t)).collect(),
                    vec![self.block_at(*default)],
                ),
                (opcode, Operand::Branch(target)) => {
                    let taken = self.block_at(*target);
                    match opcode {
                        op::IFNE | op::IFGE | op::IFNONNULL | op::IF_ICMPEQ | op::IF_ACMPEQ => {
                            (vec![taken], vec![next])
                        }
                        op::IFEQ | op::IFLT | op::IFNULL | op::IF_ICMPNE | op::IF_ACMPNE => {
                            (vec![next], vec![taken])
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            };
        let resolve = |blocks: Vec<Option<usize>>| -> Vec<usize> {
            blocks
                .into_iter()
                .flatten()
                .map(|to| self.thread(b, to))
                .collect()
        };
        Some((resolve(found), resolve(not_found)))
    }
}

/// Jump threading. Compilers turn a string switch, and code that sets a flag
/// and tests it later, into branches that store constants and a later block
/// that branches on them. The merged state at that block loses the constant,
/// so each edge is replayed through its target block from the state at the
/// end of its source, and when the tested value comes out constant the edge
/// goes straight to the branch it picks.
fn thread_edges(
    settled: &Settled,
    policy: &dyn Policy,
    block_out: &[Option<Frame>],
) -> HashMap<(usize, usize), usize> {
    let (instructions, cfg) = (&settled.instructions, &settled.cfg);
    let engine = Engine {
        pool: settled.pool,
        policy,
    };
    let block_at = |offset: i64| {
        cfg.blocks
            .iter()
            .position(|b| i64::from(instructions[b.start].offset) == offset)
    };
    let thread_edge = |from: usize, to: usize| -> usize {
        let Some(mut frame) = block_out[from].clone() else {
            return to;
        };
        let block = &cfg.blocks[to];
        for ins in &instructions[block.start..block.end - 1] {
            engine.step(ins, &mut frame);
        }
        let int = |depth: usize| match frame.peek(depth).map(|v| &v.known) {
            Some(Some(Known::Int(value))) => Some(*value),
            _ => None,
        };
        let test = &instructions[block.end - 1];
        let target = match (test.opcode, &test.operand) {
            (
                op::TABLESWITCH,
                Operand::TableSwitch {
                    default,
                    low,
                    targets,
                },
            ) => {
                let Some(value) = int(0) else {
                    return to;
                };
                usize::try_from(i64::from(value) - i64::from(*low))
                    .ok()
                    .and_then(|i| targets.get(i))
                    .copied()
                    .unwrap_or(*default)
            }
            (op::LOOKUPSWITCH, Operand::LookupSwitch { default, pairs }) => {
                let Some(value) = int(0) else {
                    return to;
                };
                pairs
                    .iter()
                    .find(|(key, _)| *key == value)
                    .map_or(*default, |(_, target)| *target)
            }
            (opcode, Operand::Branch(target)) => {
                let taken = match opcode {
                    op::IFEQ..=op::IFLE => {
                        let Some(value) = int(0) else {
                            return to;
                        };
                        compare(opcode - op::IFEQ, value, 0)
                    }
                    op::IF_ICMPEQ..=op::IF_ICMPLE => {
                        let (Some(left), Some(right)) = (int(1), int(0)) else {
                            return to;
                        };
                        compare(opcode - op::IF_ICMPEQ, left, right)
                    }
                    _ => return to,
                };
                if !taken {
                    return if to + 1 < cfg.blocks.len() {
                        to + 1
                    } else {
                        to
                    };
                }
                *target
            }
            _ => return to,
        };
        block_at(target).unwrap_or(to)
    };
    cfg.blocks
        .iter()
        .enumerate()
        .flat_map(|(b, block)| block.successors.iter().map(move |&to| (b, to)))
        .map(|(b, to)| ((b, to), thread_edge(b, to)))
        .collect()
}

/// The conditional branches in a method that test values carrying any of
/// `labels`, with whether each outcome can end in a throw or a return.
/// Branches whose outcomes cannot be read as found or not found, such as
/// `ifgt`, are left out.
pub fn decisions(
    class: &ClassFile,
    method: &Member,
    policy: &dyn Policy,
    labels: Labels,
) -> Vec<Decision> {
    let Some(lookups) = Lookups::new(class, method, policy, labels) else {
        return Vec::new();
    };
    let (instructions, cfg) = (&lookups.settled.instructions, &lookups.settled.cfg);
    let thread = |from: usize, to: usize| lookups.thread(from, to);
    let mut out = Vec::new();
    for b in 0..cfg.blocks.len() {
        let Some((found, not_found)) = lookups.outcomes(b) else {
            continue;
        };
        // An outcome is judged without passing this branch again, so a loop
        // that tries the next candidate after a miss does not count the
        // next candidate's hit as part of the miss.
        let reach = cfg.reach(instructions, &thread, b);
        let combine = |blocks: &[usize]| {
            blocks.iter().fold(Reach::default(), |acc, &to| Reach {
                throws: acc.throws || reach[to].throws,
                returns: acc.returns || reach[to].returns,
            })
        };
        out.push(Decision {
            offset: instructions[cfg.blocks[b].end - 1].offset,
            found: combine(&found),
            not_found: combine(&not_found),
        });
    }
    out
}

/// True when the method can finish normally without any lookup on a labeled
/// value succeeding. That holds when some path from entry, taking only the
/// not found outcomes of branches on labeled values and including paths
/// through exception handlers, reaches a return of a labeled value, or any
/// return when the method returns a primitive or nothing. Calls that
/// `guards` accepts stop a path, as they cannot return without their own
/// lookup succeeding.
pub fn finishes_unguarded(
    class: &ClassFile,
    method: &Member,
    policy: &dyn Policy,
    labels: Labels,
    guards: &mut dyn FnMut(&LabeledCall) -> bool,
) -> bool {
    finishes(class, method, policy, labels, guards, true)
}

/// True when the method can finish normally without any branch on a
/// labeled value on the way, so it never looks at the value at all. Calls
/// that `guards` accepts stop a path, as in [`finishes_unguarded`].
pub fn finishes_unchecked(
    class: &ClassFile,
    method: &Member,
    policy: &dyn Policy,
    labels: Labels,
    guards: &mut dyn FnMut(&LabeledCall) -> bool,
) -> bool {
    finishes(class, method, policy, labels, guards, false)
}

/// The path search behind [`finishes_unguarded`] and [`finishes_unchecked`].
/// `through_misses` decides whether a branch on a labeled value lets a path
/// continue through its not found outcome, or stops it.
fn finishes(
    class: &ClassFile,
    method: &Member,
    policy: &dyn Policy,
    labels: Labels,
    guards: &mut dyn FnMut(&LabeledCall) -> bool,
    through_misses: bool,
) -> bool {
    let Some(lookups) = Lookups::new(class, method, policy, labels) else {
        return false;
    };
    let guard_offsets: Vec<u32> = lookups
        .calls
        .iter()
        .filter(|(_, call)| guards(call))
        .map(|(offset, _)| *offset)
        .collect();
    let (instructions, cfg) = (&lookups.settled.instructions, &lookups.settled.cfg);

    let mut visited = vec![false; cfg.blocks.len()];
    let mut queue = vec![0usize];
    while let Some(b) = queue.pop() {
        if std::mem::replace(&mut visited[b], true) {
            continue;
        }
        let block = &cfg.blocks[b];
        let mut stopped = false;
        let span = block.start..block.end;
        for (ins, handlers) in instructions[span.clone()].iter().zip(&cfg.handlers[span]) {
            // An exception at any instruction, a guard included, leaves for
            // the handlers covering it.
            queue.extend(handlers.iter().copied());
            let offset = ins.offset;
            if lookups.exits.contains(&offset) {
                return true;
            }
            if guard_offsets.contains(&offset) {
                stopped = true;
                break;
            }
        }
        if stopped {
            continue;
        }
        match lookups.outcomes(b) {
            Some((_, not_found)) if through_misses => queue.extend(not_found),
            Some(_) => {}
            None => queue.extend(block.successors.iter().map(|&s| lookups.thread(b, s))),
        }
    }
    false
}

/// Applies one of the six int comparisons, in opcode order: equal, not
/// equal, less, greater or equal, greater, less or equal.
fn compare(which: u8, left: i32, right: i32) -> bool {
    match which {
        0 => left == right,
        1 => left != right,
        2 => left < right,
        3 => left >= right,
        4 => left > right,
        _ => left <= right,
    }
}

fn entry_frame(
    class_name: &str,
    is_static: bool,
    descriptor: &str,
    max_locals: usize,
    policy: &dyn Policy,
) -> Frame {
    let source = |index: Option<usize>, ty: &str| {
        let mut value = Value::default();
        if let Some((labels, description)) = policy.parameter(index, ty) {
            let origin = Origin {
                offset: 0,
                description: description.into(),
                parameter: true,
            };
            value.add(labels, Some(&origin));
        }
        value
    };
    let mut frame = Frame::default();
    let mut slot = 0;
    if !is_static {
        let mut receiver = source(None, class_name);
        receiver.ty = Some(class_name.into());
        receiver.receiver = true;
        frame.set_local(0, receiver);
        slot = 1;
    }
    for (index, param) in MethodType::parse(descriptor).params.into_iter().enumerate() {
        let mut value = match &param.reference {
            Some(ty) => source(Some(index), ty),
            None => Value::default(),
        };
        value.ty = param.reference.as_deref().map(Into::into);
        value.param = Some(index);
        if index < 64 {
            value.params = 1 << index;
        }
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
        wraps: frame.wraps.clone(),
        written: frame.written.clone(),
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
                parameter: false,
            };
            value.add(labels, Some(&origin));
        }
    }

    fn step(&self, ins: &Instruction, f: &mut Frame) {
        let opcode = ins.opcode;
        match opcode {
            op::NOP | op::IINC | op::GOTO | op::GOTO_W | op::RET | op::RETURN => {}

            op::ICONST_M1..=op::ICONST_5 => f.push(Value::known(Known::Int(
                i32::from(opcode) - i32::from(op::ICONST_0),
            ))),
            op::BIPUSH | op::SIPUSH => match ins.operand {
                Operand::Immediate(value) => f.push(Value::known(Known::Int(value))),
                _ => f.push(Value::of_width(false)),
            },
            op::ACONST_NULL | op::FCONST_0..=op::FCONST_2 => f.push(Value::of_width(false)),
            op::LCONST_0 | op::LCONST_1 | op::DCONST_0 | op::DCONST_1 => {
                f.push(Value::of_width(true))
            }
            op::LDC | op::LDC_W => {
                let mut value = Value::of_width(false);
                if let Operand::Constant(index) = ins.operand {
                    match self.pool.get(index) {
                        Some(Constant::Class { .. }) => {
                            if let Ok(name) = self.pool.class_name(index) {
                                value.known = Some(Known::Class(name.into()));
                            }
                            value.ty = Some("java/lang/Class".into());
                        }
                        Some(Constant::String { .. }) => value.ty = Some("java/lang/String".into()),
                        _ => {}
                    }
                }
                f.push(value);
            }
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
                    f.taint_alloc(alloc.offset, &value);
                }
                f.mark_value_written(&array);
                f.mark_value_written(&value);
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

            op::GETSTATIC => {
                let mut value = Value::of_width(self.field_is_wide(ins));
                if let Operand::Constant(index) = ins.operand
                    && let Ok(field) = self.pool.member_ref(index)
                {
                    let name: Rc<str> = format!("{}.{}", field.class_name, field.name).into();
                    value.known = Some(Known::Static(name.clone()));
                    value.field = Some(name);
                    value.ty = field_type(&field.descriptor)
                        .and_then(|t| t.reference)
                        .map(Into::into);
                    let found = self.policy.static_field(&field.class_name, &field.name);
                    self.source(found, ins.offset, &mut value);
                    let stored =
                        self.policy
                            .field(&field.class_name, &field.name, &field.descriptor);
                    self.source(stored, ins.offset, &mut value);
                }
                f.push(value);
            }
            op::PUTSTATIC => {
                let value = f.pop();
                f.mark_value_written(&value);
            }
            op::GETFIELD => {
                // A field read from a labeled object carries its labels, and
                // a field the policy knows to hold untrusted data carries
                // those too.
                let object = f.pop();
                let mut value = Value::derived([&object], self.field_is_wide(ins));
                if let Operand::Constant(index) = ins.operand
                    && let Ok(field) = self.pool.member_ref(index)
                {
                    let stored =
                        self.policy
                            .field(&field.class_name, &field.name, &field.descriptor);
                    self.source(stored, ins.offset, &mut value);
                    value.field = Some(format!("{}.{}", field.class_name, field.name).into());
                    value.ty = field_type(&field.descriptor)
                        .and_then(|t| t.reference)
                        .map(Into::into);
                }
                f.push(value);
            }
            op::PUTFIELD => {
                let value = f.pop();
                let object = f.pop();
                if let Some(alloc) = &object.alloc {
                    f.taint_alloc(alloc.offset, &value);
                }
                f.mark_value_written(&object);
                f.mark_value_written(&value);
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
                f.retire(ins.offset);
                let mut value = Value {
                    alloc: Some(Alloc {
                        offset: ins.offset,
                        class: class.clone(),
                        made: true,
                    }),
                    ty: (!class.is_empty()).then(|| class.clone()),
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
                f.retire(ins.offset);
                f.push(Value {
                    alloc: Some(Alloc {
                        offset: ins.offset,
                        class: "[".into(),
                        made: true,
                    }),
                    ..Value::default()
                });
            }
            op::ARRAYLENGTH | op::INSTANCEOF => {
                let operand = f.pop();
                f.push(Value::derived([&operand], false));
            }
            op::CHECKCAST => {
                // A cast that succeeds pins the type, and the value is
                // otherwise unchanged.
                if let Operand::Constant(index) = ins.operand
                    && let Ok(name) = self.pool.class_name(index)
                    && let Some(top) = f.stack.last_mut()
                {
                    top.ty = Some(name.into());
                }
            }

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
            // arguments' labels go to every copy of that object. An object
            // built around another one wraps it from then on.
            if let Some(alloc) = receiver.as_ref().and_then(|r| r.alloc.clone()) {
                for arg in &args {
                    f.taint_alloc(alloc.offset, arg);
                    if let Some(inner) = &arg.alloc {
                        let link = (alloc.offset, inner.offset);
                        if inner.offset != alloc.offset && !f.wraps.contains(&link) {
                            f.wraps.push(link);
                        }
                    }
                }
            }
            return;
        }

        // Any other call can write the objects it is handed, including its
        // receiver and what they wrap.
        for value in receiver.iter().chain(&args) {
            f.mark_value_written(value);
        }

        // A serializer writes a description of the object into the stream
        // it was built over, carrying its own source in place of the
        // object's data.
        if !owner.is_empty()
            && let Some(found) = self.policy.serializes(&owner, &name, &descriptor)
        {
            if let Some(alloc) = receiver.as_ref().and_then(|r| r.alloc.as_ref()) {
                let mut written = Value::default();
                self.source(Some(found), ins.offset, &mut written);
                f.taint_alloc(alloc.offset, &written);
            }
            if let Some(returns) = method.returns {
                f.push(Value::of_width(returns.wide));
            }
            return;
        }

        // A call can fill any object it is handed from its other inputs, as
        // in `buf.readBytes(bytes)` from the receiver,
        // `System.arraycopy(source, 0, bytes, 0, n)` from another argument,
        // or `out.write(data)` into the receiver.
        let inputs = Value::derived(receiver.iter().chain(&args), false);
        if inputs.carries_anything() {
            for arg in &args {
                if let Some(alloc) = &arg.alloc {
                    f.taint_alloc(alloc.offset, &inputs);
                }
            }
        }
        let arguments = Value::derived(&args, false);
        if let Some(alloc) = receiver.as_ref().and_then(|r| r.alloc.as_ref())
            && arguments.carries_anything()
        {
            f.taint_alloc(alloc.offset, &arguments);
        }

        if let Some(returns) = method.returns {
            let dispatches = matches!(ins.opcode, op::INVOKEVIRTUAL | op::INVOKEINTERFACE);
            let known = (!owner.is_empty())
                .then(|| {
                    self.policy
                        .result_inputs(ins.offset, &owner, &name, &descriptor, dispatches)
                })
                .flatten();
            let mut result = match known {
                // Only the inputs the callee's returned value comes from.
                Some(inputs) => Value::derived(
                    receiver.iter().filter(|_| inputs.receiver).chain(
                        args.iter()
                            .enumerate()
                            .filter(|(i, _)| *i < 64 && inputs.params & (1 << i) != 0)
                            .map(|(_, arg)| arg),
                    ),
                    returns.wide,
                ),
                None => Value::derived(receiver.iter().chain(&args), returns.wide),
            };
            result.ty = returns.reference.as_deref().map(Into::into);
            // A method returning its own class is taken to return the
            // receiver, as fluent setters and builders do, so settings
            // chained onto a new object still reach it.
            if returns.reference.as_deref() == Some(owner.as_str()) {
                result.alloc = receiver.as_ref().and_then(|r| r.alloc.clone());
            }
            // Any other object a call returns gets an identity of its own, so
            // what is written into it later, such as a buffer filled after
            // ByteBuffer.allocate, stays with it.
            if result.alloc.is_none()
                && let Some(class) = returns.reference.as_deref()
                && !IMMUTABLE.contains(&class)
            {
                f.retire(ins.offset);
                result.alloc = Some(Alloc {
                    offset: ins.offset,
                    class: class.into(),
                    made: false,
                });
            }
            result.known = match ins.opcode {
                op::INVOKEDYNAMIC => Some(Known::Lambda(index)),
                op::INVOKESTATIC if args.is_empty() => {
                    Some(Known::Call(format!("{owner}.{name}").into()))
                }
                // Optional.of only wraps its argument, so a constant passed
                // through it, such as a packet direction, stays visible.
                op::INVOKESTATIC if owner == "java/util/Optional" && name == "of" => {
                    args.first().and_then(|a| a.known.clone())
                }
                _ => None,
            };
            if !owner.is_empty() {
                self.source(
                    self.policy.call(ins.offset, &owner, &name, &descriptor),
                    ins.offset,
                    &mut result,
                );
            }
            for arg in &args {
                if let Some(Known::Lambda(index)) = arg.known {
                    self.source(self.policy.lambda_result(index), ins.offset, &mut result);
                }
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
