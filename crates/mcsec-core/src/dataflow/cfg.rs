//! Splitting a method's instructions into basic blocks joined by control flow.

use std::collections::{BTreeSet, HashMap};

use crate::class_file::{ExceptionHandler, Instruction, Operand, op};

/// A run of instructions with one entry and one exit, by instruction index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    /// Blocks reached by falling through or branching, by block index.
    pub successors: Vec<usize>,
}

#[derive(Debug)]
pub struct Cfg {
    pub blocks: Vec<Block>,
    /// For each instruction index, the blocks of exception handlers that
    /// cover it.
    pub handlers: Vec<Vec<usize>>,
}

impl Cfg {
    pub fn build(instructions: &[Instruction], exception_table: &[ExceptionHandler]) -> Self {
        let index_of: HashMap<i64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, ins)| (i64::from(ins.offset), i))
            .collect();
        let target = |offset: i64| index_of.get(&offset).copied();

        let mut leaders = BTreeSet::new();
        if !instructions.is_empty() {
            leaders.insert(0);
        }
        for (i, ins) in instructions.iter().enumerate() {
            for t in branch_targets(ins) {
                if let Some(index) = target(t) {
                    leaders.insert(index);
                }
            }
            if ends_block(ins.opcode) && i + 1 < instructions.len() {
                leaders.insert(i + 1);
            }
        }
        for handler in exception_table {
            if let Some(index) = target(i64::from(handler.handler)) {
                leaders.insert(index);
            }
        }

        let starts: Vec<usize> = leaders.into_iter().collect();
        let block_of: HashMap<usize, usize> =
            starts.iter().enumerate().map(|(b, &s)| (s, b)).collect();
        let mut blocks = Vec::with_capacity(starts.len());
        for (b, &start) in starts.iter().enumerate() {
            let end = starts.get(b + 1).copied().unwrap_or(instructions.len());
            let last = &instructions[end - 1];
            let mut successors: Vec<usize> = branch_targets(last)
                .into_iter()
                .filter_map(|t| target(t).and_then(|i| block_of.get(&i).copied()))
                .collect();
            if falls_through(last.opcode) && end < instructions.len() {
                successors.push(b + 1);
            }
            successors.sort_unstable();
            successors.dedup();
            blocks.push(Block {
                start,
                end,
                successors,
            });
        }

        let mut handlers = vec![Vec::new(); instructions.len()];
        for handler in exception_table {
            let Some(&handler_block) =
                target(i64::from(handler.handler)).and_then(|i| block_of.get(&i))
            else {
                continue;
            };
            for (i, ins) in instructions.iter().enumerate() {
                if ins.offset >= u32::from(handler.start) && ins.offset < u32::from(handler.end) {
                    handlers[i].push(handler_block);
                }
            }
        }

        Self { blocks, handlers }
    }
}

impl Cfg {
    /// For each block, whether normal control flow from its start can reach
    /// an `athrow` or a return. Exception edges are left out, so a throw
    /// only counts when the method raises it on that path. `edge` maps an
    /// edge from one block to another onto the block it really continues
    /// in, for jump threading. Paths through the `excluded` block are cut,
    /// so it reaches nothing and nothing is reached through it.
    pub fn reach(
        &self,
        instructions: &[Instruction],
        edge: &dyn Fn(usize, usize) -> usize,
        excluded: usize,
    ) -> Vec<super::Reach> {
        let mut reach: Vec<super::Reach> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(b, block)| {
                let opcode = instructions[block.end - 1].opcode;
                super::Reach {
                    throws: b != excluded && opcode == op::ATHROW,
                    returns: b != excluded && matches!(opcode, op::IRETURN..=op::RETURN),
                }
            })
            .collect();
        let mut changed = true;
        while changed {
            changed = false;
            for b in (0..self.blocks.len()).rev().filter(|&b| b != excluded) {
                for &successor in &self.blocks[b].successors {
                    let s = edge(b, successor);
                    let next = super::Reach {
                        throws: reach[b].throws || reach[s].throws,
                        returns: reach[b].returns || reach[s].returns,
                    };
                    if next != reach[b] {
                        reach[b] = next;
                        changed = true;
                    }
                }
            }
        }
        reach
    }
}

fn branch_targets(ins: &Instruction) -> Vec<i64> {
    match &ins.operand {
        Operand::Branch(target) => vec![*target],
        Operand::TableSwitch {
            default, targets, ..
        } => std::iter::once(*default)
            .chain(targets.iter().copied())
            .collect(),
        Operand::LookupSwitch { default, pairs } => std::iter::once(*default)
            .chain(pairs.iter().map(|(_, target)| *target))
            .collect(),
        _ => Vec::new(),
    }
}

/// Instructions after which a new block starts.
fn ends_block(opcode: u8) -> bool {
    matches!(
        opcode,
        op::IFEQ..=op::RETURN | op::IFNULL | op::IFNONNULL | op::GOTO_W | op::JSR_W | op::ATHROW
    )
}

/// Instructions that can continue to the next instruction in order.
fn falls_through(opcode: u8) -> bool {
    !matches!(
        opcode,
        op::GOTO | op::GOTO_W | op::RET | op::TABLESWITCH | op::LOOKUPSWITCH | op::IRETURN
            ..=op::RETURN | op::ATHROW
    )
}
