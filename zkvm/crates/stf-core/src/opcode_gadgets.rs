//! Prepared straight-line opcode gadgets for common Solidity runtime motifs.
//!
//! RISC Zero proves the RISC-V guest trace rather than an EVM-specific
//! arithmetic circuit. These gadgets therefore optimize the guest executor:
//! two adjacent, side-effect-free EVM operations execute under one interpreter
//! loop/inspector dispatch. Original bytecode, stack semantics, exceptional
//! halts, and Osaka gas accounting remain authoritative.
//!
//! The ranked table is generated from unique production runtime bytecodes in
//! `contracts/out` by `scripts/analyze-opcode-motifs.mts`. Only adjacent
//! arithmetic/bitwise operations are eligible. No gadget spans a JUMPDEST,
//! memory/storage access, call, log, create, precompile, or other host effect.

use revm::{
    handler::instructions::EthInstructions,
    interpreter::{
        instructions::{arithmetic, bitwise},
        interpreter_types::{InterpreterTypes, Jumps, LoopControl},
        Host, Instruction, InstructionContext,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeMotif {
    pub rank: u8,
    pub first: u8,
    pub second: u8,
    pub first_name: &'static str,
    pub second_name: &'static str,
    pub corpus_occurrences: u64,
}

macro_rules! motif {
    ($rank:literal, $first:literal, $second:literal, $first_name:literal, $second_name:literal, $count:literal) => {
        OpcodeMotif {
            rank: $rank,
            first: $first,
            second: $second,
            first_name: $first_name,
            second_name: $second_name,
            corpus_occurrences: $count,
        }
    };
}

/// Top 50 adjacent, gadget-safe opcode pairs in the pinned zkdeal Solidity
/// corpus (64 unique production runtimes, 711,634 decoded opcodes).
pub const TOP_50_SOLIDITY_MOTIFS: [OpcodeMotif; 50] = [
    motif!(1, 0x1b, 0x03, "SHL", "SUB", 8310),
    motif!(2, 0x01, 0x12, "ADD", "SLT", 2296),
    motif!(3, 0x19, 0x01, "NOT", "ADD", 1935),
    motif!(4, 0x03, 0x16, "SUB", "AND", 1920),
    motif!(5, 0x03, 0x12, "SUB", "SLT", 1174),
    motif!(6, 0x01, 0x03, "ADD", "SUB", 1141),
    motif!(7, 0x10, 0x15, "LT", "ISZERO", 1107),
    motif!(8, 0x19, 0x16, "NOT", "AND", 1038),
    motif!(9, 0x1c, 0x16, "SHR", "AND", 961),
    motif!(10, 0x01, 0x01, "ADD", "ADD", 838),
    motif!(11, 0x15, 0x15, "ISZERO", "ISZERO", 718),
    motif!(12, 0x16, 0x17, "AND", "OR", 601),
    motif!(13, 0x14, 0x15, "EQ", "ISZERO", 571),
    motif!(14, 0x03, 0x19, "SUB", "NOT", 521),
    motif!(15, 0x1b, 0x16, "SHL", "AND", 506),
    motif!(16, 0x03, 0x01, "SUB", "ADD", 456),
    motif!(17, 0x16, 0x15, "AND", "ISZERO", 411),
    motif!(18, 0x11, 0x17, "GT", "OR", 353),
    motif!(19, 0x11, 0x15, "GT", "ISZERO", 246),
    motif!(20, 0x12, 0x15, "SLT", "ISZERO", 238),
    motif!(21, 0x16, 0x14, "AND", "EQ", 230),
    motif!(22, 0x01, 0x16, "ADD", "AND", 228),
    motif!(23, 0x16, 0x10, "AND", "LT", 204),
    motif!(24, 0x1b, 0x19, "SHL", "NOT", 203),
    motif!(25, 0x1b, 0x01, "SHL", "ADD", 192),
    motif!(26, 0x1b, 0x1c, "SHL", "SHR", 182),
    motif!(27, 0x16, 0x01, "AND", "ADD", 162),
    motif!(28, 0x01, 0x11, "ADD", "GT", 159),
    motif!(29, 0x10, 0x17, "LT", "OR", 135),
    motif!(30, 0x16, 0x11, "AND", "GT", 135),
    motif!(31, 0x16, 0x16, "AND", "AND", 105),
    motif!(32, 0x1b, 0x17, "SHL", "OR", 93),
    motif!(33, 0x03, 0x02, "SUB", "MUL", 91),
    motif!(34, 0x1c, 0x19, "SHR", "NOT", 88),
    motif!(35, 0x16, 0x03, "AND", "SUB", 56),
    motif!(36, 0x01, 0x10, "ADD", "LT", 53),
    motif!(37, 0x1c, 0x03, "SHR", "SUB", 53),
    motif!(38, 0x16, 0x1c, "AND", "SHR", 44),
    motif!(39, 0x17, 0x15, "OR", "ISZERO", 43),
    motif!(40, 0x17, 0x17, "OR", "OR", 43),
    motif!(41, 0x15, 0x17, "ISZERO", "OR", 35),
    motif!(42, 0x10, 0x14, "LT", "EQ", 34),
    motif!(43, 0x16, 0x1b, "AND", "SHL", 29),
    motif!(44, 0x03, 0x04, "SUB", "DIV", 26),
    motif!(45, 0x02, 0x01, "MUL", "ADD", 20),
    motif!(46, 0x15, 0x03, "ISZERO", "SUB", 18),
    motif!(47, 0x03, 0x06, "SUB", "MOD", 14),
    motif!(48, 0x02, 0x18, "MUL", "XOR", 13),
    motif!(49, 0x04, 0x01, "DIV", "ADD", 13),
    motif!(50, 0x04, 0x17, "DIV", "OR", 13),
];

#[inline]
pub fn top_50_motif_rank(first: u8, second: u8) -> Option<u8> {
    // Keep recognition out of the data table's linear scan. This function is
    // in the proved hot loop, so a compiled integer match is materially less
    // work than comparing up to 50 table rows for every arithmetic opcode.
    match u16::from(first) << 8 | u16::from(second) {
        0x1b03 => Some(1),
        0x0112 => Some(2),
        0x1901 => Some(3),
        0x0316 => Some(4),
        0x0312 => Some(5),
        0x0103 => Some(6),
        0x1015 => Some(7),
        0x1916 => Some(8),
        0x1c16 => Some(9),
        0x0101 => Some(10),
        0x1515 => Some(11),
        0x1617 => Some(12),
        0x1415 => Some(13),
        0x0319 => Some(14),
        0x1b16 => Some(15),
        0x0301 => Some(16),
        0x1615 => Some(17),
        0x1117 => Some(18),
        0x1115 => Some(19),
        0x1215 => Some(20),
        0x1614 => Some(21),
        0x0116 => Some(22),
        0x1610 => Some(23),
        0x1b19 => Some(24),
        0x1b01 => Some(25),
        0x1b1c => Some(26),
        0x1601 => Some(27),
        0x0111 => Some(28),
        0x1017 => Some(29),
        0x1611 => Some(30),
        0x1616 => Some(31),
        0x1b17 => Some(32),
        0x0302 => Some(33),
        0x1c19 => Some(34),
        0x1603 => Some(35),
        0x0110 => Some(36),
        0x1c03 => Some(37),
        0x161c => Some(38),
        0x1715 => Some(39),
        0x1717 => Some(40),
        0x1517 => Some(41),
        0x1014 => Some(42),
        0x161b => Some(43),
        0x0304 => Some(44),
        0x0201 => Some(45),
        0x1503 => Some(46),
        0x0306 => Some(47),
        0x0218 => Some(48),
        0x0401 => Some(49),
        0x0417 => Some(50),
        _ => None,
    }
}

#[inline]
const fn static_gas(opcode: u8) -> u64 {
    match opcode {
        0x01 | 0x03 => 3,                             // ADD, SUB
        0x02 | 0x04 | 0x05 | 0x06 | 0x07 | 0x0b => 5, // MUL..SIGNEXTEND
        0x08 | 0x09 => 8,                             // ADDMOD, MULMOD
        0x0a => 10,                                   // EXP base cost
        0x10..=0x1d => 3,                             // comparisons/bitwise/shifts
        0x1e => 5,                                    // CLZ
        _ => 0,
    }
}

#[inline]
fn execute_pure<WIRE, H>(
    opcode: u8,
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
    host: &mut H,
) where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    macro_rules! call {
        ($function:path) => {
            $function(InstructionContext { interpreter, host })
        };
    }
    match opcode {
        0x01 => call!(arithmetic::add),
        0x02 => call!(arithmetic::mul),
        0x03 => call!(arithmetic::sub),
        0x04 => call!(arithmetic::div),
        0x05 => call!(arithmetic::sdiv),
        0x06 => call!(arithmetic::rem),
        0x07 => call!(arithmetic::smod),
        0x08 => call!(arithmetic::addmod),
        0x09 => call!(arithmetic::mulmod),
        0x0a => call!(arithmetic::exp),
        0x0b => call!(arithmetic::signextend),
        0x10 => call!(bitwise::lt),
        0x11 => call!(bitwise::gt),
        0x12 => call!(bitwise::slt),
        0x13 => call!(bitwise::sgt),
        0x14 => call!(bitwise::eq),
        0x15 => call!(bitwise::iszero),
        0x16 => call!(bitwise::bitand),
        0x17 => call!(bitwise::bitor),
        0x18 => call!(bitwise::bitxor),
        0x19 => call!(bitwise::not),
        0x1a => call!(bitwise::byte),
        0x1b => call!(bitwise::shl),
        0x1c => call!(bitwise::shr),
        0x1d => call!(bitwise::sar),
        0x1e => call!(bitwise::clz),
        _ => unreachable!("only gadget-safe opcodes reach execute_pure"),
    }
}

#[inline]
fn execute_fused<WIRE, H>(first: u8, context: InstructionContext<'_, H, WIRE>)
where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    let InstructionContext { interpreter, host } = context;
    let second = interpreter.bytecode.opcode();
    let pair = u16::from(first) << 8 | u16::from(second);

    execute_pure(first, interpreter, host);
    if interpreter.bytecode.is_end() {
        return;
    }

    // Recognize the pair and dispatch its second operation in one compiled
    // branch. Keeping these as two matches measured worse than the reference:
    // the redundant recognizer erased most of the saved interpreter pass.
    macro_rules! second {
        ($function:path) => {{
            // Match Interpreter::step exactly for the consumed second opcode:
            // advance the PC, charge static gas, then run standard semantics.
            interpreter.bytecode.relative_jump(1);
            if interpreter.gas.record_cost_unsafe(static_gas(second)) {
                interpreter.halt_oog();
                return;
            }
            $function(InstructionContext { interpreter, host });
        }};
    }
    match pair {
        0x1901 | 0x0101 | 0x0301 | 0x1b01 | 0x1601 | 0x0201 | 0x0401 => {
            second!(arithmetic::add)
        }
        0x0302 => second!(arithmetic::mul),
        0x1b03 | 0x0103 | 0x1603 | 0x1c03 | 0x1503 => second!(arithmetic::sub),
        0x0304 => second!(arithmetic::div),
        0x0306 => second!(arithmetic::rem),
        0x1610 | 0x0110 => second!(bitwise::lt),
        0x0111 | 0x1611 => second!(bitwise::gt),
        0x0112 | 0x0312 => second!(bitwise::slt),
        0x1614 | 0x1014 => second!(bitwise::eq),
        0x1015 | 0x1515 | 0x1415 | 0x1615 | 0x1115 | 0x1215 | 0x1715 => {
            second!(bitwise::iszero)
        }
        0x0316 | 0x1916 | 0x1c16 | 0x1b16 | 0x0116 | 0x1616 => {
            second!(bitwise::bitand)
        }
        0x1617 | 0x1117 | 0x1017 | 0x1b17 | 0x1717 | 0x1517 | 0x0417 => {
            second!(bitwise::bitor)
        }
        0x0218 => second!(bitwise::bitxor),
        0x0319 | 0x1b19 | 0x1c19 => second!(bitwise::not),
        0x161b => second!(bitwise::shl),
        0x1b1c | 0x161c => second!(bitwise::shr),
        _ => {}
    }
}

macro_rules! fused_entry {
    ($name:ident, $opcode:literal) => {
        #[inline]
        fn $name<WIRE, H>(context: InstructionContext<'_, H, WIRE>)
        where
            WIRE: InterpreterTypes,
            H: Host + ?Sized,
        {
            execute_fused($opcode, context);
        }
    };
}

fused_entry!(fused_add, 0x01);
fused_entry!(fused_mul, 0x02);
fused_entry!(fused_sub, 0x03);
fused_entry!(fused_div, 0x04);
fused_entry!(fused_lt, 0x10);
fused_entry!(fused_gt, 0x11);
fused_entry!(fused_slt, 0x12);
fused_entry!(fused_eq, 0x14);
fused_entry!(fused_iszero, 0x15);
fused_entry!(fused_and, 0x16);
fused_entry!(fused_or, 0x17);
fused_entry!(fused_not, 0x19);
fused_entry!(fused_shl, 0x1b);
fused_entry!(fused_shr, 0x1c);

/// Install the ranked superinstructions into an Osaka REVM instruction table.
///
/// The function is called after REVM constructs its spec-correct table. Each
/// replacement keeps the original first-op static gas; the gadget charges the
/// second operation exactly when the ranked pair is present.
pub fn install_top_50_opcode_gadgets<WIRE, H>(instructions: &mut EthInstructions<WIRE, H>)
where
    WIRE: InterpreterTypes,
    H: Host,
{
    instructions.insert_instruction(0x01, Instruction::new(fused_add::<WIRE, H>, 3));
    instructions.insert_instruction(0x02, Instruction::new(fused_mul::<WIRE, H>, 5));
    instructions.insert_instruction(0x03, Instruction::new(fused_sub::<WIRE, H>, 3));
    instructions.insert_instruction(0x04, Instruction::new(fused_div::<WIRE, H>, 5));
    instructions.insert_instruction(0x10, Instruction::new(fused_lt::<WIRE, H>, 3));
    instructions.insert_instruction(0x11, Instruction::new(fused_gt::<WIRE, H>, 3));
    instructions.insert_instruction(0x12, Instruction::new(fused_slt::<WIRE, H>, 3));
    instructions.insert_instruction(0x14, Instruction::new(fused_eq::<WIRE, H>, 3));
    instructions.insert_instruction(0x15, Instruction::new(fused_iszero::<WIRE, H>, 3));
    instructions.insert_instruction(0x16, Instruction::new(fused_and::<WIRE, H>, 3));
    instructions.insert_instruction(0x17, Instruction::new(fused_or::<WIRE, H>, 3));
    instructions.insert_instruction(0x19, Instruction::new(fused_not::<WIRE, H>, 3));
    instructions.insert_instruction(0x1b, Instruction::new(fused_shl::<WIRE, H>, 3));
    instructions.insert_instruction(0x1c, Instruction::new(fused_shr::<WIRE, H>, 3));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn table_is_ranked_unique_and_gadget_safe() {
        let mut ranks = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for motif in TOP_50_SOLIDITY_MOTIFS {
            assert!(ranks.insert(motif.rank));
            assert!(pairs.insert((motif.first, motif.second)));
            assert!(static_gas(motif.first) > 0);
            assert!(static_gas(motif.second) > 0);
            assert_eq!(
                top_50_motif_rank(motif.first, motif.second),
                Some(motif.rank)
            );
        }
        assert_eq!(ranks, (1..=50).collect());
    }
}
