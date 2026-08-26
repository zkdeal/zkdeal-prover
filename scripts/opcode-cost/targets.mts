/**
 * Classification of the Osaka instruction set into measurement templates.
 *
 * The inventory is NOT written here. It is dumped from the pinned revm the
 * guest executes (`stf-core --bin dump-opcode-manifest`), so the sweep cannot
 * silently miss an instruction. This module only says how each one is measured,
 * and any active opcode without a classification is a hard error - the first
 * draft of this table was missing SLOTNUM, and the cross-check is what caught
 * it.
 */

import type { OpcodeClass } from './bytecode.mts'

const NULLARY = new Set([
  'ADDRESS', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATASIZE', 'CODESIZE',
  'GASPRICE', 'RETURNDATASIZE', 'COINBASE', 'TIMESTAMP', 'NUMBER',
  'PREVRANDAO', 'GASLIMIT', 'CHAINID', 'SELFBALANCE', 'BASEFEE',
  'BLOBBASEFEE', 'PC', 'MSIZE', 'GAS', 'PUSH0',
  // revm names 0x44 DIFFICULTY rather than PREVRANDAO; both are carried so the
  // classification does not depend on which alias the interpreter reports.
  'DIFFICULTY',
  // 0x4b, the Osaka slot-number instruction.
  'SLOTNUM',
])

const UNARY = new Set([
  'ISZERO', 'NOT', 'CLZ', 'CALLDATALOAD', 'BLOCKHASH', 'BLOBHASH',
])

/**
 * Unary opcodes whose operand is an ADDRESS.
 *
 * They must be handed an account the witness declares, or execution fails with
 * `Database(UndeclaredAccount)`. The arithmetic reservoir's first word is 0x7f,
 * which is exactly the address the first full dry run died on.
 */
const ACCOUNT_UNARY = new Set(['BALANCE', 'EXTCODESIZE', 'EXTCODEHASH'])

/**
 * Memory- and storage-addressing instructions need SMALL, DECLARED operands.
 *
 * Feeding them the arithmetic reservoir makes them address memory at 1e18,
 * which either explodes the memory high-water mark or - for storage - fails
 * outright with `Database(UndeclaredStorage)`, because the compact witness is
 * an allow-list and only the slots named in the request exist.
 */
const MEM_LOAD = new Set(['MLOAD'])
const MEM_HASH = new Set(['KECCAK256'])
const MEM_STORE = new Set(['MSTORE', 'MSTORE8'])
const MEM_COPY3 = new Set(['CALLDATACOPY', 'CODECOPY', 'RETURNDATACOPY', 'MCOPY'])
const MEM_COPY4 = new Set(['EXTCODECOPY'])
const STORAGE_LOAD = new Set(['SLOAD', 'TLOAD'])
const STORAGE_STORE = new Set(['SSTORE', 'TSTORE'])

const BINARY = new Set([
  'ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD', 'EXP', 'SIGNEXTEND',
  'LT', 'GT', 'SLT', 'SGT', 'EQ', 'AND', 'OR', 'XOR', 'BYTE', 'SHL', 'SHR',
  'SAR',
])

const TERNARY = new Set(['ADDMOD', 'MULMOD'])

const LOG = new Set(['LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4'])

const CALL = new Set(['CALL', 'DELEGATECALL', 'STATICCALL'])

/**
 * Forbidden by the guest, not by the fixture.
 *
 * `stf-core/src/policy/from_v5.rs:62-67` rejects a policy that permits creation
 * or self-destruct before execution begins, and the inspector latches CALLCODE
 * as a violation during it. Both are compiled into the guest, so relaxing the
 * host-side fixture policy changes nothing. Measuring these would require a
 * separate, explicitly non-production guest build with its own image id; that
 * is a deliberate decision, not a configuration flag.
 */
export const POLICY_FORBIDDEN = new Map<string, string>([
  ['CREATE', 'policy/from_v5.rs:62-67 rejects allow_contract_creation'],
  ['CREATE2', 'policy/from_v5.rs:62-67 rejects allow_contract_creation'],
  ['SELFDESTRUCT', 'policy/from_v5.rs:62-67 rejects allow_self_destruct'],
  ['CALLCODE', 'policy/inspector.rs:257-260 latches CALLCODE as a violation'],
])

/**
 * Terminators, measured by frame differential rather than repetition.
 *
 * They end the frame, so they cannot repeat in a straight line. Instead the
 * terminator goes in a callee and the CALL is repeated: the difference between
 * the STOP callee and each other callee isolates that terminator. Only
 * differences against the STOP frame are measurable; the absolute per-execution
 * cost is not separable from frame teardown, and the table says so.
 */
export const FRAME_DIFFERENTIAL = new Map<string, string>([
  ['STOP', 'reference frame for the terminator differential'],
  ['RETURN', 'measured as callee frame minus the STOP frame'],
  ['REVERT', 'measured as callee frame minus the STOP frame'],
  ['INVALID', 'measured as callee frame minus the STOP frame; consumes all forwarded gas'],
])

/** EOF-only instructions, unreachable from the legacy runtime a room deploys. */
export const EOF_ONLY = new Set([
  'DATALOAD', 'DATALOADN', 'DATASIZE', 'DATACOPY', 'RJUMP', 'RJUMPI',
  'RJUMPV', 'CALLF', 'RETF', 'JUMPF', 'DUPN', 'SWAPN', 'EXCHANGE',
  'EOFCREATE', 'RETURNCONTRACT', 'RETURNDATALOAD', 'EXTCALL',
  'EXTDELEGATECALL', 'EXTSTATICCALL',
])

export interface Target {
  readonly byte: number
  readonly name: string
  readonly klass: OpcodeClass
  readonly reason?: string
}

export function classify(byte: number, name: string): Target {
  if (EOF_ONLY.has(name)) {
    return { byte, name, klass: 'unreachable', reason: 'EOF-only; unreachable from legacy runtime code' }
  }
  const forbidden = POLICY_FORBIDDEN.get(name)
  if (forbidden) return { byte, name, klass: 'forbidden', reason: forbidden }

  const differential = FRAME_DIFFERENTIAL.get(name)
  if (differential) return { byte, name, klass: 'terminating', reason: differential }

  if (name === 'JUMP' || name === 'JUMPI') return { byte, name, klass: 'jump' }
  if (name === 'JUMPDEST') return { byte, name, klass: 'floor' }
  if (name === 'POP') return { byte, name, klass: 'floor' }

  if (byte >= 0x60 && byte <= 0x7f) return { byte, name, klass: 'nullary' }
  if (byte >= 0x80 && byte <= 0x8f) return { byte, name, klass: 'dup' }
  if (byte >= 0x90 && byte <= 0x9f) return { byte, name, klass: 'swap' }

  if (NULLARY.has(name)) return { byte, name, klass: 'nullary' }
  if (UNARY.has(name)) return { byte, name, klass: 'unary' }
  if (ACCOUNT_UNARY.has(name)) return { byte, name, klass: 'account-unary' }
  if (BINARY.has(name)) return { byte, name, klass: 'binary' }
  if (TERNARY.has(name)) return { byte, name, klass: 'ternary' }
  if (MEM_LOAD.has(name)) return { byte, name, klass: 'mem-load' }
  if (MEM_HASH.has(name)) return { byte, name, klass: 'mem-hash' }
  if (MEM_STORE.has(name)) return { byte, name, klass: 'mem-store' }
  if (MEM_COPY3.has(name)) return { byte, name, klass: 'mem-copy3' }
  if (MEM_COPY4.has(name)) return { byte, name, klass: 'mem-copy4' }
  if (STORAGE_LOAD.has(name)) return { byte, name, klass: 'sload' }
  if (STORAGE_STORE.has(name)) return { byte, name, klass: 'sstore' }
  if (LOG.has(name)) return { byte, name, klass: 'log' }
  if (CALL.has(name)) return { byte, name, klass: 'call' }

  return { byte, name, klass: 'unreachable', reason: 'no classification; sweep must not silently skip it' }
}

export interface ManifestEntry {
  readonly byte: number
  readonly hex: string
  readonly name: string
  readonly active: boolean
}

export function classifyManifest(entries: readonly ManifestEntry[]): Target[] {
  const targets = entries.filter((entry) => entry.active).map((entry) => classify(entry.byte, entry.name))
  const unclassified = targets.filter((target) => target.reason?.startsWith('no classification'))
  if (unclassified.length > 0) {
    const names = unclassified.map((target) => `${target.name} (0x${target.byte.toString(16)})`).join(', ')
    throw new Error(`unclassified active opcodes: ${names}`)
  }
  return targets
}

/**
 * Precompiles. Every one of these addresses must be seated as a resident
 * account in the request, or the call fails with `Database(UndeclaredAccount)`
 * before it reaches the precompile at all - the compact witness is a hard
 * allow-list, not a cache hint.
 *
 * INPUT REALISM. Inputs are structurally valid but degenerate - zero bytes,
 * which decode to the point at infinity or a zero scalar. Gas is charged from
 * the schedule regardless, so the gas column is exact, but a curve operation on
 * a trivial input may short-circuit and do far less work than a real one. The
 * cycle column for the curve rows is therefore a LOWER BOUND, and the published
 * table must say so; closing it needs real curve vectors.
 *
 * `accelerated` marks the two families this guest actually accelerates: the
 * RISC Zero keccak coprocessor and the patched k256/crypto-bigint used for
 * secp256k1. Everything else is stock crates.io compiled to RISC-V, which is
 * why published RISC0 opcode rankings do not transfer to this build.
 */
export const PRECOMPILE_TARGETS = [
  { address: 0x01, name: 'ECRECOVER', argsSize: 128, accelerated: true },
  { address: 0x02, name: 'SHA256', argsSize: 64, accelerated: false },
  { address: 0x03, name: 'RIPEMD160', argsSize: 64, accelerated: false },
  { address: 0x04, name: 'IDENTITY', argsSize: 64, accelerated: false },
  { address: 0x05, name: 'MODEXP', argsSize: 128, accelerated: false },
  { address: 0x06, name: 'BN254_ADD', argsSize: 128, accelerated: false },
  { address: 0x07, name: 'BN254_MUL', argsSize: 96, accelerated: false },
  // An empty input is a valid pairing check (it returns 1), and it is the only
  // shape this harness can currently produce that BN254 pairing accepts. It
  // therefore measures the 45000-gas BASE charge and no pairing work at all;
  // the row must be published as base-only until a real pair vector exists.
  { address: 0x08, name: 'BN254_PAIRING', argsSize: 0, accelerated: false, inputRealism: 'base-charge-only' },
  { address: 0x09, name: 'BLAKE2F', argsSize: 213, accelerated: false, inputRealism: 'needs-valid-vector' },
  { address: 0x0a, name: 'POINT_EVALUATION', argsSize: 192, accelerated: false, inputRealism: 'needs-valid-vector' },
  { address: 0x0b, name: 'BLS12_G1ADD', argsSize: 256, accelerated: false },
  { address: 0x0c, name: 'BLS12_G1MSM', argsSize: 160, accelerated: false },
  { address: 0x0d, name: 'BLS12_G2ADD', argsSize: 512, accelerated: false },
  { address: 0x0e, name: 'BLS12_G2MSM', argsSize: 288, accelerated: false },
  { address: 0x0f, name: 'BLS12_PAIRING', argsSize: 384, accelerated: false, inputRealism: 'needs-valid-vector' },
  { address: 0x10, name: 'BLS12_MAP_FP_TO_G1', argsSize: 64, accelerated: false },
  { address: 0x11, name: 'BLS12_MAP_FP2_TO_G2', argsSize: 128, accelerated: false },
  { address: 0x100, name: 'P256VERIFY', argsSize: 160, accelerated: false },
] as const

/** Every precompile address, for the request's resident-account list. */
export function precompileAddresses(): string[] {
  return PRECOMPILE_TARGETS.map((entry) => `0x${entry.address.toString(16).padStart(40, '0')}`)
}
