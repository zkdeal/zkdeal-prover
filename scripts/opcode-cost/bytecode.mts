/**
 * Runtime bytecode generation for the per-opcode proving-cost sweep.
 *
 * Every target is measured as a SLOPE, never as an absolute. For a target we
 * emit runtimes containing 0, N/3, 2N/3 and N repetitions of a stack-neutral
 * unit and fit the gradient. That is the only way to remove the fixed cost of a
 * room batch - cold-template validation, MPT root recomputation, signature
 * recovery, proof setup, wrapping - none of which belongs to any opcode.
 *
 * Four properties hold by construction, and each is asserted against the
 * prover's own counters rather than assumed:
 *
 *   1. CONSTANT LENGTH. Every runtime is padded to exactly 24576 bytes. Code
 *      length is itself a cost: the guest runs JUMPDEST analysis, hashes the
 *      whole runtime for the code hash, and scans it for dynamic control flow,
 *      all O(length), and the code hash re-enters the state root each block. A
 *      row whose variants differed in length would fold that into the gradient.
 *      Verified by `encodedWitnessBytes` being byte-identical across a row.
 *
 *   2. STACK-NEUTRAL UNITS, fed from a reservoir. The prologue pushes words
 *      that are never consumed; each unit duplicates the operands it needs,
 *      runs the target and pops the results. Operands are therefore identical
 *      on every iteration and no underflow is reachable.
 *
 *   3. NO ACCIDENTAL FUSION. The guest replaces 50 ranked ADJACENT ALU pairs
 *      with single dispatches. Every motif's second byte is an ALU opcode in
 *      0x01-0x1c; our units always follow the target with POP (0x50) or DUP
 *      (0x8x), neither of which is any motif's second byte. Verified by
 *      `fusedMotifHits == 0`.
 *
 *   4. PREDICTABLE GAS. A reverted or halted transaction still produces a valid
 *      proof of a truncated execution, so a broken template would yield a clean
 *      gradient of the wrong thing. The only thing that catches it is asserting
 *      executed gas equals the static prediction exactly.
 *
 * Gas constants are never transcribed here. `proofWork.executedGas` comes from
 * the same pinned revm the guest runs, so the gas gradient is fitted from the
 * same samples as the cycle gradient.
 */

/** EIP-170 caps deployed runtime at 24576 bytes. Every variant is padded here. */
export const RUNTIME_BYTES = 24576

const POP = 0x50
const PUSH0 = 0x5f
const PUSH1 = 0x60
const PUSH2 = 0x61
const PUSH32 = 0x7f
const CALLDATALOAD = 0x35
const SSTORE = 0x55
const MSTORE = 0x52
const STOP = 0x00
const DUP1 = 0x80

/**
 * The real state write every generated room performs.
 *
 * A batch that changes no state is not a room transition. Being constant, it
 * lands in the regression intercept rather than in any gradient.
 */
const STATE_WRITE = [PUSH1, 0x04, CALLDATALOAD, PUSH0, SSTORE]

/**
 * Reservoir operands.
 *
 * Deliberately not 0 or 1: those are the arguments most likely to hit a
 * short-circuit - a zero exponent, a division guard, a bigint fast path - and
 * an opcode measured only on its cheapest input is priced too low. Shift counts
 * and byte indices get their own small slots so SHL, BYTE and SIGNEXTEND do
 * meaningful work instead of saturating.
 */
export const RESERVOIR_PRESETS = {
  arithmetic: [0x7fn, 0x08n, 1_000_000n, 2_000_000_000_000_000_000n, 1_000_000_000_000_000_000n],
  small: [0x20n, 0x20n, 0x00n],
} as const

/**
 * A reservoir of `depth` distinct, non-degenerate words.
 *
 * DUP16 needs sixteen words present and SWAP16 needs seventeen; a reservoir
 * sized to the arithmetic preset alone underflows the stack, and the resulting
 * halt shows up as a flat gas curve rather than an error - which is exactly
 * what the first dry run reported for DUP7 upward.
 */
export function reservoirOfDepth(depth: number): bigint[] {
  const words: bigint[] = []
  for (let index = 0; index < depth; index += 1) {
    const preset = RESERVOIR_PRESETS.arithmetic[index]
    words.push(preset ?? BigInt(0x1000 + index * 7))
  }
  return words
}

function pushWord(value: bigint): number[] {
  const hex = value.toString(16).padStart(64, '0')
  const bytes = hex.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16))
  return [PUSH32, ...bytes]
}

/** DUP{n}. */
function dup(depth: number): number {
  if (depth < 1 || depth > 16) throw new Error(`DUP depth ${depth} out of range`)
  return DUP1 + depth - 1
}

/**
 * Feed an arity-`n` operand group from the top `n` reservoir words.
 *
 * Emitting DUP{n} exactly n times reproduces the top n words in their original
 * order: each DUP pushes one word, which deepens the remaining originals by
 * one, so a fixed index walks down the group. Six DUP6 therefore reproduce a
 * STATICCALL frame exactly.
 */
function feed(arity: number): number[] {
  return Array.from({ length: arity }, () => dup(arity))
}

export type OpcodeClass =
  | 'floor'
  | 'nullary'
  | 'swap'
  | 'dup'
  | 'unary'
  | 'binary'
  | 'ternary'
  | 'account-unary'
  | 'mem-load'
  | 'mem-hash'
  | 'mem-store'
  | 'mem-copy3'
  | 'mem-copy4'
  | 'sload'
  | 'sstore'
  | 'log'
  | 'call'
  | 'jump'
  | 'terminating'
  | 'forbidden'
  | 'unreachable'

export interface UnitPlan {
  readonly opcode: number
  readonly name: string
  readonly klass: OpcodeClass
  /** Reservoir words, bottom of the group first; the last becomes slot 1. */
  readonly reservoir: readonly bigint[]
  /** Extra prologue bytes emitted after the reservoir, e.g. memory warm-up. */
  readonly warmup: number[]
  /** The stack-neutral repeated unit. */
  readonly unit: number[]
  readonly unmeasurable?: string
}

function plan(
  opcode: number,
  name: string,
  klass: OpcodeClass,
  reservoir: readonly bigint[],
  unit: number[],
  warmup: number[] = [],
): UnitPlan {
  return { opcode, name, klass, reservoir, warmup, unit }
}

/** Bytes the prologue occupies for a given plan. */
export function prologueBytes(target: UnitPlan): number[] {
  const bytes = [...STATE_WRITE]
  for (const word of target.reservoir) bytes.push(...pushWord(word))
  bytes.push(...target.warmup)
  return bytes
}

/**
 * Assemble a complete runtime at a given repetition count, padded to a
 * constant length so nothing but the repeated region differs within a row.
 */
export function assemble(target: UnitPlan, units: number): Uint8Array {
  if (target.unmeasurable) throw new Error(`${target.name}: ${target.unmeasurable}`)
  const code = [...prologueBytes(target)]
  for (let index = 0; index < units; index += 1) code.push(...target.unit)
  code.push(STOP)
  if (code.length > RUNTIME_BYTES) {
    throw new Error(`${target.name} at ${units} units is ${code.length} bytes, over ${RUNTIME_BYTES}`)
  }
  while (code.length < RUNTIME_BYTES) code.push(0x00)
  return Uint8Array.from(code)
}

/** Largest unit count that still fits the constant runtime length. */
export function maxUnits(target: UnitPlan): number {
  if (target.unmeasurable || target.unit.length === 0) return 0
  return Math.floor((RUNTIME_BYTES - prologueBytes(target).length - 1) / target.unit.length)
}

export function toHex(code: Uint8Array): string {
  return `0x${Array.from(code, (byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

// --- templates -------------------------------------------------------------


/** Pre-grow memory to one word so memory rows never pay expansion mid-sweep. */
const MEMORY_WARMUP = [PUSH0, PUSH0, MSTORE]

export function templateFor(opcode: number, name: string, klass: OpcodeClass): UnitPlan {
  // PUSHn carry their operand inline: the immediate bytes are part of the unit,
  // or the following instruction is swallowed as data.
  if (opcode >= 0x60 && opcode <= 0x7f) {
    const width = opcode - 0x5f
    const immediate = Array.from({ length: width }, (_, index) => (0x9d + index) & 0xff)
    return plan(opcode, name, 'nullary', [], [opcode, ...immediate, POP])
  }
  if (opcode >= 0x80 && opcode <= 0x8f) {
    // DUPn needs n words present; the reservoir supplies them.
    const depth = opcode - DUP1 + 1
    return plan(opcode, name, 'dup', reservoirOfDepth(depth), [opcode, POP])
  }
  if (opcode >= 0x90 && opcode <= 0x9f) {
    // SWAPn is already stack-neutral and needs n+1 words present.
    const depth = opcode - 0x8f + 1
    return plan(opcode, name, 'swap', reservoirOfDepth(depth), [opcode])
  }

  switch (klass) {
    case 'floor':
      // JUMPDEST consumes nothing and is the true dispatch floor. POP needs a
      // word to consume, so it is measured as the DUP1+POP pair and published
      // as that pair - the two are not separately identifiable in a
      // stack-balanced straight line, and saying so is better than pretending.
      if (opcode === POP) return plan(opcode, name, klass, reservoirOfDepth(1), [DUP1, POP])
      return plan(opcode, name, klass, [], [opcode])
    case 'nullary':
      return plan(opcode, name, klass, [], [opcode, POP])
    case 'unary':
      return plan(opcode, name, klass, reservoirOfDepth(1), [...feed(1), opcode, POP])
    case 'binary':
      return plan(opcode, name, klass, reservoirOfDepth(2), [...feed(2), opcode, POP])
    case 'ternary':
      return plan(opcode, name, klass, reservoirOfDepth(3), [...feed(3), opcode, POP])
    // Memory rows address one already-warmed word, so the high-water mark is
    // constant across the row and only the instruction itself varies.
    // 0x01 is the ECRECOVER precompile address, seated as a resident account
    // by the request, so it is always declared and always has empty code.
    case 'account-unary':
      return plan(opcode, name, klass, [0x01n], [...feed(1), opcode, POP])
    case 'mem-load':
      return plan(opcode, name, klass, [0x00n], [...feed(1), opcode, POP], MEMORY_WARMUP)
    case 'mem-hash':
      // KECCAK256 pops offset then size, so offset must end up on top.
      return plan(opcode, name, klass, [0x20n, 0x00n], [...feed(2), opcode, POP], MEMORY_WARMUP)
    case 'mem-store':
      // MSTORE pops offset then value; offset on top.
      return plan(opcode, name, klass, [0x2an, 0x00n], [...feed(2), opcode], MEMORY_WARMUP)
    case 'mem-copy3':
      // (destOffset, offset, size) with destOffset on top. RETURNDATACOPY is
      // the exception: the return-data buffer is empty in this frame, and any
      // window past its end is an exceptional halt rather than a zero fill, so
      // it is measured with a zero-length copy - dispatch cost only, which the
      // published row must state.
      return opcode === 0x3e
        ? plan(opcode, name, klass, [0x00n, 0x00n, 0x00n], [...feed(3), opcode], MEMORY_WARMUP)
        : plan(opcode, name, klass, [0x20n, 0x00n, 0x00n], [...feed(3), opcode], MEMORY_WARMUP)
    case 'mem-copy4':
      // EXTCODECOPY (address, destOffset, offset, size), address on top.
      return plan(opcode, name, klass, [0x20n, 0x00n, 0x00n, 0x04n], [...feed(4), opcode], MEMORY_WARMUP)
    // Storage rows use slot 0, the one slot the request declares. Repeating
    // against a single slot measures the WARM cost; the cold surcharge is a
    // one-off that belongs in the intercept, and the fixture's resident-slot
    // cap makes a cold sweep impossible to fit a line through anyway.
    case 'sload':
      return plan(opcode, name, klass, [0x00n], [...feed(1), opcode, POP])
    case 'sstore':
      // SSTORE pops slot then value; slot on top.
      return plan(opcode, name, klass, [0x2an, 0x00n], [...feed(2), opcode])
    case 'log': {
      const topics = opcode - 0xa0
      // Bottom-to-top: topics deepest, then size, then offset on top. The first
      // draft had topics on top, so LOGn read a topic as its memory offset and
      // grew memory - which the maxMemoryBytes invariant caught.
      const words: bigint[] = []
      for (let index = topics; index >= 1; index -= 1) words.push(BigInt(0x11 + index))
      words.push(0x20n, 0x00n)
      return plan(opcode, name, klass, words, [...feed(2 + topics), opcode], MEMORY_WARMUP)
    }
    default:
      return { opcode, name, klass, reservoir: [], warmup: [], unit: [], unmeasurable: `class ${klass} has no template` }
  }
}

/**
 * The CALL family and precompile invocation.
 *
 * The frame is fed from a six- or seven-word reservoir in one go. A warm-up
 * call in the prologue makes the target account warm in EVERY variant, so the
 * one-off cold-access surcharge stays a constant of the row rather than
 * appearing as a step between the zero-unit and first-unit points.
 */
export function callTemplate(
  opcode: number,
  name: string,
  target: number,
  argsSize: number,
  input?: string,
): UnitPlan {
  const takesValue = opcode === 0xf1 || opcode === 0xf2
  const size = input ? input.length / 2 : argsSize
  // THE RETURN WINDOW MUST NOT OVERLAP THE INPUT.
  //
  // The first version of this template used argsOffset = retOffset = 0, so each
  // call's output landed on top of its own input. Call one succeeded and every
  // later call in the chain parsed the previous result as its arguments. That
  // read as "the precompile rejects this input" when the harness was in fact
  // corrupting it: BLAKE2F happily accepts a zeroed block, returns the BLAKE2b
  // IV, and the next call then sees a round count of 147 million and burns its
  // entire gas allowance.
  const RET_OFFSET = 0x800
  const words: bigint[] = [
    0x40n, // retSize
    BigInt(RET_OFFSET),
    BigInt(size),
    0x00n, // argsOffset
    ...(takesValue ? [0x00n] : []),
    BigInt(target),
    1_000_000n, // gas
  ]
  const arity = words.length
  const frame = feed(arity)
  // Stage the literal input once, in the prologue. It is identical at every
  // unit count, so its cost lands in the regression intercept and cannot
  // contaminate the gradient.
  const staging = input ? stageMemory(input) : [...MEMORY_WARMUP]
  return plan(opcode, name, 'call', words, [...frame, opcode, POP], [...staging, ...frame, opcode, POP])
}

/** Write a hex literal into memory from offset zero, one 32-byte word at a time. */
function stageMemory(hex: string): number[] {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = clean.match(/.{1,2}/g)!.map((pair) => Number.parseInt(pair, 16))
  const code: number[] = []
  for (let offset = 0; offset < bytes.length; offset += 32) {
    const word = bytes.slice(offset, offset + 32)
    while (word.length < 32) word.push(0) // right-pad the tail word
    code.push(PUSH32, ...word)
    code.push(...pushOffset(offset), MSTORE)
  }
  return code
}

/** PUSH the smallest immediate that carries an offset. */
function pushOffset(value: number): number[] {
  if (value === 0) return [PUSH0]
  if (value <= 0xff) return [PUSH1, value]
  return [PUSH2, (value >> 8) & 0xff, value & 0xff]
}

/**
 * JUMP and JUMPI, as a forward chain.
 *
 * Each unit jumps to the JUMPDEST that immediately follows it, so the sequence
 * is straight-line, stack-balanced and repeatable. The destination is
 * back-patched once the unit's position is known, which is why these are built
 * by a dedicated assembler rather than by repeating a fixed byte string.
 */
export function jumpChain(opcode: number, name: string): UnitPlan {
  // The unit is position-dependent, so this plan carries only its shape for
  // sizing; `assembleJumpChain` emits the real bytes with the destination
  // back-patched. JUMP is PUSH2 dest / JUMP / JUMPDEST; JUMPI additionally
  // pushes the condition beneath the destination.
  const unitLength = opcode === 0x56 ? 5 : 7
  return {
    opcode,
    name,
    klass: 'jump',
    reservoir: [],
    warmup: [],
    unit: new Array(unitLength).fill(0x00),
  }
}

/** Position-aware assembly for the jump rows. */
export function assembleJumpChain(opcode: number, units: number, taken: boolean): Uint8Array {
  const code: number[] = [...STATE_WRITE]
  for (let index = 0; index < units; index += 1) {
    if (opcode === 0x57) code.push(PUSH1, taken ? 0x01 : 0x00)
    const patchAt = code.length + 1
    code.push(0x61, 0x00, 0x00, opcode, 0x5b) // PUSH2 <dest> JUMP/JUMPI JUMPDEST
    const destination = code.length - 1 // index of the JUMPDEST just emitted
    code[patchAt] = (destination >> 8) & 0xff
    code[patchAt + 1] = destination & 0xff
  }
  code.push(STOP)
  if (code.length > RUNTIME_BYTES) throw new Error(`jump chain at ${units} units overflows`)
  while (code.length < RUNTIME_BYTES) code.push(0x00)
  return Uint8Array.from(code)
}
