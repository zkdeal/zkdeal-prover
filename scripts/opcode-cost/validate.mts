/**
 * Static validation of generated microbenchmark bytecode.
 *
 * A template bug is expensive here in a way it is not elsewhere: a unit that
 * quietly leaks one stack word per repetition still executes, still proves, and
 * still produces a clean-looking gradient - of the wrong thing. At 10 s per
 * proof and thousands of proofs in a sweep, discovering that afterwards costs a
 * night. So every plan is simulated before it is ever sent to a prover.
 *
 * The simulation is deliberately shallow: it tracks stack depth only, because
 * the properties that matter are structural. It does not interpret values.
 */

import { assemble, maxRepetitions, MAX_RUNTIME_BYTES, type UnitPlan } from './bytecode.mts'

/** Stack effect as [popped, pushed] for the opcodes this harness emits. */
const STACK_EFFECT = new Map<number, [number, number]>([
  [0x00, [0, 0]], // STOP
  [0x20, [2, 1]], // KECCAK256
  [0x35, [1, 1]], // CALLDATALOAD
  [0x37, [3, 0]], // CALLDATACOPY
  [0x39, [3, 0]], // CODECOPY
  [0x3c, [4, 0]], // EXTCODECOPY
  [0x3e, [3, 0]], // RETURNDATACOPY
  [0x50, [1, 0]], // POP
  [0x51, [1, 1]], // MLOAD
  [0x52, [2, 0]], // MSTORE
  [0x53, [2, 0]], // MSTORE8
  [0x54, [1, 1]], // SLOAD
  [0x55, [2, 0]], // SSTORE
  [0x5c, [1, 1]], // TLOAD
  [0x5d, [2, 0]], // TSTORE
  [0x5e, [3, 0]], // MCOPY
  [0x5f, [0, 1]], // PUSH0
  [0xa0, [2, 0]], // LOG0
  [0xa1, [3, 0]], // LOG1
  [0xa2, [4, 0]], // LOG2
  [0xa3, [5, 0]], // LOG3
  [0xa4, [6, 0]], // LOG4
  [0xf0, [3, 1]], // CREATE
  [0xf1, [7, 1]], // CALL
  [0xf2, [7, 1]], // CALLCODE
  [0xf4, [6, 1]], // DELEGATECALL
  [0xf5, [4, 1]], // CREATE2
  [0xfa, [6, 1]], // STATICCALL
])

function effectOf(opcode: number, klass: string): [number, number] {
  const known = STACK_EFFECT.get(opcode)
  if (known) return known
  if (opcode >= 0x60 && opcode <= 0x7f) return [0, 1] // PUSH1-32
  if (opcode >= 0x80 && opcode <= 0x8f) return [0, 1] // DUPn: net +1
  if (opcode >= 0x90 && opcode <= 0x9f) return [0, 0] // SWAPn: net 0
  switch (klass) {
    case 'nullary':
      return [0, 1]
    case 'unary':
      return [1, 1]
    case 'binary':
      return [2, 1]
    case 'ternary':
      return [3, 1]
    case 'consumer1':
      return [1, 0]
    default:
      throw new Error(`no stack effect known for opcode 0x${opcode.toString(16)} in class ${klass}`)
  }
}

/** Walk a byte sequence, skipping PUSH immediates, returning depth history. */
function walk(code: number[], klass: string, start: number): { depth: number; min: number } {
  let depth = start
  let min = start
  let index = 0
  while (index < code.length) {
    const opcode = code[index]!
    const [popped, pushed] = effectOf(opcode, klass)
    depth -= popped
    min = Math.min(min, depth)
    depth += pushed
    index += 1
    if (opcode >= 0x60 && opcode <= 0x7f) index += opcode - 0x5f // skip immediate
  }
  return { depth, min }
}

export interface ValidationIssue {
  readonly name: string
  readonly problem: string
}

export function validatePlan(plan: UnitPlan): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (plan.unmeasurable) return issues // reported separately, not a bug

  if (plan.unit.length === 0) {
    issues.push({ name: plan.name, problem: 'empty repetition unit' })
    return issues
  }

  const prologue = walk(plan.prologue, plan.klass, 0)
  if (prologue.min < 0) {
    issues.push({ name: plan.name, problem: 'prologue underflows the stack' })
  }

  // The unit must be stack-neutral, or N repetitions diverge.
  const unit = walk(plan.unit, plan.klass, prologue.depth)
  if (unit.depth !== prologue.depth) {
    issues.push({
      name: plan.name,
      problem: `unit is not stack-neutral: net ${unit.depth - prologue.depth} per repetition`,
    })
  }
  if (unit.min < 0) {
    issues.push({ name: plan.name, problem: 'unit underflows the stack' })
  }

  // Deep repetition must not exceed the 1024-word stack either.
  const deep = walk(
    Array.from({ length: 8 }, () => plan.unit).flat(),
    plan.klass,
    prologue.depth,
  )
  if (deep.depth > 1024) {
    issues.push({ name: plan.name, problem: 'repetition grows the stack past 1024' })
  }

  const epilogue = walk(plan.epilogue, plan.klass, unit.depth)
  if (epilogue.min < 0) {
    issues.push({ name: plan.name, problem: 'epilogue underflows the stack' })
  }

  const cap = maxRepetitions(plan)
  if (cap < 4) {
    issues.push({ name: plan.name, problem: `only ${cap} repetitions fit ${MAX_RUNTIME_BYTES} bytes` })
  } else {
    const code = assemble(plan, cap)
    if (code.length > MAX_RUNTIME_BYTES) {
      issues.push({ name: plan.name, problem: `assembled ${code.length} bytes exceeds the limit` })
    }
  }

  return issues
}
