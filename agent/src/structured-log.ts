/**
 * Allowlisted hosted trace records emitted by the packaged prover agent.
 *
 * The record deliberately cannot carry request/result bytes, authentication,
 * proof material, error reasons, or arbitrary metadata. It is a correlation
 * join surface, not an application log or a metrics-label source.
 */

export const AGENT_TRACE_EVENTS = ['job.start', 'job.complete', 'job.error'] as const
export type AgentTraceEvent = (typeof AGENT_TRACE_EVENTS)[number]
export type AgentTraceOutcome = 'started' | 'succeeded' | 'retrying' | 'failed'

export interface AgentTraceInput {
  correlationId: string
  tenantId: string
  roomId: string | null
  jobId: string
  event: AgentTraceEvent
  outcome: AgentTraceOutcome
}

export interface AgentTraceRecord extends AgentTraceInput {
  schemaVersion: 1
  timestamp: string
  operationId: null
  component: 'prover-agent'
}

export type AgentTraceSink = (input: AgentTraceInput) => void

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/
const OUTCOMES = new Set<AgentTraceOutcome>(['started', 'succeeded', 'retrying', 'failed'])
const EVENTS = new Set<AgentTraceEvent>(AGENT_TRACE_EVENTS)
export const MAX_AGENT_TRACE_BYTES = 2_048

function identifier(value: unknown, label: string, nullable = false): string | null {
  if (value === null && nullable) return null
  if (typeof value !== 'string' || !SAFE_IDENTIFIER.test(value)) {
    throw new Error(`${label} is unsafe for a prover-agent trace`)
  }
  return value
}

export function agentTraceRecord(input: AgentTraceInput, now = new Date()): AgentTraceRecord {
  if (!EVENTS.has(input.event)) throw new Error('event is unsupported for a prover-agent trace')
  if (!OUTCOMES.has(input.outcome)) throw new Error('outcome is unsupported for a prover-agent trace')
  const record: AgentTraceRecord = {
    schemaVersion: 1,
    timestamp: now.toISOString(),
    correlationId: identifier(input.correlationId, 'correlationId')!,
    tenantId: identifier(input.tenantId, 'tenantId')!,
    roomId: identifier(input.roomId, 'roomId', true),
    jobId: identifier(input.jobId, 'jobId')!,
    operationId: null,
    component: 'prover-agent',
    event: input.event,
    outcome: input.outcome,
  }
  if (Buffer.byteLength(JSON.stringify(record), 'utf8') > MAX_AGENT_TRACE_BYTES) {
    throw new Error('prover-agent trace exceeds its serialized byte bound')
  }
  return record
}

export function emitAgentTrace(input: AgentTraceInput): AgentTraceRecord {
  const record = agentTraceRecord(input)
  process.stdout.write(`${JSON.stringify(record)}\n`)
  return record
}

