/**
 * The prover-node agent: a queue-pull sidecar next to `zkdeal-r0 serve`.
 *
 * Pull, never push: the queue cannot reach into a prover's network, so the
 * agent polls `POST /queue/v1/lease`, forwards the leased job to the local
 * prover, heartbeats the lease while the proof runs, and reports the
 * verbatim result back. The agent holds no protocol knowledge - the queue
 * whitelists the endpoints, the prover judges the requests, and the agent is
 * deliberately just plumbing that can die without losing anything: an
 * unreported job is re-leased when its lease expires.
 *
 * env: QUEUE_URL, ZKDEAL_QUEUE_NODE_TOKEN, NODE_ID, PROVER_URL,
 * ZKDEAL_PROVER_TOKEN (forwarded to the prover), ZKDEAL_AGENT_GPU=0 for a
 * CPU-only worker, POLL_INTERVAL_MS, HEARTBEAT_INTERVAL_MS, and
 * ZKDEAL_AGENT_STUB (see local-prover.ts). ROOM_POOL plus the scoped
 * NODE_LIVENESS_COORDINATOR_* contract enables production heartbeats through
 * the hosted coordinator's durable L1 operation/watcher surface. A direct
 * L1_RPC_URL and raw key are accepted only in explicit loopback development.
 */

import { randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { onChainOptionsFromEnv, startOnChainHeartbeat } from './heartbeat.js'
import {
  createHttpLocalProver,
  createStubProver,
  type ForwardOutcome,
  type LocalProver,
} from './local-prover.js'
import {
  agentTraceRecord,
  emitAgentTrace,
  type AgentTraceInput,
  type AgentTraceSink,
} from './structured-log.js'

export interface LeasedJob {
  jobId: string
  tenantId: string
  roomId: string | null
  correlationId: string
  endpoint: string
  needsGpu: boolean
  attempts: number
  request: unknown
}

export interface AgentOptions {
  queueUrl: string
  nodeToken: string
  nodeId: string
  prover: LocalProver
  /** Declared to the queue; false keeps GPU jobs away from this worker. */
  gpu?: boolean
  pollIntervalMs?: number
  heartbeatIntervalMs?: number
  log?: (line: string) => void
  /** Allowlisted structured trace sink. Identifiers are never metric labels. */
  trace?: AgentTraceSink
}

export interface AgentController {
  /** Resolves once the loop has fully wound down. */
  stop: () => Promise<void>
}

const DEFAULT_POLL_INTERVAL_MS = 2_000
const DEFAULT_HEARTBEAT_INTERVAL_MS = 30_000
/** Reports are cheap and complete is idempotent; a blip must not cost a proof. */
const REPORT_ATTEMPTS = 3

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('leased job must be an object')
  }
  return value as Record<string, unknown>
}

/** Validate the owner-derived correlation tuple before forwarding any bytes. */
export function parseLeasedJob(value: unknown): LeasedJob {
  const source = object(value)
  if (typeof source.endpoint !== 'string' || !source.endpoint.startsWith('/')) {
    throw new Error('leased job endpoint is invalid')
  }
  if (typeof source.needsGpu !== 'boolean') throw new Error('leased job needsGpu is invalid')
  if (!Object.hasOwn(source, 'request')) throw new Error('leased job request is missing')
  if (typeof source.attempts !== 'number' || !Number.isSafeInteger(source.attempts) || source.attempts < 1) {
    throw new Error('leased job attempts is invalid')
  }
  const job: LeasedJob = {
    jobId: String(source.jobId ?? ''),
    tenantId: String(source.tenantId ?? ''),
    roomId: source.roomId === null ? null : String(source.roomId ?? ''),
    correlationId: String(source.correlationId ?? ''),
    endpoint: source.endpoint,
    needsGpu: source.needsGpu,
    attempts: Number(source.attempts),
    request: source.request,
  }
  // Construction validates the exact same identifier bounds as emission,
  // without writing a line or inspecting request bytes.
  agentTraceRecord({
    correlationId: job.correlationId,
    tenantId: job.tenantId,
    roomId: job.roomId,
    jobId: job.jobId,
    event: 'job.start',
    outcome: 'started',
  })
  return job
}

export function startAgent(options: AgentOptions): AgentController {
  const base = options.queueUrl.replace(/\/+$/, '')
  const pollMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
  const heartbeatMs = options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS
  const log = options.log ?? ((line) => process.stderr.write(`${line}\n`))
  const trace = options.trace ?? emitAgentTrace
  let stopped = false
  let wake: (() => void) | null = null

  const sleep = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => {
        wake = null
        resolve()
      }, ms)
      // stop() flips `stopped` and wakes the loop so shutdown is prompt.
      wake = () => {
        clearTimeout(timer)
        wake = null
        resolve()
      }
    })

  const queue = async (path: string, body: unknown): Promise<Response> =>
    fetch(`${base}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${options.nodeToken}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    })

  const report = async (path: string, body: unknown): Promise<boolean> => {
    for (let attempt = 1; attempt <= REPORT_ATTEMPTS; attempt += 1) {
      try {
        const response = await queue(path, body)
        // 409 means the queue no longer recognises this lease (it expired
        // and moved on); repeating the same report cannot change that.
        if (response.ok) return true
        if (response.status === 409) return false
      } catch {
        /* network blip: retry below */
      }
      await sleep(1_000)
    }
    log(`Progress: the queue never acknowledged ${path}; the lease will expire it.`)
    return false
  }

  const jobTrace = (
    job: LeasedJob,
    event: AgentTraceInput['event'],
    outcome: AgentTraceInput['outcome'],
  ): void => {
    try {
      trace({
        correlationId: job.correlationId,
        tenantId: job.tenantId,
        roomId: job.roomId,
        jobId: job.jobId,
        event,
        outcome,
      })
    } catch {
      // Trace I/O must not alter proof or queue state. The tuple was already
      // validated before forwarding, so this is a sink failure only.
      log('Progress: the bounded prover-agent trace sink failed.')
    }
  }

  const work = async (job: LeasedJob): Promise<void> => {
    jobTrace(job, 'job.start', 'started')
    const beat = setInterval(() => {
      void queue(`/queue/v1/jobs/${job.jobId}/heartbeat`, { nodeId: options.nodeId }).catch(
        () => {
          // A missed heartbeat is survivable; the lease TTL is the backstop.
        },
      )
    }, heartbeatMs)
    let outcome: ForwardOutcome
    try {
      outcome = await options.prover.forward(job.endpoint, job.request)
    } catch (error) {
      // A crashed forward indicts this node, not the request.
      outcome = {
        kind: 'unavailable',
        reason: error instanceof Error ? error.message : 'the local forward crashed',
      }
    } finally {
      clearInterval(beat)
    }
    if (outcome.kind === 'ok') {
      const acknowledged = await report(`/queue/v1/jobs/${job.jobId}/complete`, {
        nodeId: options.nodeId,
        result: outcome.result,
      })
      jobTrace(job, acknowledged ? 'job.complete' : 'job.error', acknowledged ? 'succeeded' : 'retrying')
      return
    }
    const acknowledged = await report(`/queue/v1/jobs/${job.jobId}/fail`, {
      nodeId: options.nodeId,
      reason: outcome.reason,
      retryable: outcome.kind === 'unavailable',
    })
    jobTrace(
      job,
      'job.error',
      outcome.kind === 'unavailable' || !acknowledged ? 'retrying' : 'failed',
    )
  }

  const loop = (async (): Promise<void> => {
    while (!stopped) {
      // A sick prover must not take work it cannot do: no health, no lease.
      if (!(await options.prover.healthy().catch(() => false))) {
        await sleep(pollMs)
        continue
      }
      let leased: LeasedJob | null = null
      try {
        const response = await queue('/queue/v1/lease', {
          nodeId: options.nodeId,
          capabilities: { gpu: options.gpu !== false },
        })
        if (response.status === 401) {
          log('Progress: the queue refused the node token; check ZKDEAL_QUEUE_NODE_TOKEN.')
        } else if (response.status === 200) {
          try {
            leased = parseLeasedJob(await response.json())
          } catch {
            log('Decision: the queue returned a job without a safe hosted correlation tuple; its lease will expire unexecuted.')
          }
        }
      } catch {
        // The queue being down is the same as the queue being empty: wait.
      }
      if (!leased) {
        await sleep(pollMs)
        continue
      }
      log(`Progress: leased ${leased.jobId} for ${leased.endpoint}.`)
      await work(leased)
    }
  })()

  return {
    stop: async () => {
      stopped = true
      wake?.()
      await loop
    },
  }
}

function main(): void {
  const queueUrl = process.env.QUEUE_URL?.trim()
  if (!queueUrl) throw new Error('QUEUE_URL is required')
  const nodeToken = process.env.ZKDEAL_QUEUE_NODE_TOKEN?.trim()
  if (!nodeToken) throw new Error('ZKDEAL_QUEUE_NODE_TOKEN is required')
  const nodeId = process.env.NODE_ID?.trim() || `agent-${randomUUID().slice(0, 8)}`
  const gpu = process.env.ZKDEAL_AGENT_GPU !== '0'
  const prover =
    createStubProver(process.env.ZKDEAL_AGENT_STUB?.trim() || undefined) ??
    createHttpLocalProver({
      proverUrl: process.env.PROVER_URL?.trim() || 'http://127.0.0.1:8080',
      proverToken: process.env.ZKDEAL_PROVER_TOKEN?.trim() || null,
    })
  const agent = startAgent({
    queueUrl,
    nodeToken,
    nodeId,
    prover,
    gpu,
    pollIntervalMs: process.env.POLL_INTERVAL_MS ? Number(process.env.POLL_INTERVAL_MS) : undefined,
    heartbeatIntervalMs: process.env.HEARTBEAT_INTERVAL_MS
      ? Number(process.env.HEARTBEAT_INTERVAL_MS)
      : undefined,
  })
  // The on-chain voucher only ever speaks while the local prover is healthy.
  const onChain = onChainOptionsFromEnv(process.env, nodeId, gpu, () =>
    prover.healthy().catch(() => false),
  )
  const reporter = onChain ? startOnChainHeartbeat(onChain) : null
  const shutdown = (): void => {
    reporter?.stop()
    void agent.stop().then(() => process.exit(0))
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
  process.stderr.write(`Decision: prover agent ${nodeId} is polling ${queueUrl}.\n`)
}

const entry = process.argv[1]
if (entry && import.meta.url === pathToFileURL(entry).href) main()
