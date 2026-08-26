/**
 * The agent against an in-process fake queue and fake prover.
 *
 * What must hold: a leased job comes back as the prover's verbatim JSON with
 * the prover bearer forwarded; the prover judging a request (4xx) condemns
 * it while a broken prover (5xx, unreachable) only forfeits the attempt; the
 * lease is heartbeaten while the proof runs; an unhealthy prover means no
 * lease is ever taken; and the stub modes behave exactly as the compose e2e
 * relies on them to.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { readFile } from 'node:fs/promises'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { startAgent, type AgentController, type LeasedJob } from '../src/agent.js'
import { createHttpLocalProver, createStubProver } from '../src/local-prover.js'
import {
  agentTraceRecord,
  type AgentTraceInput,
  type AgentTraceRecord,
} from '../src/structured-log.js'

const NODE_TOKEN = 'unit-test-node-token'

interface FakeQueue {
  url: string
  server: Server
  jobs: LeasedJob[]
  leases: Array<{ nodeId: string; capabilities: unknown; authorization: string | undefined }>
  heartbeats: Array<{ jobId: string; nodeId: string }>
  completions: Array<{ jobId: string; nodeId: string; result: unknown }>
  failures: Array<{ jobId: string; nodeId: string; reason: string; retryable: boolean }>
}

function json(response: ServerResponse, status: number, body?: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' })
  response.end(body === undefined ? undefined : JSON.stringify(body))
}

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(chunk as Buffer)
  const text = Buffer.concat(chunks).toString('utf8')
  return text ? (JSON.parse(text) as Record<string, unknown>) : {}
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
}

async function startFakeQueue(): Promise<FakeQueue> {
  const queue: Omit<FakeQueue, 'url' | 'server'> = {
    jobs: [],
    leases: [],
    heartbeats: [],
    completions: [],
    failures: [],
  }
  const server = createServer((request, response) => {
    void (async () => {
      const body = await readBody(request)
      const url = request.url ?? ''
      if (url === '/queue/v1/lease') {
        if (request.headers.authorization !== `Bearer ${NODE_TOKEN}`) {
          return json(response, 401, { error: 'bad bearer' })
        }
        queue.leases.push({
          nodeId: body.nodeId as string,
          capabilities: body.capabilities,
          authorization: request.headers.authorization,
        })
        const job = queue.jobs.shift()
        if (!job) return json(response, 204)
        return json(response, 200, job)
      }
      const action = /^\/queue\/v1\/jobs\/([^/]+)\/(heartbeat|complete|fail)$/.exec(url)
      if (action) {
        const [, jobId, verb] = action
        if (verb === 'heartbeat') queue.heartbeats.push({ jobId: jobId!, nodeId: body.nodeId as string })
        if (verb === 'complete') {
          queue.completions.push({ jobId: jobId!, nodeId: body.nodeId as string, result: body.result })
        }
        if (verb === 'fail') {
          queue.failures.push({
            jobId: jobId!,
            nodeId: body.nodeId as string,
            reason: body.reason as string,
            retryable: body.retryable as boolean,
          })
        }
        return json(response, 200, { ok: true })
      }
      return json(response, 404, { error: 'unknown route' })
    })().catch(() => json(response, 500))
  })
  const url = await listen(server)
  return { ...queue, url, server }
}

interface FakeProverBehavior {
  healthy?: boolean
  status?: number
  delayMs?: number
  body?: unknown
}

async function startFakeProver(behavior: FakeProverBehavior): Promise<{
  url: string
  server: Server
  requests: Array<{ url: string; authorization: string | undefined; body: unknown }>
}> {
  const requests: Array<{ url: string; authorization: string | undefined; body: unknown }> = []
  const server = createServer((request, response) => {
    void (async () => {
      if (request.url === '/healthz') {
        return json(response, behavior.healthy === false ? 503 : 200, { status: 'ok' })
      }
      const body = await readBody(request)
      requests.push({ url: request.url ?? '', authorization: request.headers.authorization, body })
      if (behavior.delayMs) await new Promise((resolve) => setTimeout(resolve, behavior.delayMs))
      return json(response, behavior.status ?? 200, behavior.body ?? { decision: 'proved' })
    })().catch(() => json(response, 500))
  })
  const url = await listen(server)
  return { url, server, requests }
}

async function until(check: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!check()) {
    if (Date.now() > deadline) throw new Error('condition never became true')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

function lineage(jobId: string, roomId: string | null = '7'): Pick<
  LeasedJob,
  'jobId' | 'tenantId' | 'roomId' | 'correlationId'
> {
  return { jobId, tenantId: 'tenant-a', roomId, correlationId: `trace:${jobId}` }
}

describe('the prover-node agent', () => {
  const cleanups: Array<() => Promise<void> | void> = []
  const later = (fn: () => Promise<void> | void): void => {
    cleanups.push(fn)
  }
  afterEach(async () => {
    for (const fn of cleanups.splice(0).reverse()) await fn()
  })

  const run = (
    queueUrl: string,
    prover: Parameters<typeof startAgent>[0]['prover'],
    trace?: (input: AgentTraceInput) => void,
    log: (line: string) => void = () => {},
  ): AgentController => {
    const agent = startAgent({
      queueUrl,
      nodeToken: NODE_TOKEN,
      nodeId: 'unit-node',
      prover,
      pollIntervalMs: 25,
      heartbeatIntervalMs: 50,
      log,
      trace,
    })
    later(() => agent.stop())
    return agent
  }

  it('leases, forwards with the prover bearer, and completes verbatim', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({ body: { decision: 'proved', sealB64: 'abc' } })
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000001'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: { witness: 'w' },
    })
    const traces: AgentTraceRecord[] = []
    run(
      queue.url,
      createHttpLocalProver({ proverUrl: prover.url, proverToken: 's3cret' }),
      (input) => traces.push(agentTraceRecord(input)),
    )
    await until(() => queue.completions.length === 1)
    expect(queue.completions[0]).toEqual({
      jobId: 'pj-0000000001',
      nodeId: 'unit-node',
      result: { decision: 'proved', sealB64: 'abc' },
    })
    expect(prover.requests[0]).toMatchObject({
      url: '/v5/rooms/prove',
      authorization: 'Bearer s3cret',
      body: { witness: 'w' },
    })
    expect(traces.map(({ event, outcome }) => ({ event, outcome }))).toEqual([
      { event: 'job.start', outcome: 'started' },
      { event: 'job.complete', outcome: 'succeeded' },
    ])
    expect(traces[0]).toMatchObject({
      schemaVersion: 1,
      correlationId: 'trace:pj-0000000001',
      tenantId: 'tenant-a',
      roomId: '7',
      jobId: 'pj-0000000001',
      operationId: null,
      component: 'prover-agent',
    })
    const serialized = JSON.stringify(traces)
    for (const forbidden of ['s3cret', 'witness', 'sealB64', 'request', 'result', 'authorization', 'token']) {
      expect(serialized).not.toContain(forbidden)
    }
  })

  it('reports a prover 400 as a non-retryable failure', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({
      status: 400,
      body: { decision: 'request-rejected', reason: 'bad witness' },
    })
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000002'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    const traces: AgentTraceRecord[] = []
    run(queue.url, createHttpLocalProver({ proverUrl: prover.url }), (input) => {
      traces.push(agentTraceRecord(input))
    })
    await until(() => queue.failures.length === 1)
    expect(queue.failures[0]).toMatchObject({ reason: 'bad witness', retryable: false })
    expect(traces.at(-1)).toMatchObject({ event: 'job.error', outcome: 'failed' })
  })

  it('reports a prover 500 as retryable', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({ status: 500, body: { boom: true } })
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000003'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    const traces: AgentTraceRecord[] = []
    run(queue.url, createHttpLocalProver({ proverUrl: prover.url }), (input) => {
      traces.push(agentTraceRecord(input))
    })
    await until(() => queue.failures.length === 1)
    expect(queue.failures[0]).toMatchObject({ retryable: true })
    expect(traces.at(-1)).toMatchObject({ event: 'job.error', outcome: 'retrying' })
  })

  it('reports an unreachable prover as retryable', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000004'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    // A prover whose /healthz answers but whose proof port is gone: point the
    // forward at a closed port while health rides a live server.
    const health = await startFakeProver({})
    later(() => void health.server.close())
    const dead = await startFakeProver({})
    const deadUrl = dead.url
    await new Promise<void>((resolve) => dead.server.close(() => resolve()))
    const prover = {
      healthy: () => createHttpLocalProver({ proverUrl: health.url }).healthy(),
      forward: (endpoint: string, request: unknown) =>
        createHttpLocalProver({ proverUrl: deadUrl }).forward(endpoint, request),
    }
    run(queue.url, prover)
    await until(() => queue.failures.length === 1)
    expect(queue.failures[0]?.retryable).toBe(true)
    expect(queue.failures[0]?.reason).toMatch(/unreachable/)
  })

  it('refuses a leased job whose owner correlation tuple is missing', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({})
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000009'),
      tenantId: '',
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: { shouldNotReachProver: true },
    })
    const traces: AgentTraceRecord[] = []
    const logs: string[] = []
    run(
      queue.url,
      createHttpLocalProver({ proverUrl: prover.url }),
      (input) => traces.push(agentTraceRecord(input)),
      (line) => logs.push(line),
    )
    await until(() => queue.leases.length >= 1)
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(prover.requests).toEqual([])
    expect(queue.completions).toEqual([])
    expect(traces).toEqual([])
    expect(logs.join('\n')).toMatch(/safe hosted correlation tuple/)
  })

  it('heartbeats the lease while the proof runs', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({ delayMs: 300 })
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000005'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    run(queue.url, createHttpLocalProver({ proverUrl: prover.url }))
    await until(() => queue.completions.length === 1)
    // 300ms of proving with a 50ms heartbeat: several must have landed.
    expect(queue.heartbeats.length).toBeGreaterThanOrEqual(2)
    expect(queue.heartbeats[0]).toEqual({ jobId: 'pj-0000000005', nodeId: 'unit-node' })
  })

  it('takes no lease while the local prover is unhealthy', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    const prover = await startFakeProver({ healthy: false })
    later(() => void prover.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000006'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    run(queue.url, createHttpLocalProver({ proverUrl: prover.url }))
    await new Promise((resolve) => setTimeout(resolve, 300))
    expect(queue.leases).toEqual([])
    expect(queue.jobs).toHaveLength(1)
  })

  it('completes via the ok:<ms> stub without any prover at all', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000007', null),
      endpoint: '/v5/cold-templates/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    run(queue.url, createStubProver('ok:50')!)
    await until(() => queue.completions.length === 1)
    expect(queue.completions[0]?.result).toMatchObject({
      decision: 'stub-proof',
      endpoint: '/v5/cold-templates/prove',
    })
  })

  it('the take-and-die stub dies exactly at the forward, lease already taken', async () => {
    const queue = await startFakeQueue()
    later(() => void queue.server.close())
    queue.jobs.push({
      ...lineage('pj-0000000008'),
      endpoint: '/v5/rooms/prove',
      needsGpu: true,
      attempts: 1,
      request: {},
    })
    let died = false
    const stub = createStubProver('take-and-die', {
      die: () => {
        died = true
        // The real stub calls process.exit(1); the test stands in with a
        // throw so the death is observable instead of fatal.
        throw new Error('stub died')
      },
    })!
    run(queue.url, stub)
    await until(() => died)
    expect(queue.leases.length).toBeGreaterThanOrEqual(1)
    // The death surfaces as a retryable failure report at worst - never as a
    // completion.
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(queue.completions).toEqual([])
  })

  it('refuses an unknown stub mode loudly', () => {
    expect(() => createStubProver('explode')).toThrow(/ZKDEAL_AGENT_STUB/)
  })

  it('shares the exact owner trace envelope and join tuple fixture', async () => {
    type FixtureRecord = Omit<AgentTraceRecord, 'component' | 'event' | 'outcome'> & {
      component: string
      event: string
      outcome: string
    }
    const fixture = JSON.parse(await readFile(
      new URL('./fixtures/hosted-trace-join.json', import.meta.url),
      'utf8',
    )) as { joinFields: string[]; records: FixtureRecord[] }
    expect(fixture.joinFields).toEqual(['correlationId', 'tenantId', 'roomId', 'jobId'])
    const keys = fixture.records.map((record) => fixture.joinFields.map(
      (field) => String(record[field as keyof FixtureRecord] ?? ''),
    ).join('|'))
    expect(new Set(keys).size).toBe(1)
    const agentRecords = fixture.records.filter((record) => record.component === 'prover-agent')
    expect(agentRecords.map(({ event, outcome }) => ({ event, outcome }))).toEqual([
      { event: 'job.start', outcome: 'started' },
      { event: 'job.complete', outcome: 'succeeded' },
    ])
    for (const record of agentRecords) {
      expect(agentTraceRecord({
        correlationId: record.correlationId,
        tenantId: record.tenantId,
        roomId: record.roomId,
        jobId: record.jobId,
        event: record.event as AgentTraceInput['event'],
        outcome: record.outcome as AgentTraceInput['outcome'],
      }, new Date(record.timestamp))).toEqual(record)
    }
  })
})
