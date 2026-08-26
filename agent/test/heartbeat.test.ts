/**
 * First coverage for the optional on-chain liveness loop (src/heartbeat.ts).
 *
 * The explicit loopback-development path builds a real viem public + wallet
 * client over http(rpcUrl), signs and sends reportNodeHeartbeat, and waits for
 * the receipt. We stand a local fake JSON-RPC server in front of that path:
 * a node http server that parses JSON-RPC bodies, dispatches on `method`,
 * records every method seen, and answers from a per-method scriptable queue (or
 * a sane default). Nothing here needs a chain - viem signs locally with the
 * explicit loopback-dev account and only the RPC surface has to be faithful.
 *
 * Reorg framing (see also the forge RoomManagerReorg suite and the web2
 * admission tests): a heartbeat whose settlement block is reorged out merely
 * delays the on-chain lastHealthyBlock by one interval; the permissionless
 * markNodeStale backstop on the pool remains the real liveness guarantee, so
 * the loop only has to (a) keep vouching while healthy, (b) go quiet when the
 * prover is sick, and (c) never die on a transient chain fault or a reverted /
 * lost receipt. Those are exactly D1-D4 below. Production tests use a second
 * fake server for the authenticated coordinator's durable operation/watcher
 * API; production never receives a raw key and never owns an L1 nonce.
 *
 * RPC methods viem 2.55.16 actually issues for one beat (verified against the
 * pinned source): writeContract -> eth_chainId, eth_getTransactionCount,
 * eth_getBlockByNumber (baseFee), eth_maxPriorityFeePerGas, eth_estimateGas,
 * eth_sendRawTransaction; waitForTransactionReceipt -> eth_blockNumber (watch),
 * eth_getTransactionByHash (replacement check, before the receipt), then
 * eth_getTransactionReceipt, and eth_getBlockByNumber(includeTransactions) only
 * when a receipt comes back null. Log strings emitted by heartbeat.ts:
 *   revert  -> 'Progress: the on-chain heartbeat reverted.'
 *   failure -> 'Progress: the on-chain heartbeat failed: <message>'
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import {
  onChainOptionsFromEnv,
  startOnChainHeartbeat,
  type OnChainHeartbeatClients,
  type OnChainHeartbeatOptions,
} from '../src/heartbeat.js'

// A well-known anvil dev key; used only to sign locally, never sent anywhere.
const SERVICE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const POOL_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
const NODE_ID = '0x1111111111111111111111111111111111111111111111111111111111111111'
const PROFILE_HASH = '0x2222222222222222222222222222222222222222222222222222222222222222'
const TX_HASH = '0xabababababababababababababababababababababababababababababababab'
const ACCOUNT = privateKeyToAccount(SERVICE_KEY).address.toLowerCase()

function bytes(byte: string, times: number): string {
  return `0x${byte.repeat(times)}`
}

function blockObject(): Record<string, unknown> {
  // Serves both fee estimation (latest block, needs baseFeePerGas) and the
  // replacement scan on a null receipt (needs an empty transactions array).
  return {
    number: '0x1',
    hash: bytes('22', 32),
    parentHash: bytes('00', 32),
    nonce: '0x0000000000000000',
    sha3Uncles: bytes('00', 32),
    logsBloom: bytes('00', 256),
    transactionsRoot: bytes('00', 32),
    stateRoot: bytes('00', 32),
    receiptsRoot: bytes('00', 32),
    miner: bytes('00', 20),
    difficulty: '0x0',
    totalDifficulty: '0x0',
    extraData: '0x',
    size: '0x0',
    gasLimit: '0x1c9c380',
    gasUsed: '0x0',
    timestamp: '0x1',
    transactions: [],
    uncles: [],
    baseFeePerGas: '0x1',
    mixHash: bytes('00', 32),
  }
}

function receiptObject(status: '0x1' | '0x0'): Record<string, unknown> {
  return {
    transactionHash: TX_HASH,
    transactionIndex: '0x0',
    blockHash: bytes('33', 32),
    blockNumber: '0x1',
    from: ACCOUNT,
    to: POOL_ADDRESS.toLowerCase(),
    cumulativeGasUsed: '0x5208',
    gasUsed: '0x5208',
    contractAddress: null,
    logs: [],
    logsBloom: bytes('00', 256),
    status,
    type: '0x2',
    effectiveGasPrice: '0x1',
  }
}

function pendingTxObject(): Record<string, unknown> {
  return {
    hash: TX_HASH,
    nonce: '0x0',
    blockHash: null,
    blockNumber: null,
    transactionIndex: null,
    from: ACCOUNT,
    to: POOL_ADDRESS.toLowerCase(),
    value: '0x0',
    gas: '0x5208',
    gasPrice: '0x1',
    input: '0x',
    type: '0x2',
    chainId: '0x7a69',
    maxFeePerGas: '0x2',
    maxPriorityFeePerGas: '0x1',
    accessList: [],
    v: '0x0',
    r: bytes('11', 32),
    s: bytes('22', 32),
    yParity: '0x0',
  }
}

interface FakeRpc {
  url: string
  server: Server
  calls: string[]
  unhandled: string[]
  countOf: (method: string) => number
  queue: (method: string, ...results: unknown[]) => void
  setFailAll: (fail: boolean) => void
  setReceiptStatus: (status: '0x1' | '0x0') => void
  close: () => Promise<void>
}

interface RecordedCoordinatorRequest {
  headers: Record<string, string | string[] | undefined>
  body: Record<string, unknown>
}

interface FakeCoordinator {
  url: string
  posts: RecordedCoordinatorRequest[]
  gets: RecordedCoordinatorRequest[]
  setOutcome: (outcome: 'included' | 'recovery-then-included' | 'missing-evidence') => void
  setFrom: (from: string) => void
  close: () => Promise<void>
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(chunk as Buffer)
  const text = Buffer.concat(chunks).toString('utf8')
  return text ? (JSON.parse(text) as Record<string, unknown>) : {}
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
}

async function startFakeRpc(): Promise<FakeRpc> {
  const calls: string[] = []
  const unhandled: string[] = []
  const queues = new Map<string, unknown[]>()
  const control = { failAll: false, receiptStatus: '0x1' as '0x1' | '0x0' }
  let blockNum = 1

  const defaultFor = (method: string): unknown => {
    switch (method) {
      case 'eth_chainId':
        return '0x7a69'
      case 'eth_getTransactionCount':
        return '0x0'
      case 'eth_gasPrice':
        return '0x1'
      case 'eth_maxPriorityFeePerGas':
        return '0x1'
      case 'eth_blockNumber':
        // Must advance so the receipt watcher re-polls on a fresh block.
        return `0x${(blockNum++).toString(16)}`
      case 'eth_getBlockByNumber':
      case 'eth_getBlockByHash':
        return blockObject()
      case 'eth_estimateGas':
        return '0x5208'
      case 'eth_fillTransaction':
        // viem 2.55.16 optimistically probes this Geth-only fill method as the
        // last step of prepareTransactionRequest; nonce/fees/gas are already
        // estimated by then, so a null "nothing to fill" answer merges
        // harmlessly and viem proceeds to sign and send.
        return null
      case 'eth_sendRawTransaction':
        return TX_HASH
      case 'eth_getTransactionReceipt':
        return receiptObject(control.receiptStatus)
      case 'eth_getTransactionByHash':
        return pendingTxObject()
      case 'eth_call':
        return '0x'
      default:
        unhandled.push(method)
        return null
    }
  }

  const server = createServer((request, response) => {
    void (async () => {
      const body = await readJson(request)
      const method = (body.method as string) ?? 'unknown'
      const id = body.id ?? null
      calls.push(method)
      if (control.failAll) {
        response.writeHead(500, { 'content-type': 'text/plain' })
        response.end('fake rpc failure')
        return
      }
      const q = queues.get(method)
      const result = q && q.length ? q.shift() : defaultFor(method)
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ jsonrpc: '2.0', id, result }))
    })().catch(() => {
      response.writeHead(500, { 'content-type': 'text/plain' })
      response.end('handler error')
    })
  })

  const url = await listen(server)
  return {
    url,
    server,
    calls,
    unhandled,
    countOf: (method) => calls.filter((c) => c === method).length,
    queue: (method, ...results) => {
      const q = queues.get(method) ?? []
      q.push(...results)
      queues.set(method, q)
    },
    setFailAll: (fail) => {
      control.failAll = fail
    },
    setReceiptStatus: (status) => {
      control.receiptStatus = status
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

async function startFakeCoordinator(): Promise<FakeCoordinator> {
  const posts: RecordedCoordinatorRequest[] = []
  const gets: RecordedCoordinatorRequest[] = []
  const control = {
    outcome: 'included' as 'included' | 'recovery-then-included' | 'missing-evidence',
    from: ACCOUNT,
    statusReads: 0,
  }

  const server = createServer((request, response) => {
    void (async () => {
      const path = new URL(request.url ?? '/', 'http://coordinator.invalid').pathname
      if (request.method === 'GET' && path === '/hosting/v1/capabilities') {
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(
          JSON.stringify({
            schemaVersion: 7,
            negotiation: {
              header: 'Accept-Schema-Version',
              supported: [6, 7],
              default: 7,
            },
          }),
        )
        return
      }

      if (request.method === 'POST' && path === '/hosting/v1/l1-operations/node-heartbeats') {
        const body = await readJson(request)
        posts.push({ headers: { ...request.headers }, body })
        const idempotencyKey = String(request.headers['idempotency-key'] ?? '')
        const correlationId = String(request.headers['x-correlation-id'] ?? '')
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(
          JSON.stringify({
            operationId: 'heartbeat-op-0001',
            idempotencyKey,
            correlationId,
            status: 'RESERVED',
            chainId: 31337,
            from: control.from,
            to: POOL_ADDRESS.toLowerCase(),
            nonce: '7',
            transactionHash: null,
          }),
        )
        return
      }

      if (
        request.method === 'GET' &&
        path === '/hosting/v1/l1-transactions/heartbeat-op-0001'
      ) {
        gets.push({ headers: { ...request.headers }, body: {} })
        control.statusReads++
        const idempotencyKey = String(posts.at(-1)?.headers['idempotency-key'] ?? '')
        const correlationId = String(posts.at(-1)?.headers['x-correlation-id'] ?? '')
        const recovery =
          control.outcome === 'recovery-then-included' && control.statusReads === 1
        const missingEvidence = control.outcome === 'missing-evidence'
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(
          JSON.stringify({
            operationId: 'heartbeat-op-0001',
            idempotencyKey,
            correlationId,
            status: recovery ? 'RECOVERY_REQUIRED' : 'INCLUDED',
            failureCode: recovery ? 'CANONICAL_RECEIPT_LOST' : undefined,
            chainId: 31337,
            from: control.from,
            to: POOL_ADDRESS.toLowerCase(),
            nonce: '7',
            transactionHash: TX_HASH,
            blockNumber: '123',
            blockHash: bytes('33', 32),
            confirmations: 2,
            receiptSource: missingEvidence
              ? undefined
              : {
                  providerIds: ['rpc-a', 'rpc-b'],
                  observedAt: '2026-08-21T12:00:00.000Z',
                  canonical: true,
                },
          }),
        )
        return
      }

      response.writeHead(404, { 'content-type': 'text/plain' })
      response.end('not found')
    })().catch((error) => {
      response.writeHead(500, { 'content-type': 'text/plain' })
      response.end(error instanceof Error ? error.message : 'handler error')
    })
  })

  const url = await listen(server)
  return {
    url,
    posts,
    gets,
    setOutcome: (outcome) => {
      control.outcome = outcome
      control.statusReads = 0
    },
    setFrom: (from) => {
      control.from = from
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

async function until(check: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!check()) {
    if (Date.now() > deadline) throw new Error('condition never became true')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

const REVERT_LINE = 'the on-chain heartbeat reverted'
const FAILURE_LINE = 'the on-chain heartbeat failed'

describe('the prover-node on-chain heartbeat', () => {
  const cleanups: Array<() => Promise<void> | void> = []
  const later = (fn: () => Promise<void> | void): void => {
    cleanups.push(fn)
  }
  afterEach(async () => {
    for (const fn of cleanups.splice(0).reverse()) await fn()
  })

  const baseOptions = (
    rpc: FakeRpc,
    overrides: Partial<OnChainHeartbeatOptions>,
  ): OnChainHeartbeatOptions => ({
    poolAddress: POOL_ADDRESS,
    livenessAccount: ACCOUNT as `0x${string}`,
    sender: { kind: 'dev-private-key', rpcUrl: rpc.url, privateKey: SERVICE_KEY },
    nodeId: NODE_ID,
    profileHash: PROFILE_HASH,
    intervalMs: 40,
    healthy: async () => true,
    ...overrides,
  })

  // D1 -----------------------------------------------------------------------
  it('reports a heartbeat while the prover is healthy', async () => {
    const rpc = await startFakeRpc()
    later(() => rpc.close())
    const logs: string[] = []
    const hb = startOnChainHeartbeat(
      baseOptions(rpc, { healthy: async () => true, log: (line) => logs.push(line) }),
    )
    later(() => hb.stop())

    await until(() => rpc.countOf('eth_sendRawTransaction') >= 1)
    // The write is only half of a beat; the loop must also confirm it.
    await until(() => rpc.countOf('eth_getTransactionReceipt') >= 1)

    expect(logs).toEqual([])
    // No method fell through to the default null answer.
    expect(rpc.unhandled).toEqual([])
  })

  // D2 -----------------------------------------------------------------------
  it('goes quiet on chain while the prover is unhealthy', async () => {
    const rpc = await startFakeRpc()
    later(() => rpc.close())
    const logs: string[] = []
    const hb = startOnChainHeartbeat(
      baseOptions(rpc, { healthy: async () => false, log: (line) => logs.push(line) }),
    )
    later(() => hb.stop())

    // Roughly five 40ms intervals: a sick prover must not touch the chain.
    await sleep(220)

    expect(rpc.calls).toEqual([])
    expect(logs).toEqual([])
  })

  // D3 -----------------------------------------------------------------------
  it('swallows an RPC failure and retries on the next interval', async () => {
    // Timing note: viem 2.55.16's http transport retries HTTP 500 (retryCount
    // 3, ~1.4s of backoff) before it throws. The explicit immediate re-send,
    // not the wide interval, must land beat 2 after the log callback clears the
    // fault. The single-flight guard prevents overlapping nonce use.
    const rpc = await startFakeRpc()
    later(() => rpc.close())
    const logs: string[] = []
    rpc.setFailAll(true)
    const hb = startOnChainHeartbeat(
      baseOptions(rpc, {
        intervalMs: 6000,
        retryDelayMs: 0,
        healthy: async () => true,
        log: (line) => {
          logs.push(line)
          // Clear the fault the moment beat 1 has failed and logged.
          if (line.includes(FAILURE_LINE)) rpc.setFailAll(false)
        },
      }),
    )
    later(() => hb.stop())

    // Attempt 2 is the immediate re-send; it lands before the 6s interval.
    await until(() => rpc.countOf('eth_sendRawTransaction') >= 1, 5_500)

    const failures = logs.filter((line) => line.includes(FAILURE_LINE))
    expect(failures).toHaveLength(1)
    // The failure path is a thrown exception, not a receipt revert.
    expect(logs.filter((line) => line.includes(REVERT_LINE))).toEqual([])
  })

  // D4 -----------------------------------------------------------------------
  // A heartbeat lost to a reorg is re-polled to canonical depth or immediately
  // re-sent. The loop stays alive and never overlaps writes from its account.
  it('re-polls a heartbeat receipt that is briefly missing (reorg re-land)', async () => {
    const rpc = await startFakeRpc()
    later(() => rpc.close())
    const logs: string[] = []
    // The settlement tx is not yet in the canonical chain: one null, then it
    // re-lands. viem re-polls on the next block (default 4s poll interval), so
    // give this a generous budget. A wide heartbeat interval keeps a single
    // beat in flight so the scripted queue is consumed by exactly that beat.
    rpc.queue('eth_getTransactionReceipt', null, receiptObject('0x1'))
    const hb = startOnChainHeartbeat(
      baseOptions(rpc, {
        intervalMs: 60_000,
        healthy: async () => true,
        log: (line) => logs.push(line),
      }),
    )
    later(() => hb.stop())

    // null poll, then the success poll on the next block.
    await until(() => rpc.countOf('eth_getTransactionReceipt') >= 2, 20_000)
    await sleep(300)

    expect(logs).toEqual([])
  })

  it('stays alive when a heartbeat receipt comes back reverted (orphaned block)', async () => {
    const rpc = await startFakeRpc()
    later(() => rpc.close())
    const logs: string[] = []
    rpc.setReceiptStatus('0x0')
    const hb = startOnChainHeartbeat(
      baseOptions(rpc, { healthy: async () => true, log: (line) => logs.push(line) }),
    )
    later(() => hb.stop())

    // Two reverts in one scheduled beat prove the immediate re-send ran.
    await until(() => logs.filter((line) => line.includes(REVERT_LINE)).length >= 2)

    expect(rpc.countOf('eth_sendRawTransaction')).toBeGreaterThanOrEqual(2)
    // A revert is a normal receipt, not a thrown fault.
    expect(logs.filter((line) => line.includes(FAILURE_LINE))).toEqual([])
  })

  it('uses the authenticated durable operation surface and reuses one logical operation on retry', async () => {
    const coordinator = await startFakeCoordinator()
    coordinator.setOutcome('recovery-then-included')
    later(() => coordinator.close())
    const logs: string[] = []
    const hb = startOnChainHeartbeat({
      poolAddress: POOL_ADDRESS,
      livenessAccount: ACCOUNT as `0x${string}`,
      sender: {
        kind: 'durable-coordinator',
        url: coordinator.url,
        bearerToken: 'scoped-l1-liveness-token',
        chainId: 31337,
        pollIntervalMs: 1,
      },
      nodeId: NODE_ID,
      profileHash: PROFILE_HASH,
      intervalMs: 60_000,
      retryDelayMs: 0,
      receiptTimeoutMs: 1_000,
      requestTimeoutMs: 500,
      confirmations: 2,
      now: () => 1_900_000_000_000,
      healthy: async () => true,
      log: (line) => logs.push(line),
    })
    later(() => hb.stop())

    await until(() => coordinator.posts.length === 2 && coordinator.gets.length >= 2)
    const [first, second] = coordinator.posts
    expect(first.headers.authorization).toBe('Bearer scoped-l1-liveness-token')
    // The fake deliberately advertises schema 7: the client must not hard-code 1.
    expect(first.headers['accept-schema-version']).toBe('7')
    expect(first.headers['idempotency-key']).toMatch(/^node-heartbeat:[0-9a-f]{64}$/)
    expect(first.headers['x-correlation-id']).toBe(first.headers['idempotency-key'])
    expect(second.headers['idempotency-key']).toBe(first.headers['idempotency-key'])
    expect(second.headers['x-correlation-id']).toBe(first.headers['x-correlation-id'])
    expect(second.body).toEqual(first.body)
    expect(first.body).toEqual({
      schemaVersion: 7,
      chainId: 31337,
      poolAddress: POOL_ADDRESS,
      expectedLivenessAccount: ACCOUNT,
      nodeId: NODE_ID,
      profileHash: PROFILE_HASH,
      confirmationPolicy: { minimumConfirmations: 2 },
    })
    expect('operationsAccount' in first.body).toBe(false)
    expect('payoutAccount' in first.body).toBe(false)
    expect(logs.some((line) => line.includes('RECOVERY_REQUIRED/CANONICAL_RECEIPT_LOST'))).toBe(
      true,
    )
  })

  it('fails closed when an included operation lacks canonical receipt-source evidence', async () => {
    const coordinator = await startFakeCoordinator()
    coordinator.setOutcome('missing-evidence')
    later(() => coordinator.close())
    const logs: string[] = []
    const hb = startOnChainHeartbeat({
      poolAddress: POOL_ADDRESS,
      livenessAccount: ACCOUNT as `0x${string}`,
      sender: {
        kind: 'durable-coordinator',
        url: coordinator.url,
        bearerToken: 'scoped-l1-liveness-token',
        chainId: 31337,
        pollIntervalMs: 1,
      },
      nodeId: NODE_ID,
      profileHash: PROFILE_HASH,
      intervalMs: 60_000,
      retryDelayMs: 0,
      receiptTimeoutMs: 1_000,
      requestTimeoutMs: 500,
      confirmations: 2,
      now: () => 1_900_000_000_000,
      healthy: async () => true,
      log: (line) => logs.push(line),
    })
    later(() => hb.stop())

    await until(
      () => logs.filter((line) => line.includes('lacks canonical receipt-source evidence')).length >= 2,
    )
    expect(coordinator.posts).toHaveLength(2)
    expect(coordinator.posts[1].headers['idempotency-key']).toBe(
      coordinator.posts[0].headers['idempotency-key'],
    )
  })

  it('rejects an operation not bound to the expected scoped liveness account', async () => {
    const coordinator = await startFakeCoordinator()
    coordinator.setFrom('0x3333333333333333333333333333333333333333')
    later(() => coordinator.close())
    const logs: string[] = []
    const hb = startOnChainHeartbeat({
      poolAddress: POOL_ADDRESS,
      livenessAccount: ACCOUNT as `0x${string}`,
      sender: {
        kind: 'durable-coordinator',
        url: coordinator.url,
        bearerToken: 'scoped-l1-liveness-token',
        chainId: 31337,
      },
      nodeId: NODE_ID,
      profileHash: PROFILE_HASH,
      intervalMs: 60_000,
      retryDelayMs: 0,
      requestTimeoutMs: 500,
      healthy: async () => true,
      log: (line) => logs.push(line),
    })
    later(() => hb.stop())

    await until(
      () => logs.filter((line) => line.includes('liveness account mismatch')).length >= 2,
    )
    expect(coordinator.gets).toHaveLength(0)
  })

  it('times out an unavailable durable publication boundary without touching other authorities', async () => {
    let waits = 0
    const logs: string[] = []
    const clients: OnChainHeartbeatClients = {
      publishHeartbeat: () => new Promise(() => undefined),
      waitForOutcome: async () => {
        waits++
        return { status: 'success' }
      },
    }
    const hb = startOnChainHeartbeat({
      poolAddress: POOL_ADDRESS,
      livenessAccount: ACCOUNT as `0x${string}`,
      sender: {
        kind: 'durable-coordinator',
        url: 'http://127.0.0.1:1',
        bearerToken: 'scoped-l1-liveness-token',
        chainId: 31337,
      },
      nodeId: NODE_ID,
      profileHash: PROFILE_HASH,
      intervalMs: 60_000,
      retryDelayMs: 0,
      requestTimeoutMs: 20,
      healthy: async () => true,
      clients,
      log: (line) => logs.push(line),
    })
    later(() => hb.stop())
    await until(() => logs.filter((line) => line.includes('timed out')).length >= 2)
    expect(waits).toBe(0)
  })

  it('requires the durable coordinator in production and confines raw keys to loopback dev mode', () => {
    const common = {
      ROOM_POOL: POOL_ADDRESS,
      NODE_LIVENESS_COORDINATOR_URL: 'https://hosting.example',
      NODE_LIVENESS_ACCOUNT: ACCOUNT,
      L1_CHAIN_ID: '1',
    }
    expect(() => onChainOptionsFromEnv(common, 'node', true, async () => true)).toThrow(
      /must be set together/,
    )
    const production = onChainOptionsFromEnv(
      { ...common, NODE_LIVENESS_COORDINATOR_AUTH_TOKEN: 'scoped-l1-liveness-token' },
      'node',
      true,
      async () => true,
    )!
    expect(production.sender.kind).toBe('durable-coordinator')
    expect(production.livenessAccount).toBe(ACCOUNT)
    expect('operationsAccount' in production).toBe(false)
    expect('payoutAccount' in production).toBe(false)

    expect(() =>
      onChainOptionsFromEnv(
        {
          ROOM_POOL: POOL_ADDRESS,
          L1_RPC_URL: 'https://l1.example',
          NODE_LIVENESS_DEV_MODE: 'true',
          NODE_LIVENESS_DEV_PRIVATE_KEY: SERVICE_KEY,
        },
        'node',
        true,
        async () => true,
      ),
    ).toThrow(/loopback/)
    const dev = onChainOptionsFromEnv(
      {
        ROOM_POOL: POOL_ADDRESS,
        L1_RPC_URL: 'http://127.0.0.1:8545',
        NODE_LIVENESS_DEV_MODE: 'true',
        NODE_LIVENESS_DEV_PRIVATE_KEY: SERVICE_KEY,
      },
      'node',
      true,
      async () => true,
    )!
    expect(dev.sender.kind).toBe('dev-private-key')
    expect(() =>
      onChainOptionsFromEnv(
        { ...common, NODE_SERVICE_KEY: SERVICE_KEY },
        'node',
        true,
        async () => true,
      ),
    ).toThrow(/NODE_SERVICE_KEY is forbidden/)
    expect(() =>
      onChainOptionsFromEnv(
        {
          ...common,
          NODE_LIVENESS_SIGNER_URL: 'https://signer.example',
          NODE_LIVENESS_COORDINATOR_AUTH_TOKEN: 'scoped-l1-liveness-token',
        },
        'node',
        true,
        async () => true,
      ),
    ).toThrow(/direct Web3Signer heartbeat publication is forbidden/)
  })
})
