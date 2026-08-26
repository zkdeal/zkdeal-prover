/**
 * Optional on-chain liveness: `reportNodeHeartbeat(nodeId, profileHash)` on
 * the room-pool registry, authorized only by the node's scoped liveness
 * account. Production publication is an authenticated request to the hosted
 * coordinator's durable L1 operation/nonce/watcher surface. The agent never
 * owns a production signer or nonce.
 *
 * A direct viem/raw-key sender exists only for an explicit loopback
 * development chain. In either mode, the loop reports only while the local
 * prover answers its health probe: an agent whose GPU died must go quiet.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  toBytes,
  type Address,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const REPORT_NODE_HEARTBEAT_ABI = [
  {
    type: 'function',
    name: 'reportNodeHeartbeat',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'nodeId', type: 'bytes32' },
      { name: 'profileHash', type: 'bytes32' },
    ],
    outputs: [],
  },
] as const

const REPORT_NODE_HEARTBEAT_SELECTOR = '0x7cd0e630'
const CAPABILITIES_PATH = '/hosting/v1/capabilities'
const HEARTBEAT_OPERATION_PATH = '/hosting/v1/l1-operations/node-heartbeats'
const L1_OPERATION_PATH = '/hosting/v1/l1-transactions'

export type HeartbeatSender =
  | {
      kind: 'durable-coordinator'
      url: string
      bearerToken: string
      chainId: number
      pollIntervalMs?: number
    }
  | {
      kind: 'dev-private-key'
      rpcUrl: string
      privateKey: Hex
    }

export interface OnChainHeartbeatOptions {
  poolAddress: Address
  livenessAccount: Address
  sender: HeartbeatSender
  /** bytes32 pool node id (NOT the queue's free-form nodeId label). */
  nodeId: Hex
  profileHash: Hex
  intervalMs?: number
  /** Canonical depth required before a heartbeat is considered landed. */
  confirmations?: number
  /** Bound a lost/orphaned receipt or durable operation watcher. */
  receiptTimeoutMs?: number
  /** Delay before the one immediate retry after a transport/reorg failure. */
  retryDelayMs?: number
  /** Bound each coordinator, signer, or direct-development send request. */
  requestTimeoutMs?: number
  healthy: () => Promise<boolean>
  log?: (line: string) => void
  /** Injectable publication boundary used by deterministic tests. */
  clients?: OnChainHeartbeatClients
  /** Injectable clock used only to derive a logical heartbeat idempotency bucket. */
  now?: () => number
}

export interface HeartbeatPublishContext {
  logicalBeat: number
  confirmations: number
}

export interface HeartbeatPublication {
  reference: string
  idempotencyKey: string
  correlationId: string
}

export interface HeartbeatOutcome {
  status: 'success' | 'reverted' | 'failed'
  reason?: string
}

export interface OnChainHeartbeatClients {
  publishHeartbeat: (context: HeartbeatPublishContext) => Promise<HeartbeatPublication>
  waitForOutcome: (
    publication: HeartbeatPublication,
    confirmations: number,
    timeoutMs: number,
  ) => Promise<HeartbeatOutcome>
}

interface DurableOperation {
  operationId: string
  idempotencyKey: string
  correlationId: string
  status: DurableOperationStatus
  chainId: number
  from: Address
  to: Address
  nonce: string
  transactionHash: Hex | null
  blockNumber?: string
  blockHash?: Hex
  confirmations?: number
  receiptSource?: {
    providerIds: string[]
    observedAt: string
    canonical: true
  }
  finalized?: true
  failureCode?: string
}

type DurableOperationStatus =
  | 'RESERVED'
  | 'SIGNED'
  | 'ARCHIVED'
  | 'BROADCAST'
  | 'INCLUDED'
  | 'FINALIZED'
  | 'FAILED'
  | 'RECOVERY_REQUIRED'
  | 'SUPERSEDED'

const DURABLE_STATUSES = new Set<DurableOperationStatus>([
  'RESERVED',
  'SIGNED',
  'ARCHIVED',
  'BROADCAST',
  'INCLUDED',
  'FINALIZED',
  'FAILED',
  'RECOVERY_REQUIRED',
  'SUPERSEDED',
])

const DEFAULT_ONCHAIN_INTERVAL_MS = 60_000
const DEFAULT_HEARTBEAT_CONFIRMATIONS = 2
const DEFAULT_RECEIPT_TIMEOUT_MS = 45_000
const DEFAULT_RETRY_DELAY_MS = 1_000
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000
const DEFAULT_COORDINATOR_POLL_MS = 1_000

/**
 * The queue label is free-form; the pool key is bytes32. A label already 32
 * hex bytes is used verbatim; anything else is hashed into a stable key.
 */
export function poolNodeId(label: string): Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(label)
    ? (label.toLowerCase() as Hex)
    : keccak256(toBytes(label))
}

export function profileHashFor(label: string, gpu: boolean): Hex {
  return keccak256(toBytes(`zkdeal-prover-agent/${label}/gpu=${gpu}`))
}

function isLoopbackUrl(raw: string): boolean {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return false
  }
  return ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(url.hostname.toLowerCase())
}

function addressFromEnv(name: string, value: string | undefined): Address {
  if (!value || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${name} must be a 20-byte hexadecimal address`)
  }
  return value.toLowerCase() as Address
}

function positiveNumber(name: string, raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined
  const value = Number(raw)
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be positive`)
  return value
}

function positiveInteger(name: string, raw: string | undefined): number | undefined {
  const value = positiveNumber(name, raw)
  if (value !== undefined && !Number.isSafeInteger(value)) {
    throw new Error(`${name} must be a positive safe integer`)
  }
  return value
}

/** Read the optional on-chain config; null disables the loop entirely. */
export function onChainOptionsFromEnv(
  env: NodeJS.ProcessEnv,
  label: string,
  gpu: boolean,
  healthy: () => Promise<boolean>,
): OnChainHeartbeatOptions | null {
  const poolAddress = env.ROOM_POOL
  const coordinatorUrl = env.NODE_LIVENESS_COORDINATOR_URL
  const coordinatorToken = env.NODE_LIVENESS_COORDINATOR_AUTH_TOKEN
  const expectedAccount = env.NODE_LIVENESS_ACCOUNT
  const chainId = positiveInteger('L1_CHAIN_ID', env.L1_CHAIN_ID)
  const rpcUrl = env.L1_RPC_URL
  const devPrivateKey = env.NODE_LIVENESS_DEV_PRIVATE_KEY
  const requested = [
    poolAddress,
    coordinatorUrl,
    coordinatorToken,
    expectedAccount,
    env.L1_CHAIN_ID,
    rpcUrl,
    devPrivateKey,
    env.NODE_SERVICE_KEY,
    env.NODE_LIVENESS_SIGNER_URL,
    env.NODE_LIVENESS_SIGNER_AUTH_TOKEN,
  ].some(Boolean)
  if (!requested) return null
  if (env.NODE_SERVICE_KEY) {
    throw new Error('NODE_SERVICE_KEY is forbidden for liveness publication')
  }
  if (env.NODE_LIVENESS_SIGNER_URL || env.NODE_LIVENESS_SIGNER_AUTH_TOKEN) {
    throw new Error(
      'direct Web3Signer heartbeat publication is forbidden; use the durable coordinator transport',
    )
  }
  if (!poolAddress) throw new Error('ROOM_POOL is required when on-chain liveness is configured')
  const normalizedPool = addressFromEnv('ROOM_POOL', poolAddress)

  let livenessAccount: Address
  let sender: HeartbeatSender
  if (coordinatorUrl || coordinatorToken || expectedAccount || chainId !== undefined) {
    if (!coordinatorUrl || !coordinatorToken || !expectedAccount || chainId === undefined) {
      throw new Error(
        'NODE_LIVENESS_COORDINATOR_URL, NODE_LIVENESS_COORDINATOR_AUTH_TOKEN, NODE_LIVENESS_ACCOUNT, and L1_CHAIN_ID must be set together',
      )
    }
    if (devPrivateKey || env.NODE_LIVENESS_DEV_MODE === 'true') {
      throw new Error('durable coordinator and direct development heartbeat modes are mutually exclusive')
    }
    livenessAccount = addressFromEnv('NODE_LIVENESS_ACCOUNT', expectedAccount)
    sender = {
      kind: 'durable-coordinator',
      url: coordinatorUrl,
      bearerToken: coordinatorToken,
      chainId,
      pollIntervalMs: positiveNumber(
        'NODE_LIVENESS_COORDINATOR_POLL_MS',
        env.NODE_LIVENESS_COORDINATOR_POLL_MS,
      ),
    }
  } else if (devPrivateKey) {
    if (env.NODE_LIVENESS_DEV_MODE !== 'true' || !rpcUrl || !isLoopbackUrl(rpcUrl)) {
      throw new Error(
        'NODE_LIVENESS_DEV_PRIVATE_KEY requires NODE_LIVENESS_DEV_MODE=true and a loopback L1_RPC_URL',
      )
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(devPrivateKey)) {
      throw new Error('NODE_LIVENESS_DEV_PRIVATE_KEY must be a 32-byte hexadecimal private key')
    }
    const account = privateKeyToAccount(devPrivateKey as Hex)
    livenessAccount = account.address.toLowerCase() as Address
    sender = { kind: 'dev-private-key', rpcUrl, privateKey: devPrivateKey as Hex }
  } else {
    throw new Error('production on-chain liveness requires the durable coordinator transport')
  }

  return {
    poolAddress: normalizedPool,
    livenessAccount,
    sender,
    nodeId: poolNodeId(label),
    profileHash: profileHashFor(label, gpu),
    intervalMs: positiveNumber('NODE_LIVENESS_INTERVAL_MS', env.NODE_LIVENESS_INTERVAL_MS),
    confirmations: positiveInteger(
      'NODE_LIVENESS_CONFIRMATIONS',
      env.NODE_LIVENESS_CONFIRMATIONS,
    ),
    receiptTimeoutMs: positiveNumber(
      'NODE_LIVENESS_RECEIPT_TIMEOUT_MS',
      env.NODE_LIVENESS_RECEIPT_TIMEOUT_MS,
    ),
    retryDelayMs: positiveNumber(
      'NODE_LIVENESS_RETRY_DELAY_MS',
      env.NODE_LIVENESS_RETRY_DELAY_MS,
    ),
    requestTimeoutMs: positiveNumber(
      'NODE_LIVENESS_REQUEST_TIMEOUT_MS',
      env.NODE_LIVENESS_REQUEST_TIMEOUT_MS,
    ),
    healthy,
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  return value as Record<string, unknown>
}

function endpoint(base: string, path: string): string {
  return `${base.replace(/\/+$/, '')}${path}`
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  label: string,
): Promise<unknown> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  timer.unref?.()
  try {
    const response = await fetch(url, { ...init, signal: controller.signal })
    const text = await response.text()
    if (!response.ok) {
      throw new Error(`${label} returned HTTP ${response.status}${text ? `: ${text.slice(0, 256)}` : ''}`)
    }
    try {
      return text ? JSON.parse(text) : {}
    } catch {
      throw new Error(`${label} returned invalid JSON`)
    }
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`${label} timed out after ${timeoutMs}ms`)
    }
    throw error
  } finally {
    clearTimeout(timer)
  }
}

function parseAddress(value: unknown, label: string): Address {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${label} is not an address`)
  }
  return value.toLowerCase() as Address
}

function parseDurableOperation(
  value: unknown,
  expected: {
    chainId: number
    from: Address
    to: Address
    idempotencyKey: string
    correlationId: string
  },
): DurableOperation {
  const source = record(value, 'durable heartbeat operation')
  const operationId = source.operationId
  const status = source.status
  const nonce = source.nonce
  if (typeof operationId !== 'string' || operationId.length < 8 || operationId.length > 200) {
    throw new Error('durable heartbeat operationId is invalid')
  }
  if (typeof status !== 'string' || !DURABLE_STATUSES.has(status as DurableOperationStatus)) {
    throw new Error(`durable heartbeat operation status is invalid: ${String(status)}`)
  }
  if (source.chainId !== expected.chainId) throw new Error('durable heartbeat chainId mismatch')
  if (source.idempotencyKey !== expected.idempotencyKey) {
    throw new Error('durable heartbeat idempotency key mismatch')
  }
  if (source.correlationId !== expected.correlationId) {
    throw new Error('durable heartbeat correlation id mismatch')
  }
  const from = parseAddress(source.from, 'durable heartbeat from')
  const to = parseAddress(source.to, 'durable heartbeat to')
  if (from !== expected.from.toLowerCase()) throw new Error('durable heartbeat liveness account mismatch')
  if (to !== expected.to.toLowerCase()) throw new Error('durable heartbeat pool target mismatch')
  if (typeof nonce !== 'string' || !/^(0|[1-9][0-9]*)$/.test(nonce)) {
    throw new Error('durable heartbeat nonce is not canonical decimal')
  }
  const transactionHash = source.transactionHash
  if (
    transactionHash !== null &&
    (typeof transactionHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(transactionHash))
  ) {
    throw new Error('durable heartbeat transactionHash is invalid')
  }

  const operation: DurableOperation = {
    operationId,
    idempotencyKey: expected.idempotencyKey,
    correlationId: expected.correlationId,
    status: status as DurableOperationStatus,
    chainId: expected.chainId,
    from,
    to,
    nonce,
    transactionHash: transactionHash === null ? null : (transactionHash.toLowerCase() as Hex),
  }
  if (typeof source.blockNumber === 'string') operation.blockNumber = source.blockNumber
  if (typeof source.blockHash === 'string') operation.blockHash = source.blockHash as Hex
  if (typeof source.confirmations === 'number') operation.confirmations = source.confirmations
  if (source.finalized === true) operation.finalized = true
  if (typeof source.failureCode === 'string') operation.failureCode = source.failureCode
  if (source.receiptSource !== undefined) {
    const evidence = record(source.receiptSource, 'durable heartbeat receiptSource')
    if (
      !Array.isArray(evidence.providerIds) ||
      evidence.providerIds.length === 0 ||
      evidence.providerIds.some(
        (item) => typeof item !== 'string' || item.length === 0 || item.length > 200,
      )
    ) {
      throw new Error('durable heartbeat receiptSource.providerIds is invalid')
    }
    operation.receiptSource = {
      providerIds: evidence.providerIds as string[],
      observedAt: typeof evidence.observedAt === 'string' ? evidence.observedAt : '',
      canonical: evidence.canonical as true,
    }
  }
  return operation
}

function canonicalOutcome(
  operation: DurableOperation,
  requiredConfirmations: number,
): HeartbeatOutcome | null {
  if (
    operation.status === 'FAILED' ||
    operation.status === 'RECOVERY_REQUIRED' ||
    operation.status === 'SUPERSEDED'
  ) {
    return {
      status: 'failed',
      reason: `${operation.status}${operation.failureCode ? `/${operation.failureCode}` : ''}`,
    }
  }
  if (operation.status !== 'INCLUDED' && operation.status !== 'FINALIZED') return null
  if (!operation.transactionHash) {
    throw new Error('included heartbeat lacks a transactionHash')
  }
  if (!operation.blockNumber || !/^(0|[1-9][0-9]*)$/.test(operation.blockNumber)) {
    throw new Error('included heartbeat lacks canonical decimal blockNumber')
  }
  if (!operation.blockHash || !/^0x[0-9a-fA-F]{64}$/.test(operation.blockHash)) {
    throw new Error('included heartbeat lacks a canonical blockHash')
  }
  if (
    !Number.isSafeInteger(operation.confirmations) ||
    (operation.confirmations ?? 0) < requiredConfirmations
  ) {
    throw new Error('included heartbeat has insufficient canonical confirmations')
  }
  const source = operation.receiptSource
  if (
    !source ||
    source.canonical !== true ||
    source.providerIds.length === 0 ||
    !source.observedAt ||
    !Number.isFinite(Date.parse(source.observedAt))
  ) {
    throw new Error('included heartbeat lacks canonical receipt-source evidence')
  }
  if (operation.status === 'FINALIZED' && operation.finalized !== true) {
    throw new Error('finalized heartbeat lacks finalized=true evidence')
  }
  return { status: 'success' }
}

function durableCoordinatorClients(
  options: OnChainHeartbeatOptions,
  sender: Extract<HeartbeatSender, { kind: 'durable-coordinator' }>,
): OnChainHeartbeatClients {
  const requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  const pollIntervalMs = sender.pollIntervalMs ?? DEFAULT_COORDINATOR_POLL_MS
  let negotiated:
    | Promise<{ schemaVersion: number; header: 'Accept-Schema-Version' }>
    | undefined

  const negotiate = (): Promise<{ schemaVersion: number; header: 'Accept-Schema-Version' }> => {
    if (!negotiated) {
      negotiated = (async () => {
        const value = await fetchJson(
          endpoint(sender.url, CAPABILITIES_PATH),
          { method: 'GET', headers: { Accept: 'application/json' } },
          requestTimeoutMs,
          'coordinator capability negotiation',
        )
        const capabilities = record(value, 'coordinator capabilities')
        const negotiation = record(capabilities.negotiation, 'coordinator schema negotiation')
        const schemaVersion = Number(capabilities.schemaVersion)
        if (!Number.isSafeInteger(schemaVersion) || schemaVersion < 1) {
          throw new Error('coordinator advertised an invalid schema version')
        }
        if (String(negotiation.header).toLowerCase() !== 'accept-schema-version') {
          throw new Error('coordinator does not advertise Accept-Schema-Version negotiation')
        }
        if (
          !Array.isArray(negotiation.supported) ||
          !negotiation.supported.some((item) => Number(item) === schemaVersion)
        ) {
          throw new Error('coordinator current schema is not in its supported schema set')
        }
        return { schemaVersion, header: 'Accept-Schema-Version' as const }
      })().catch((error) => {
        negotiated = undefined
        throw error
      })
    }
    return negotiated
  }

  const headers = (
    schemaVersion: number,
    correlationId: string,
    idempotencyKey?: string,
  ): Record<string, string> => ({
    Authorization: `Bearer ${sender.bearerToken}`,
    Accept: 'application/json',
    'Accept-Schema-Version': String(schemaVersion),
    'X-Correlation-Id': correlationId,
    ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
  })

  return {
    publishHeartbeat: async ({ logicalBeat, confirmations }) => {
      const { schemaVersion } = await negotiate()
      const body = {
        schemaVersion,
        chainId: sender.chainId,
        poolAddress: options.poolAddress,
        expectedLivenessAccount: options.livenessAccount,
        nodeId: options.nodeId,
        profileHash: options.profileHash,
        confirmationPolicy: { minimumConfirmations: confirmations },
      }
      const digest = keccak256(toBytes(JSON.stringify({ logicalBeat, ...body })))
      const idempotencyKey = `node-heartbeat:${digest.slice(2)}`
      const correlationId = idempotencyKey
      let value: unknown
      try {
        value = await fetchJson(
          endpoint(sender.url, HEARTBEAT_OPERATION_PATH),
          {
            method: 'POST',
            headers: {
              ...headers(schemaVersion, correlationId, idempotencyKey),
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
          },
          requestTimeoutMs,
          `durable heartbeat submit [${correlationId}]`,
        )
      } catch (error) {
        throw new Error(
          `[${correlationId}] ${error instanceof Error ? error.message : 'heartbeat submit failed'}`,
        )
      }
      const operation = parseDurableOperation(value, {
        chainId: sender.chainId,
        from: options.livenessAccount,
        to: options.poolAddress,
        idempotencyKey,
        correlationId,
      })
      return { reference: operation.operationId, idempotencyKey, correlationId }
    },
    waitForOutcome: async (publication, confirmations, timeoutMs) => {
      const { schemaVersion } = await negotiate()
      const deadline = Date.now() + timeoutMs
      while (Date.now() < deadline) {
        const value = await fetchJson(
          endpoint(
            sender.url,
            `${L1_OPERATION_PATH}/${encodeURIComponent(publication.reference)}`,
          ),
          {
            method: 'GET',
            headers: headers(schemaVersion, publication.correlationId),
          },
          Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
          `durable heartbeat status [${publication.correlationId}]`,
        )
        const operation = parseDurableOperation(value, {
          chainId: sender.chainId,
          from: options.livenessAccount,
          to: options.poolAddress,
          idempotencyKey: publication.idempotencyKey,
          correlationId: publication.correlationId,
        })
        if (operation.operationId !== publication.reference) {
          throw new Error(`[${publication.correlationId}] durable heartbeat operationId mismatch`)
        }
        const outcome = canonicalOutcome(operation, confirmations)
        if (outcome) return outcome
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, Math.min(pollIntervalMs, deadline - Date.now()))
          timer.unref?.()
        })
      }
      throw new Error(
        `[${publication.correlationId}] durable heartbeat receipt timed out after ${timeoutMs}ms`,
      )
    },
  }
}

function directDevelopmentClients(
  options: OnChainHeartbeatOptions,
  sender: Extract<HeartbeatSender, { kind: 'dev-private-key' }>,
): OnChainHeartbeatClients {
  if (!isLoopbackUrl(sender.rpcUrl)) {
    throw new Error('direct heartbeat publication is restricted to a loopback development RPC')
  }
  const account = privateKeyToAccount(sender.privateKey)
  if (account.address.toLowerCase() !== options.livenessAccount.toLowerCase()) {
    throw new Error('direct development heartbeat account does not match livenessAccount')
  }
  const publicClient = createPublicClient({ transport: http(sender.rpcUrl) })
  const wallet = createWalletClient({ account, transport: http(sender.rpcUrl) })
  return {
    publishHeartbeat: async ({ logicalBeat }) => {
      const digest = keccak256(
        toBytes(
          JSON.stringify({
            logicalBeat,
            poolAddress: options.poolAddress,
            nodeId: options.nodeId,
            profileHash: options.profileHash,
          }),
        ),
      )
      const correlationId = `dev-node-heartbeat:${digest.slice(2)}`
      const hash = await wallet.writeContract({
        address: options.poolAddress,
        abi: REPORT_NODE_HEARTBEAT_ABI,
        functionName: 'reportNodeHeartbeat',
        args: [options.nodeId, options.profileHash],
        chain: null,
      })
      return { reference: hash, idempotencyKey: correlationId, correlationId }
    },
    waitForOutcome: async (publication, confirmations, timeoutMs) => {
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: publication.reference as Hex,
        confirmations,
        timeout: timeoutMs,
      })
      return { status: receipt.status }
    },
  }
}

function heartbeatClients(options: OnChainHeartbeatOptions): OnChainHeartbeatClients {
  if (options.clients) return options.clients
  return options.sender.kind === 'durable-coordinator'
    ? durableCoordinatorClients(options, options.sender)
    : directDevelopmentClients(options, options.sender)
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, operation: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)), timeoutMs)
        timer.unref?.()
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export function startOnChainHeartbeat(options: OnChainHeartbeatOptions): { stop: () => void } {
  const clients = heartbeatClients(options)
  const log = options.log ?? ((line) => process.stderr.write(`${line}\n`))
  let stopped = false
  let running = false
  const intervalMs = options.intervalMs ?? DEFAULT_ONCHAIN_INTERVAL_MS
  const confirmations = options.confirmations ?? DEFAULT_HEARTBEAT_CONFIRMATIONS
  const receiptTimeoutMs = options.receiptTimeoutMs ?? DEFAULT_RECEIPT_TIMEOUT_MS
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS
  const requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  const now = options.now ?? Date.now
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new Error('heartbeat intervalMs must be positive')
  }
  if (!Number.isInteger(confirmations) || confirmations < 1) {
    throw new Error('heartbeat confirmations must be a positive integer')
  }
  if (!Number.isFinite(receiptTimeoutMs) || receiptTimeoutMs <= 0) {
    throw new Error('heartbeat receiptTimeoutMs must be positive')
  }
  if (!Number.isFinite(retryDelayMs) || retryDelayMs < 0) {
    throw new Error('heartbeat retryDelayMs must be non-negative')
  }
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
    throw new Error('heartbeat requestTimeoutMs must be positive')
  }

  const delay = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const timer = setTimeout(resolve, ms)
      timer.unref?.()
    })

  const beat = async (): Promise<void> => {
    // Serialize logical beats. Durable production nonces are coordinator-owned;
    // direct loopback development sends remain serialized as well.
    if (stopped || running) return
    running = true
    try {
      if (!(await options.healthy())) return
      const logicalBeat = Math.floor(now() / intervalMs)
      // A transport retry reuses the same body, idempotency key and correlation
      // id. The coordinator resumes the one durable operation instead of
      // allocating a second nonce.
      for (let attempt = 0; attempt < 2 && !stopped; attempt++) {
        try {
          const publication = await withTimeout(
            clients.publishHeartbeat({ logicalBeat, confirmations }),
            requestTimeoutMs,
            'heartbeat publication request',
          )
          const outcome = await clients.waitForOutcome(
            publication,
            confirmations,
            receiptTimeoutMs,
          )
          if (outcome.status === 'success') return
          if (outcome.status === 'reverted') {
            log(
              `Progress: the on-chain heartbeat reverted [${publication.correlationId}]; re-sending while the prover is healthy.`,
            )
          } else {
            log(
              `Progress: the on-chain heartbeat failed [${publication.correlationId}]: ${outcome.reason ?? 'durable operation failed'}`,
            )
          }
        } catch (error) {
          log(
            `Progress: the on-chain heartbeat failed: ${
              error instanceof Error ? error.message : 'unknown reason'
            }`,
          )
        }
        if (attempt === 0 && !stopped && (await options.healthy())) await delay(retryDelayMs)
      }
    } finally {
      running = false
    }
  }
  const timer = setInterval(() => void beat(), intervalMs)
  timer.unref?.()
  void beat()
  return {
    stop: () => {
      stopped = true
      clearInterval(timer)
    },
  }
}

export const heartbeatContractMetadata = Object.freeze({
  signature: 'reportNodeHeartbeat(bytes32,bytes32)',
  selector: REPORT_NODE_HEARTBEAT_SELECTOR,
  productionEndpoint: HEARTBEAT_OPERATION_PATH,
  statusEndpoint: `${L1_OPERATION_PATH}/{operationId}`,
})
