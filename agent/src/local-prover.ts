/**
 * The agent's only view of the prover it fronts: a health probe and a
 * forward. The prover is `zkdeal-r0 serve` on this host (`/healthz` open,
 * every `/v5/*` route behind ZKDEAL_PROVER_TOKEN) - the agent adds nothing
 * to that surface and never interprets a proof, it only carries bytes.
 *
 * ZKDEAL_AGENT_STUB swaps the whole thing for a deterministic fake so the
 * queue's multi-agent story is testable on a machine with no GPU at all:
 *   ok:<ms>      pretend to prove for <ms>, then answer a recognisable JSON
 *   reject       answer the way the prover answers a bad witness (HTTP 400)
 *   take-and-die die INSIDE the forward - a lease taken and never spoken for
 */

/** How a forwarded job ended, mapped to the queue's retry vocabulary. */
export type ForwardOutcome =
  | { kind: 'ok'; result: unknown }
  /** The prover refused the request itself: retrying elsewhere cannot help. */
  | { kind: 'rejected'; reason: string }
  /** This prover is broken or unreachable: another node may still succeed. */
  | { kind: 'unavailable'; reason: string }

export interface LocalProver {
  healthy(): Promise<boolean>
  forward(endpoint: string, request: unknown): Promise<ForwardOutcome>
}

export interface HttpLocalProverOptions {
  proverUrl: string
  /** Forwarded as the bearer the prover's `authorized_v5` expects. */
  proverToken?: string | null
  /** Below the queue's 25-minute lease so a timeout reports before expiry. */
  requestTimeoutMs?: number
}

const DEFAULT_FORWARD_TIMEOUT_MS = 22 * 60_000

export function createHttpLocalProver(options: HttpLocalProverOptions): LocalProver {
  const base = options.proverUrl.replace(/\/+$/, '')
  const timeoutMs = options.requestTimeoutMs ?? DEFAULT_FORWARD_TIMEOUT_MS
  return {
    async healthy(): Promise<boolean> {
      try {
        const response = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(5_000) })
        return response.ok
      } catch {
        return false
      }
    },
    async forward(endpoint: string, request: unknown): Promise<ForwardOutcome> {
      let response: Response
      try {
        response = await fetch(`${base}${endpoint}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(options.proverToken
              ? { authorization: `Bearer ${options.proverToken}` }
              : {}),
          },
          body: JSON.stringify(request),
          signal: AbortSignal.timeout(timeoutMs),
        })
      } catch (error) {
        return {
          kind: 'unavailable',
          reason: `the local prover was unreachable: ${
            error instanceof Error ? error.message : 'network failure'
          }`,
        }
      }
      const text = await response.text().catch(() => '')
      let body: unknown = null
      try {
        body = JSON.parse(text)
      } catch {
        /* an unreadable body is judged by the status code alone */
      }
      if (response.ok && body !== null) return { kind: 'ok', result: body }
      const reason =
        (body as { reason?: string } | null)?.reason ??
        `the local prover answered HTTP ${response.status}`
      // 4xx is the prover judging the REQUEST (http.rs answers rejections
      // with 400): no other node can fix a bad witness, so the job is
      // condemned rather than bounced between provers. Everything else -
      // 5xx, an unreadable success body - indicts this prover only.
      if (response.status >= 400 && response.status < 500) {
        return { kind: 'rejected', reason }
      }
      return { kind: 'unavailable', reason }
    },
  }
}

export interface StubProverOptions {
  /** Injectable death, so a unit test can observe it instead of dying. */
  die?: () => never
}

/** Parse ZKDEAL_AGENT_STUB; null when unset (use the real prover). */
export function createStubProver(
  mode: string | undefined,
  options: StubProverOptions = {},
): LocalProver | null {
  if (!mode) return null
  const die =
    options.die ??
    ((): never => {
      // The whole point of this stub: a worker that takes a lease and is
      // never heard from again, so the queue's expiry path gets exercised.
      process.exit(1)
    })
  const okMatch = /^ok:(\d+)$/.exec(mode)
  if (okMatch) {
    const delayMs = Number(okMatch[1])
    return {
      healthy: async () => true,
      async forward(endpoint: string): Promise<ForwardOutcome> {
        await new Promise((resolve) => setTimeout(resolve, delayMs))
        return {
          kind: 'ok',
          result: { decision: 'stub-proof', endpoint, provedInMs: delayMs },
        }
      },
    }
  }
  if (mode === 'reject') {
    return {
      healthy: async () => true,
      forward: async () => ({
        kind: 'rejected',
        reason: 'the stub prover rejects every request',
      }),
    }
  }
  if (mode === 'take-and-die') {
    return {
      healthy: async () => true,
      forward: async () => die(),
    }
  }
  throw new Error(`ZKDEAL_AGENT_STUB must be ok:<ms>, reject or take-and-die, got ${mode}`)
}
