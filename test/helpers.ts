import { vi } from 'vitest'

export function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url')
}

/** Unsigned JWT with the given payload. Good enough for a decode-only client. */
export function fakeJwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`
}

export interface RecordedRequest {
  url: string
  method: string
  headers: Record<string, string>
  body: URLSearchParams
}

export type Reply =
  /** `json` may be a thunk so the body (e.g. a JWT `exp`) is computed when served, not when queued. */
  | { status?: number; json: unknown | (() => unknown) }
  | { status: number; text: string }
  | { networkError: string }
  | ((req: RecordedRequest) => Response | Promise<Response>)

/** A fetch mock that replays queued replies and records every request. */
export function mockFetch(...replies: Reply[]) {
  const queue = [...replies]
  const requests: RecordedRequest[] = []
  const fn = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((v, k) => {
      headers[k.toLowerCase()] = v
    })
    const req: RecordedRequest = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      body: new URLSearchParams(typeof init?.body === 'string' ? init.body : ''),
    }
    requests.push(req)
    const reply = queue.shift()
    if (!reply) throw new Error(`mockFetch: unexpected request #${requests.length} to ${req.url}`)
    if (typeof reply === 'function') return reply(req)
    if ('networkError' in reply) throw new TypeError(reply.networkError)
    if ('text' in reply) return new Response(reply.text, { status: reply.status })
    const json = typeof reply.json === 'function' ? (reply.json as () => unknown)() : reply.json
    return new Response(JSON.stringify(json), {
      status: reply.status ?? 200,
      headers: { 'Content-Type': 'application/json' },
    })
  })
  return Object.assign(fn, {
    requests,
    push: (...more: Reply[]) => {
      queue.push(...more)
    },
  })
}

export function tokenJson(overrides: Record<string, unknown> = {}, claims: Record<string, unknown> = {}) {
  const nowSec = Math.floor(Date.now() / 1000)
  const exp = typeof claims.exp === 'number' ? claims.exp : nowSec + 3600
  return {
    access_token: fakeJwt({ sub: 'user-1', aud: 'authenticated', role: 'authenticated', client_id: 'client-1', exp, ...claims }),
    token_type: 'bearer',
    expires_in: exp - nowSec,
    refresh_token: 'rt-1',
    scope: 'email',
    ...overrides,
  }
}
