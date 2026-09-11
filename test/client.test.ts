import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { OAuthError, createOAuthClient, memoryStorage, type OAuthEvent, type TokenStorage } from '../src/index.js'
import { mockFetch, tokenJson } from './helpers.js'

const SUPABASE_URL = 'https://abc.supabase.co'
const CLIENT_ID = 'client-1'
const REDIRECT_URI = 'https://rc.example.com/oauth/callback'
const TOKEN_URL = `${SUPABASE_URL}/auth/v1/oauth/token`

function make(fetch: ReturnType<typeof mockFetch>, extra: Partial<Parameters<typeof createOAuthClient>[0]> = {}) {
  const events: OAuthEvent[] = []
  const oauth = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, ...extra })
  oauth.onChange((e) => events.push(e))
  return { oauth, events }
}

/** Runs begin() + exchange() against one queued token reply. */
async function authorize(oauth: ReturnType<typeof createOAuthClient>) {
  const { state } = await oauth.begin()
  return oauth.exchange({ code: 'code-1', state })
}

describe('createOAuthClient', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-11T12:00:00Z'))
  })
  afterEach(() => vi.useRealTimers())

  describe('configuration', () => {
    it('validates required options', () => {
      const fetch = mockFetch()
      expect(() => createOAuthClient({ supabaseUrl: '', clientId: 'c', redirectUri: 'r', fetch })).toThrow(OAuthError)
      expect(() => createOAuthClient({ supabaseUrl: 'u', clientId: '', redirectUri: 'r', fetch })).toThrow(/clientId/)
      expect(() => createOAuthClient({ supabaseUrl: 'u', clientId: 'c', redirectUri: '', fetch })).toThrow(/redirectUri/)
      expect(() => createOAuthClient({ supabaseUrl: 'u', clientId: 'c', redirectUri: 'r', fetch, tokenEndpointAuthMethod: 'client_secret_post' })).toThrow(
        /clientSecret/,
      )
    })

    it('derives endpoints and tolerates a trailing slash', () => {
      const { oauth } = make(mockFetch(), { supabaseUrl: `${SUPABASE_URL}/` })
      expect(oauth.tokenUrl).toBe(TOKEN_URL)
      expect(oauth.authorizeEndpoint).toBe(`${SUPABASE_URL}/auth/v1/oauth/authorize`)
    })
  })

  describe('begin()', () => {
    it('builds a PKCE authorize URL and rotates verifier + state every call', async () => {
      const { oauth } = make(mockFetch())
      const a = await oauth.begin()
      const b = await oauth.begin({ scope: 'email profile', nonce: 'n1', extraParams: { prompt: 'login' } })

      const ua = new URL(a.authorizeUrl)
      expect(`${ua.origin}${ua.pathname}`).toBe(`${SUPABASE_URL}/auth/v1/oauth/authorize`)
      expect(Object.fromEntries(ua.searchParams)).toEqual({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_challenge: a.codeChallenge,
        code_challenge_method: 'S256',
        state: a.state,
        scope: 'email',
      })
      expect(a.codeChallenge).toMatch(/^[A-Za-z0-9\-_]{43}$/)

      const ub = new URL(b.authorizeUrl)
      expect(ub.searchParams.get('scope')).toBe('email profile')
      expect(ub.searchParams.get('nonce')).toBe('n1')
      expect(ub.searchParams.get('prompt')).toBe('login')
      expect(b.state).not.toBe(a.state)
      expect(b.codeChallenge).not.toBe(a.codeChallenge)
      // latest wins
      expect(oauth.getPendingState()).toBe(b.state)
    })

    it('cancel() drops the pending authorization only', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      await oauth.begin()
      await oauth.cancel()
      expect(oauth.getPendingState()).toBeNull()
      expect(oauth.getSession()).not.toBeNull()
      expect(events.map((e) => e.type)).toEqual(['authorized'])
    })
  })

  describe('exchange()', () => {
    it('rejects without a pending authorization', async () => {
      const { oauth } = make(mockFetch())
      await expect(oauth.exchange({ code: 'c', state: 's' })).rejects.toMatchObject({ error: 'no_pending_authorization' })
    })

    it('rejects a state mismatch and keeps the pending authorization', async () => {
      const { oauth } = make(mockFetch())
      const { state } = await oauth.begin()
      await expect(oauth.exchange({ code: 'c', state: 'stale' })).rejects.toMatchObject({ error: 'state_mismatch' })
      expect(oauth.getPendingState()).toBe(state)
    })

    it('posts the authorization_code grant and stores the session', async () => {
      const json = tokenJson()
      const fetch = mockFetch({ json })
      const { oauth, events } = make(fetch)
      const { state, authorizeUrl } = await oauth.begin()
      const session = await oauth.exchange({ code: 'code-1', state })

      const req = fetch.requests[0]!
      expect(req.url).toBe(TOKEN_URL)
      expect(req.method).toBe('POST')
      expect(Object.fromEntries(req.body)).toEqual({
        grant_type: 'authorization_code',
        code: 'code-1',
        redirect_uri: REDIRECT_URI,
        code_verifier: expect.stringMatching(/^[A-Za-z0-9\-_]{43}$/),
        client_id: CLIENT_ID,
      })
      expect(req.headers['authorization']).toBeUndefined()
      // verifier must hash to the challenge we advertised
      const { createHash } = await import('node:crypto')
      expect(createHash('sha256').update(req.body.get('code_verifier')!).digest('base64url')).toBe(
        new URL(authorizeUrl).searchParams.get('code_challenge'),
      )

      expect(session).toMatchObject({
        accessToken: json.access_token,
        refreshToken: 'rt-1',
        tokenType: 'bearer',
        scope: 'email',
        idToken: null,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      })
      expect(session.claims).toMatchObject({ sub: 'user-1', client_id: CLIENT_ID })
      expect(oauth.getSession()).toBe(session)
      expect(oauth.getPendingState()).toBeNull()
      expect(events).toEqual([{ type: 'authorized', session }])
    })

    it('falls back to expires_in when the JWT has no exp', async () => {
      const fetch = mockFetch({ json: { access_token: 'not.a-jwt', token_type: 'bearer', expires_in: 120 } })
      const { oauth } = make(fetch)
      const session = await authorize(oauth)
      expect(session.expiresAt).toBe(Math.floor(Date.now() / 1000) + 120)
      expect(session.claims).toEqual({})
      expect(session.refreshToken).toBeNull()
    })

    it('surfaces server errors and burns the pending authorization', async () => {
      const fetch = mockFetch({ status: 400, json: { error: 'invalid_grant', error_description: 'code expired' } })
      const { oauth, events } = make(fetch)
      const { state } = await oauth.begin()
      await expect(oauth.exchange({ code: 'c', state })).rejects.toMatchObject({ error: 'invalid_grant', status: 400 })
      expect(oauth.getPendingState()).toBeNull()
      expect(oauth.getSession()).toBeNull()
      expect(events).toEqual([])
    })

    it('keeps the pending authorization after a network error so the app can retry', async () => {
      const fetch = mockFetch({ networkError: 'offline' }, { json: tokenJson() })
      const { oauth } = make(fetch)
      const { state } = await oauth.begin()
      await expect(oauth.exchange({ code: 'c', state })).rejects.toMatchObject({ error: 'network_error' })
      expect(oauth.getPendingState()).toBe(state)
      await expect(oauth.exchange({ code: 'c', state })).resolves.toBeTruthy()
    })

    it('does not clobber a newer pending authorization started during the exchange', async () => {
      let release!: () => void
      const fetch = mockFetch(
        () =>
          new Promise((resolve) => {
            release = () => resolve(new Response(JSON.stringify(tokenJson()), { status: 200 }))
          }),
      )
      const { oauth } = make(fetch)
      const first = await oauth.begin()
      const p = oauth.exchange({ code: 'c', state: first.state })
      const second = await oauth.begin()
      release()
      await p
      expect(oauth.getPendingState()).toBe(second.state)
    })

    it('replaces an existing session and re-arms the refresh timer', async () => {
      const fetch = mockFetch({ json: tokenJson({ refresh_token: 'rt-a' }) }, { json: tokenJson({ refresh_token: 'rt-b' }) })
      const { oauth } = make(fetch)
      await authorize(oauth)
      await authorize(oauth)
      expect(oauth.getSession()?.refreshToken).toBe('rt-b')
      fetch.push({ json: () => tokenJson({ refresh_token: 'rt-c' }) })
      await vi.advanceTimersByTimeAsync(3600_000)
      expect(fetch.requests).toHaveLength(3)
      expect(fetch.requests[2]!.body.get('refresh_token')).toBe('rt-b')
    })
  })

  describe('completeFromUrl()', () => {
    it('returns null when the URL has neither code nor error', async () => {
      const { oauth } = make(mockFetch())
      await oauth.begin()
      await expect(oauth.completeFromUrl('https://rc.example.com/')).resolves.toBeNull()
      await expect(oauth.completeFromUrl(new URL('https://rc.example.com/?foo=bar'))).resolves.toBeNull()
      expect(oauth.getPendingState()).not.toBeNull()
    })

    it('exchanges code + state from the query string', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth } = make(fetch)
      const { state } = await oauth.begin()
      const session = await oauth.completeFromUrl(`${REDIRECT_URI}?code=abc&state=${encodeURIComponent(state)}`)
      expect(session?.accessToken).toBeTruthy()
      expect(fetch.requests[0]!.body.get('code')).toBe('abc')
    })

    it('rejects with the redirect error and clears the pending authorization', async () => {
      const { oauth } = make(mockFetch())
      const { state } = await oauth.begin()
      const err = await oauth
        .completeFromUrl(`${REDIRECT_URI}?error=access_denied&error_description=User+denied&state=${state}`)
        .catch((e) => e)
      expect(err).toBeInstanceOf(OAuthError)
      expect(err).toMatchObject({ error: 'access_denied', errorDescription: 'User denied' })
      expect(oauth.getPendingState()).toBeNull()
    })

    it('an error for a stale state does not clear a newer pending authorization', async () => {
      const { oauth } = make(mockFetch())
      const { state } = await oauth.begin()
      await expect(oauth.completeFromUrl(`${REDIRECT_URI}?error=access_denied&state=old`)).rejects.toMatchObject({ error: 'access_denied' })
      expect(oauth.getPendingState()).toBe(state)
    })

    it('requires state alongside code', async () => {
      const { oauth } = make(mockFetch())
      await oauth.begin()
      await expect(oauth.completeFromUrl(`${REDIRECT_URI}?code=abc`)).rejects.toMatchObject({ error: 'invalid_request' })
    })

    it('needs an explicit url outside the browser', async () => {
      const { oauth } = make(mockFetch())
      await expect(oauth.completeFromUrl()).rejects.toMatchObject({ error: 'invalid_request' })
    })
  })

  describe('refresh()', () => {
    it('posts the refresh_token grant, stores the rotated token and emits refreshed', async () => {
      const fetch = mockFetch({ json: tokenJson({ refresh_token: 'rt-1' }) }, { json: tokenJson({ refresh_token: 'rt-2' }) })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      const next = await oauth.refresh()
      expect(Object.fromEntries(fetch.requests[1]!.body)).toEqual({ grant_type: 'refresh_token', refresh_token: 'rt-1', client_id: CLIENT_ID })
      expect(next.refreshToken).toBe('rt-2')
      expect(oauth.getSession()).toBe(next)
      expect(events.map((e) => e.type)).toEqual(['authorized', 'refreshed'])
    })

    it('keeps the old refresh token when the server does not rotate it', async () => {
      const fetch = mockFetch({ json: tokenJson({ refresh_token: 'rt-1' }) }, { json: tokenJson({ refresh_token: undefined }) })
      const { oauth } = make(fetch)
      await authorize(oauth)
      const next = await oauth.refresh()
      expect(next.refreshToken).toBe('rt-1')
    })

    it('invalid_grant clears the session and emits signed_out', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { status: 400, json: { error: 'invalid_grant', error_description: 'revoked' } })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      await expect(oauth.refresh()).rejects.toMatchObject({ error: 'invalid_grant' })
      expect(oauth.getSession()).toBeNull()
      expect(events[1]).toMatchObject({ type: 'signed_out', reason: 'invalid_grant', error: expect.any(OAuthError) })
      // timer is gone
      await vi.advanceTimersByTimeAsync(7200_000)
      expect(fetch.requests).toHaveLength(2)
    })

    it('GoTrue refresh_token_not_found also clears the session', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { status: 400, json: { code: 400, error_code: 'refresh_token_not_found', msg: 'Refresh Token Not Found' } })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      await expect(oauth.refresh()).rejects.toMatchObject({ error: 'refresh_token_not_found', isInvalidGrant: true })
      expect(oauth.getSession()).toBeNull()
      expect(events[1]).toMatchObject({ type: 'signed_out', reason: 'invalid_grant' })
    })

    it('rejects when signed out', async () => {
      const { oauth } = make(mockFetch())
      await expect(oauth.refresh()).rejects.toMatchObject({ error: 'no_session' })
    })

    it('coalesces concurrent refreshes into one request', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { json: tokenJson({ refresh_token: 'rt-2' }) })
      const { oauth } = make(fetch)
      await authorize(oauth)
      const [a, b, c] = await Promise.all([oauth.refresh(), oauth.refresh(), oauth.refresh()])
      expect(fetch.requests).toHaveLength(2)
      expect(a).toBe(b)
      expect(b).toBe(c)
    })

    it('a signOut during an in-flight refresh wins', async () => {
      let release!: () => void
      const fetch = mockFetch(
        { json: tokenJson() },
        () =>
          new Promise((resolve) => {
            release = () => resolve(new Response(JSON.stringify(tokenJson({ refresh_token: 'rt-2' })), { status: 200 }))
          }),
      )
      const { oauth } = make(fetch)
      await authorize(oauth)
      const p = oauth.refresh()
      await oauth.signOut()
      release()
      await expect(p).rejects.toMatchObject({ error: 'signed_out' })
      expect(oauth.getSession()).toBeNull()
    })
  })

  describe('getAccessToken()', () => {
    it('returns null when signed out', async () => {
      const { oauth } = make(mockFetch())
      await expect(oauth.getAccessToken()).resolves.toBeNull()
    })

    it('returns the current token without a request while fresh', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth } = make(fetch)
      const session = await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3600_000 - 61_000)
      await expect(oauth.getAccessToken()).resolves.toBe(session.accessToken)
      expect(fetch.requests).toHaveLength(1)
    })

    it('refreshes inside the leeway window and coalesces concurrent callers', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { json: tokenJson({ refresh_token: 'rt-2' }) })
      const { oauth } = make(fetch, { autoRefresh: false })
      await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3600_000 - 30_000)
      const tokens = await Promise.all([oauth.getAccessToken(), oauth.getAccessToken(), oauth.getAccessToken()])
      expect(fetch.requests).toHaveLength(2)
      expect(new Set(tokens).size).toBe(1)
      expect(tokens[0]).toBe(oauth.getSession()!.accessToken)
    })

    it('falls back to the still-valid token if a refresh fails inside the leeway window', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { networkError: 'offline' })
      const { oauth } = make(fetch, { autoRefresh: false })
      const session = await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3600_000 - 30_000)
      await expect(oauth.getAccessToken()).resolves.toBe(session.accessToken)
    })

    it('rejects if the token is expired and the refresh fails', async () => {
      const fetch = mockFetch({ json: tokenJson() }, { networkError: 'offline' })
      const { oauth } = make(fetch, { autoRefresh: false })
      await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3601_000)
      await expect(oauth.getAccessToken()).rejects.toMatchObject({ error: 'network_error' })
    })

    it('without a refresh token: hands out the token until expiry, then signs out', async () => {
      const fetch = mockFetch({ json: tokenJson({ refresh_token: undefined }) })
      const { oauth, events } = make(fetch)
      const session = await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3600_000 - 10_000)
      await expect(oauth.getAccessToken()).resolves.toBe(session.accessToken)
      await vi.advanceTimersByTimeAsync(10_000)
      await expect(oauth.getAccessToken()).resolves.toBeNull()
      expect(events[1]).toEqual({ type: 'signed_out', reason: 'expired' })
      expect(fetch.requests).toHaveLength(1)
    })
  })

  describe('background refresh', () => {
    it('refreshes leeway seconds before expiry, then keeps going', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch, { refreshLeewaySeconds: 120 })
      await authorize(oauth)
      fetch.push({ json: () => tokenJson({ refresh_token: 'rt-2' }) })
      await vi.advanceTimersByTimeAsync(3600_000 - 120_000 - 1)
      expect(fetch.requests).toHaveLength(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(fetch.requests).toHaveLength(2)
      expect(events.map((e) => e.type)).toEqual(['authorized', 'refreshed'])
      fetch.push({ json: () => tokenJson({ refresh_token: 'rt-3' }) })
      await vi.advanceTimersByTimeAsync(3600_000 - 120_000)
      expect(fetch.requests).toHaveLength(3)
      expect(fetch.requests[2]!.body.get('refresh_token')).toBe('rt-2')
    })

    it('emits error and retries with backoff on transient failures', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      fetch.push({ networkError: 'offline' }, { status: 503, text: 'unavailable' }, { json: () => tokenJson({ refresh_token: 'rt-2' }) })
      await vi.advanceTimersByTimeAsync(3600_000 - 60_000)
      expect(fetch.requests).toHaveLength(2)
      await vi.advanceTimersByTimeAsync(1000)
      expect(fetch.requests).toHaveLength(3)
      await vi.advanceTimersByTimeAsync(2000)
      expect(fetch.requests).toHaveLength(4)
      expect(events.map((e) => e.type)).toEqual(['authorized', 'error', 'error', 'refreshed'])
      expect((events[1] as { error: OAuthError }).error).toMatchObject({ error: 'network_error' })
      expect((events[2] as { error: OAuthError }).error).toMatchObject({ error: 'http_503', status: 503 })
      expect(oauth.getSession()?.refreshToken).toBe('rt-2')
    })

    it('stops on invalid_grant', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      fetch.push({ status: 400, json: { error: 'invalid_grant' } })
      await vi.advanceTimersByTimeAsync(3600_000 * 3)
      expect(fetch.requests).toHaveLength(2)
      expect(events.map((e) => e.type)).toEqual(['authorized', 'signed_out'])
    })

    it('does not run when autoRefresh is false', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth } = make(fetch, { autoRefresh: false })
      await authorize(oauth)
      await vi.advanceTimersByTimeAsync(3600_000 * 3)
      expect(fetch.requests).toHaveLength(1)
    })

    it('signOut cancels the timer and emits signed_out once', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch)
      await authorize(oauth)
      await oauth.signOut()
      await oauth.signOut()
      await vi.advanceTimersByTimeAsync(3600_000 * 3)
      expect(fetch.requests).toHaveLength(1)
      expect(events.map((e) => e.type)).toEqual(['authorized', 'signed_out'])
      expect(events[1]).toEqual({ type: 'signed_out', reason: 'sign_out' })
    })
  })

  describe('storage', () => {
    it('persists session and pending across client instances with sync storage', async () => {
      const storage = memoryStorage()
      const fetch = mockFetch({ json: tokenJson() })
      const a = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, storage })
      const { state } = await a.begin()

      // "page reload": new instance, same storage, pending survives -> redirect variant works
      const b = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, storage, autoRefresh: false })
      expect(b.getPendingState()).toBe(state)
      const session = await b.completeFromUrl(`${REDIRECT_URI}?code=c&state=${state}`)

      const c = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, storage })
      expect(c.getSession()).toEqual(session)
      expect(c.getPendingState()).toBeNull()
      // restored session re-arms the timer
      fetch.push({ json: () => tokenJson({ refresh_token: 'rt-2' }) })
      await vi.advanceTimersByTimeAsync(3600_000)
      expect(fetch.requests).toHaveLength(2)
      await c.signOut()
      expect(await storage.getItem(`sb-oauth-${CLIENT_ID}.session`)).toBeNull()
    })

    it('supports async storage via initialize()', async () => {
      const map = new Map<string, string>()
      const storage: TokenStorage = {
        getItem: async (k) => map.get(k) ?? null,
        setItem: async (k, v) => {
          map.set(k, v)
        },
        removeItem: async (k) => {
          map.delete(k)
        },
      }
      const fetch = mockFetch({ json: tokenJson() })
      const a = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, storage })
      const session = await authorize(a)
      const b = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, fetch, storage })
      expect(b.getSession()).toBeNull()
      expect(await b.initialize()).toEqual(session)
      expect(await b.getAccessToken()).toBe(session.accessToken)
    })

    it('ignores corrupt stored values', () => {
      const storage = memoryStorage()
      storage.setItem(`sb-oauth-${CLIENT_ID}.session`, '{not json')
      storage.setItem(`sb-oauth-${CLIENT_ID}.pending`, JSON.stringify({ state: 1 }))
      const { oauth } = make(mockFetch(), { storage })
      expect(oauth.getSession()).toBeNull()
      expect(oauth.getPendingState()).toBeNull()
    })

    it('honours storageKey', async () => {
      const storage = memoryStorage()
      const { oauth } = make(mockFetch(), { storage, storageKey: 'myapp' })
      await oauth.begin()
      expect(await storage.getItem('myapp.pending')).toBeTruthy()
    })
  })

  describe('confidential clients', () => {
    it('defaults to client_secret_basic when a secret is given', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth } = make(fetch, { clientSecret: 's3cret' })
      await authorize(oauth)
      const req = fetch.requests[0]!
      expect(req.headers['authorization']).toBe(`Basic ${Buffer.from(`${CLIENT_ID}:s3cret`).toString('base64')}`)
      expect(req.body.has('client_id')).toBe(false)
      expect(req.body.has('client_secret')).toBe(false)
    })

    it('client_secret_post puts credentials in the body', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth } = make(fetch, { clientSecret: 's3cret', tokenEndpointAuthMethod: 'client_secret_post' })
      await authorize(oauth)
      const req = fetch.requests[0]!
      expect(req.headers['authorization']).toBeUndefined()
      expect(req.body.get('client_id')).toBe(CLIENT_ID)
      expect(req.body.get('client_secret')).toBe('s3cret')
    })
  })

  describe('events', () => {
    it('unsubscribe works and a throwing listener does not break the flow', async () => {
      const fetch = mockFetch({ json: tokenJson() })
      const { oauth, events } = make(fetch)
      const off = oauth.onChange(() => {
        throw new Error('listener bug')
      })
      const rejections: unknown[] = []
      const onUnhandled = (e: unknown) => rejections.push(e)
      process.on('uncaughtException', onUnhandled)
      try {
        await authorize(oauth)
        await vi.advanceTimersByTimeAsync(0)
      } finally {
        process.off('uncaughtException', onUnhandled)
      }
      expect(events.map((e) => e.type)).toEqual(['authorized'])
      off()
      await oauth.signOut()
      expect(events.map((e) => e.type)).toEqual(['authorized', 'signed_out'])
    })
  })
})
