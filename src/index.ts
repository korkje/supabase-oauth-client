/**
 * supabase-oauth-client
 *
 * Client side of Supabase Auth's OAuth 2.1 server (authorization code + PKCE),
 * built for the case where the authorization code reaches the client out of
 * band (websocket, QR relay) instead of via a browser redirect on the same
 * device. Also handles the ordinary same-device redirect via `completeFromUrl`.
 */

import { createCodeChallenge, createCodeVerifier, createState } from './pkce.js'
import { decodeJwtPayload, type JwtClaims } from './jwt.js'
import { OAuthError, tokenRequest, type ClientAuth, type TokenEndpointAuthMethod, type TokenResponse } from './token.js'
import { memoryStorage, type TokenStorage } from './storage.js'
import { RefreshScheduler } from './scheduler.js'

export { OAuthError, isOAuthError, INVALID_GRANT_CODES } from './token.js'
export type { TokenEndpointAuthMethod, TokenResponse, LocalOAuthErrorCode, OAuthErrorOptions } from './token.js'
export { memoryStorage, browserStorage } from './storage.js'
export type { TokenStorage } from './storage.js'
export { decodeJwtPayload } from './jwt.js'
export type { JwtClaims } from './jwt.js'
export { createCodeVerifier, createCodeChallenge, createState, base64UrlEncode, base64UrlDecode } from './pkce.js'

export interface OAuthClientOptions {
  /** Project URL, e.g. `https://abcdefgh.supabase.co`. */
  supabaseUrl: string
  /** OAuth client id registered in Supabase (Authentication → OAuth Apps). */
  clientId: string
  /** Must exactly match one of the redirect URIs registered for the client. */
  redirectUri: string
  /** Space-separated scopes. Default `email`. Do not add `openid` unless the project uses asymmetric JWT keys. */
  scope?: string | undefined
  /** Enables confidential-client mode. Server-side only; never ship a secret to a browser or device. */
  clientSecret?: string | undefined
  /** Default: `none` without a secret, `client_secret_basic` with one. */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod | undefined
  /** Where session and pending authorization are kept. Default: in-memory. Pass `localStorage` or `browserStorage()` to survive reloads. */
  storage?: TokenStorage | undefined
  /** Key prefix in `storage`. Default `sb-oauth-<clientId>`. */
  storageKey?: string | undefined
  /** Injectable `fetch` for tests and non-standard runtimes. Default: `globalThis.fetch`. */
  fetch?: typeof fetch | undefined
  /** Refresh this many seconds before the access token expires. Default 60. */
  refreshLeewaySeconds?: number | undefined
  /** Run a background refresh timer. Default true. Set false to refresh lazily via `getAccessToken()` only. */
  autoRefresh?: boolean | undefined
  /** Clock (epoch ms), injectable for tests. Default `Date.now`. */
  now?: (() => number) | undefined
}

export interface OAuthSession {
  accessToken: string
  /** Null if the server did not issue one. */
  refreshToken: string | null
  /** Epoch seconds. Taken from the JWT `exp` claim, falling back to `expires_in`. */
  expiresAt: number
  tokenType: string
  scope: string | null
  /** Only with the `openid` scope. */
  idToken: string | null
  /** Decoded (not verified) access token payload. */
  claims: JwtClaims
}

export interface BeginOptions {
  /** Override the client-level scope for this authorization. */
  scope?: string | undefined
  /** OIDC nonce; only meaningful with the `openid` scope. */
  nonce?: string | undefined
  /** Extra query parameters appended to the authorize URL. */
  extraParams?: Record<string, string> | undefined
}

export interface BeginResult {
  /** Put this in the QR / open it in the browser. */
  authorizeUrl: string
  /** The `state` bound to this authorization. `exchange()` requires it. */
  state: string
  codeChallenge: string
}

export interface ExchangeParams {
  code: string
  state: string
}

export type SignedOutReason = 'sign_out' | 'invalid_grant' | 'expired'

export type OAuthEvent =
  | { type: 'authorized'; session: OAuthSession }
  | { type: 'refreshed'; session: OAuthSession }
  | { type: 'signed_out'; reason: SignedOutReason; error?: OAuthError }
  /** A background refresh attempt failed and will be retried. Foreground calls reject instead of emitting this. */
  | { type: 'error'; error: unknown }

export type OAuthEventListener = (event: OAuthEvent) => void

export interface OAuthClient {
  /** Start a new authorization: fresh verifier + state every call. Replaces any pending one. */
  begin(options?: BeginOptions): Promise<BeginResult>
  /** Finish an authorization whose code arrived out of band. Verifies `state`, exchanges, stores, schedules refresh. */
  exchange(params: ExchangeParams): Promise<OAuthSession>
  /**
   * Same-device redirect variant. Reads `code`/`state` (or `error`) from `url`
   * (default `location.href`) and calls `exchange()`. Resolves `null` when the
   * URL carries neither `code` nor `error`, so it is safe to call on every load.
   */
  completeFromUrl(url?: string | URL): Promise<OAuthSession | null>
  /** Valid access token, refreshing first if needed. `null` when signed out. Safe to call concurrently. */
  getAccessToken(): Promise<string | null>
  /** Current session from memory. With an async storage adapter, await `initialize()` first. */
  getSession(): OAuthSession | null
  /** Wait for storage to be read. Idempotent. Only needed with async storage adapters. */
  initialize(): Promise<OAuthSession | null>
  /** Force a refresh now. Coalesces with any refresh already in flight. */
  refresh(): Promise<OAuthSession>
  /** Drop local tokens and stop the timer. Emits `signed_out`. Revoke server-side with `supabase.auth.oauth.revokeGrant()` on the user's device. */
  signOut(): Promise<void>
  /** Drop the pending verifier/state without touching the session. */
  cancel(): Promise<void>
  /** `state` of the pending authorization, or `null`. */
  getPendingState(): string | null
  /** Subscribe to events. Returns an unsubscribe function. */
  onChange(listener: OAuthEventListener): () => void
  /** The token endpoint this client posts to. */
  readonly tokenUrl: string
  /** The authorize endpoint (without query). */
  readonly authorizeEndpoint: string
}

interface PendingAuthorization {
  state: string
  codeVerifier: string
  createdAt: number
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '')
}

function isPromiseLike<T>(value: unknown): value is PromiseLike<T> {
  return typeof value === 'object' && value !== null && typeof (value as PromiseLike<T>).then === 'function'
}

function parseSession(raw: string | null | undefined): OAuthSession | null {
  if (!raw) return null
  try {
    const value = JSON.parse(raw) as Partial<OAuthSession>
    if (typeof value.accessToken !== 'string' || typeof value.expiresAt !== 'number') return null
    return {
      accessToken: value.accessToken,
      refreshToken: typeof value.refreshToken === 'string' ? value.refreshToken : null,
      expiresAt: value.expiresAt,
      tokenType: typeof value.tokenType === 'string' ? value.tokenType : 'bearer',
      scope: typeof value.scope === 'string' ? value.scope : null,
      idToken: typeof value.idToken === 'string' ? value.idToken : null,
      claims: value.claims && typeof value.claims === 'object' ? value.claims : safeDecode(value.accessToken),
    }
  } catch {
    return null
  }
}

function parsePending(raw: string | null | undefined): PendingAuthorization | null {
  if (!raw) return null
  try {
    const value = JSON.parse(raw) as Partial<PendingAuthorization>
    if (typeof value.state !== 'string' || typeof value.codeVerifier !== 'string') return null
    return { state: value.state, codeVerifier: value.codeVerifier, createdAt: typeof value.createdAt === 'number' ? value.createdAt : 0 }
  } catch {
    return null
  }
}

function safeDecode(token: string): JwtClaims {
  try {
    return decodeJwtPayload(token)
  } catch {
    return {}
  }
}

export class SupabaseOAuthClient implements OAuthClient {
  readonly tokenUrl: string
  readonly authorizeEndpoint: string

  private readonly clientId: string
  private readonly redirectUri: string
  private readonly scope: string
  private readonly auth: ClientAuth
  private readonly storage: TokenStorage
  private readonly sessionKey: string
  private readonly pendingKey: string
  private readonly fetchImpl: typeof fetch
  private readonly leewayMs: number
  private readonly autoRefresh: boolean
  private readonly now: () => number
  private readonly scheduler: RefreshScheduler
  private readonly listeners = new Set<OAuthEventListener>()

  private session: OAuthSession | null = null
  private pending: PendingAuthorization | null = null
  private loaded: Promise<void>
  private refreshInFlight: Promise<OAuthSession> | null = null

  constructor(options: OAuthClientOptions) {
    if (!options.supabaseUrl) throw new OAuthError('configuration_error', 'supabaseUrl is required')
    if (!options.clientId) throw new OAuthError('configuration_error', 'clientId is required')
    if (!options.redirectUri) throw new OAuthError('configuration_error', 'redirectUri is required')

    const base = trimTrailingSlash(options.supabaseUrl)
    this.tokenUrl = `${base}/auth/v1/oauth/token`
    this.authorizeEndpoint = `${base}/auth/v1/oauth/authorize`
    this.clientId = options.clientId
    this.redirectUri = options.redirectUri
    this.scope = options.scope ?? 'email'
    this.auth = {
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      method: options.tokenEndpointAuthMethod ?? (options.clientSecret ? 'client_secret_basic' : 'none'),
    }
    if (this.auth.method !== 'none' && !this.auth.clientSecret) {
      throw new OAuthError('configuration_error', `${this.auth.method} requires clientSecret`)
    }
    this.storage = options.storage ?? memoryStorage()
    const key = options.storageKey ?? `sb-oauth-${options.clientId}`
    this.sessionKey = `${key}.session`
    this.pendingKey = `${key}.pending`
    const f = options.fetch ?? (globalThis as { fetch?: typeof fetch }).fetch
    if (typeof f !== 'function') throw new OAuthError('configuration_error', 'fetch is not available; pass options.fetch')
    this.fetchImpl = f
    this.leewayMs = Math.max(0, options.refreshLeewaySeconds ?? 60) * 1000
    this.autoRefresh = options.autoRefresh ?? true
    this.now = options.now ?? Date.now
    this.scheduler = new RefreshScheduler({
      task: async () => {
        await this.refresh()
      },
      onError: (error) => {
        // invalid_grant already cleared the session inside refresh(); nothing left to retry.
        if (!this.session) return 'stop'
        this.emit({ type: 'error', error })
        return 'retry'
      },
      now: this.now,
    })
    this.loaded = this.load()
  }

  // ---------------------------------------------------------------- loading

  private load(): Promise<void> {
    const rawSession = this.storage.getItem(this.sessionKey)
    const rawPending = this.storage.getItem(this.pendingKey)
    const apply = (s: string | null | undefined, p: string | null | undefined): void => {
      this.session = parseSession(s)
      this.pending = parsePending(p)
      if (this.session) this.scheduleRefresh(this.session)
    }
    if (isPromiseLike<string | null | undefined>(rawSession) || isPromiseLike<string | null | undefined>(rawPending)) {
      return Promise.all([rawSession, rawPending]).then(([s, p]) => apply(s, p))
    }
    // Synchronous storage (memory, localStorage): state is available immediately.
    apply(rawSession, rawPending)
    return Promise.resolve()
  }

  async initialize(): Promise<OAuthSession | null> {
    await this.loaded
    return this.session
  }

  // ------------------------------------------------------------------ events

  onChange(listener: OAuthEventListener): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  private emit(event: OAuthEvent): void {
    for (const listener of Array.from(this.listeners)) {
      try {
        listener(event)
      } catch (error) {
        // Surface listener bugs without breaking the client's own state machine.
        queueMicrotask(() => {
          throw error
        })
      }
    }
  }

  // ----------------------------------------------------------------- pending

  getPendingState(): string | null {
    return this.pending?.state ?? null
  }

  async begin(options: BeginOptions = {}): Promise<BeginResult> {
    await this.loaded
    const codeVerifier = createCodeVerifier()
    const codeChallenge = await createCodeChallenge(codeVerifier)
    const state = createState()
    const pending: PendingAuthorization = { state, codeVerifier, createdAt: this.now() }
    this.pending = pending
    await this.storage.setItem(this.pendingKey, JSON.stringify(pending))

    const url = new URL(this.authorizeEndpoint)
    const q = url.searchParams
    q.set('response_type', 'code')
    q.set('client_id', this.clientId)
    q.set('redirect_uri', this.redirectUri)
    q.set('code_challenge', codeChallenge)
    q.set('code_challenge_method', 'S256')
    q.set('state', state)
    const scope = options.scope ?? this.scope
    if (scope) q.set('scope', scope)
    if (options.nonce) q.set('nonce', options.nonce)
    if (options.extraParams) {
      for (const [k, v] of Object.entries(options.extraParams)) q.set(k, v)
    }
    return { authorizeUrl: url.toString(), state, codeChallenge }
  }

  async cancel(): Promise<void> {
    await this.loaded
    await this.clearPending()
  }

  private async clearPending(): Promise<void> {
    this.pending = null
    await this.storage.removeItem(this.pendingKey)
  }

  // ---------------------------------------------------------------- exchange

  async exchange(params: ExchangeParams): Promise<OAuthSession> {
    await this.loaded
    const pending = this.pending
    if (!pending) {
      throw new OAuthError(
        'no_pending_authorization',
        'exchange() called without a pending authorization. Call begin() first; with the in-memory storage a page reload also drops it.',
      )
    }
    if (typeof params.code !== 'string' || params.code.length === 0) {
      throw new OAuthError('invalid_request', 'exchange() requires a code')
    }
    if (params.state !== pending.state) {
      // Leave the pending authorization intact: a stale code from an earlier scan must not cancel a newer one.
      throw new OAuthError('state_mismatch', 'state does not match the pending authorization')
    }

    const body = new URLSearchParams()
    body.set('grant_type', 'authorization_code')
    body.set('code', params.code)
    body.set('redirect_uri', this.redirectUri)
    body.set('code_verifier', pending.codeVerifier)

    let response: TokenResponse
    try {
      response = await tokenRequest(this.fetchImpl, this.tokenUrl, body, this.auth)
    } catch (error) {
      // The code is single-use, so anything the server answered burns it. A network failure
      // may not have reached the server; keep the verifier so the app can retry.
      if (!(error instanceof OAuthError && error.isNetworkError) && this.pending === pending) {
        await this.clearPending()
      }
      throw error
    }
    if (this.pending === pending) await this.clearPending()

    const session = this.buildSession(response, null)
    await this.setSession(session)
    this.scheduleRefresh(session)
    this.emit({ type: 'authorized', session })
    return session
  }

  async completeFromUrl(url?: string | URL): Promise<OAuthSession | null> {
    let parsed: URL
    if (url !== undefined) {
      parsed = url instanceof URL ? url : new URL(url)
    } else {
      const loc = (globalThis as { location?: { href?: string } }).location
      if (!loc?.href) {
        throw new OAuthError('invalid_request', 'completeFromUrl() needs a url argument outside the browser')
      }
      parsed = new URL(loc.href)
    }
    const q = parsed.searchParams
    const error = q.get('error')
    const code = q.get('code')
    if (error) {
      await this.loaded
      const state = q.get('state')
      if (!this.pending || state === null || state === this.pending.state) {
        await this.clearPending()
      }
      throw new OAuthError(error, q.get('error_description') ?? undefined)
    }
    if (code === null) return null
    const state = q.get('state')
    if (state === null) {
      throw new OAuthError('invalid_request', 'redirect is missing the state parameter')
    }
    return this.exchange({ code, state })
  }

  // ----------------------------------------------------------------- session

  getSession(): OAuthSession | null {
    return this.session
  }

  private buildSession(response: TokenResponse, previousRefreshToken: string | null): OAuthSession {
    const claims = safeDecode(response.access_token)
    const nowSec = Math.floor(this.now() / 1000)
    const expiresAt =
      typeof claims.exp === 'number'
        ? claims.exp
        : nowSec + (typeof response.expires_in === 'number' && response.expires_in > 0 ? response.expires_in : 3600)
    return {
      accessToken: response.access_token,
      refreshToken: typeof response.refresh_token === 'string' ? response.refresh_token : previousRefreshToken,
      expiresAt,
      tokenType: typeof response.token_type === 'string' ? response.token_type : 'bearer',
      scope: typeof response.scope === 'string' ? response.scope : null,
      idToken: typeof response.id_token === 'string' ? response.id_token : null,
      claims,
    }
  }

  private async setSession(session: OAuthSession): Promise<void> {
    this.session = session
    await this.storage.setItem(this.sessionKey, JSON.stringify(session))
  }

  private async clearSession(): Promise<void> {
    this.scheduler.cancel()
    this.session = null
    await this.storage.removeItem(this.sessionKey)
  }

  private scheduleRefresh(session: OAuthSession): void {
    if (!this.autoRefresh || !session.refreshToken) return
    this.scheduler.scheduleAt(session.expiresAt * 1000 - this.leewayMs)
  }

  private isFresh(session: OAuthSession): boolean {
    return session.expiresAt * 1000 - this.leewayMs > this.now()
  }

  private isExpired(session: OAuthSession): boolean {
    return session.expiresAt * 1000 <= this.now()
  }

  async getAccessToken(): Promise<string | null> {
    await this.loaded
    const session = this.session
    if (!session) return null
    if (this.isFresh(session)) return session.accessToken
    if (!session.refreshToken) {
      if (!this.isExpired(session)) return session.accessToken
      await this.clearSession()
      this.emit({ type: 'signed_out', reason: 'expired' })
      return null
    }
    try {
      const refreshed = await this.refresh()
      return refreshed.accessToken
    } catch (error) {
      // Still inside the leeway window: hand out the current token rather than failing the request.
      if (this.session === session && !this.isExpired(session)) return session.accessToken
      throw error
    }
  }

  refresh(): Promise<OAuthSession> {
    if (this.refreshInFlight) return this.refreshInFlight
    const run = this.doRefresh().finally(() => {
      this.refreshInFlight = null
    })
    this.refreshInFlight = run
    return run
  }

  private async doRefresh(): Promise<OAuthSession> {
    await this.loaded
    const session = this.session
    if (!session) throw new OAuthError('no_session', 'refresh() called while signed out')
    if (!session.refreshToken) throw new OAuthError('no_session', 'session has no refresh token')

    const body = new URLSearchParams()
    body.set('grant_type', 'refresh_token')
    body.set('refresh_token', session.refreshToken)

    let response: TokenResponse
    try {
      response = await tokenRequest(this.fetchImpl, this.tokenUrl, body, this.auth)
    } catch (error) {
      if (error instanceof OAuthError && error.isInvalidGrant && this.session === session) {
        await this.clearSession()
        this.emit({ type: 'signed_out', reason: 'invalid_grant', error })
      }
      throw error
    }

    if (this.session === null) {
      throw new OAuthError('signed_out', 'signed out while the refresh was in flight')
    }
    if (this.session !== session) {
      // A new authorization completed meanwhile; it wins.
      return this.session
    }
    const next = this.buildSession(response, session.refreshToken)
    await this.setSession(next)
    this.scheduleRefresh(next)
    this.emit({ type: 'refreshed', session: next })
    return next
  }

  async signOut(): Promise<void> {
    await this.loaded
    const hadSession = this.session !== null
    await this.clearSession()
    if (hadSession) this.emit({ type: 'signed_out', reason: 'sign_out' })
  }
}

/** Create an OAuth client for Supabase Auth's OAuth 2.1 server. */
export function createOAuthClient(options: OAuthClientOptions): OAuthClient {
  return new SupabaseOAuthClient(options)
}
