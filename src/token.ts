/**
 * Token endpoint client: authorization_code exchange, refresh_token grant,
 * client authentication and the typed `OAuthError`.
 */

export type TokenEndpointAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post'

/** Successful response from `/auth/v1/oauth/token`. */
export interface TokenResponse {
  access_token: string
  token_type: string
  /** Seconds until `access_token` expires. Supabase defaults to 3600. */
  expires_in?: number
  refresh_token?: string
  scope?: string
  /** Only present when the `openid` scope was granted. */
  id_token?: string
  [key: string]: unknown
}

export interface ClientAuth {
  clientId: string
  clientSecret?: string | undefined
  method: TokenEndpointAuthMethod
}

export interface OAuthErrorOptions {
  /** HTTP status of the token endpoint response, if this error came from one. */
  status?: number | undefined
  /** Parsed (or raw text) body of the failing response, for debugging. */
  response?: unknown
  cause?: unknown
}

/**
 * Error codes produced locally by this library. Anything else in
 * `OAuthError.error` came from the server (`invalid_grant`, `invalid_client`,
 * `invalid_request`, `access_denied`, `server_error`, ...).
 */
export type LocalOAuthErrorCode =
  | 'no_pending_authorization'
  | 'state_mismatch'
  | 'no_session'
  | 'network_error'
  | 'invalid_response'
  | 'signed_out'
  | 'configuration_error'

/**
 * Typed OAuth error. `error` is the OAuth 2.1 error code (RFC 6749 §5.2), or
 * one of {@link LocalOAuthErrorCode} for failures detected on the client.
 */
export class OAuthError extends Error {
  override readonly name = 'OAuthError'
  readonly error: string
  readonly errorDescription: string | undefined
  readonly status: number | undefined
  readonly response: unknown
  /** Underlying error (e.g. the `fetch` rejection) when there is one. */
  declare readonly cause?: unknown

  constructor(error: string, errorDescription?: string, options: OAuthErrorOptions = {}) {
    super(errorDescription ? `${error}: ${errorDescription}` : error)
    if (options.cause !== undefined) {
      // `cause` is ES2022; assign manually so the ES2020 lib typings stay happy.
      ;(this as { cause?: unknown }).cause = options.cause
    }
    this.error = error
    this.errorDescription = errorDescription
    this.status = options.status
    this.response = options.response
    // Preserve the prototype chain when targeting ES5-ish environments.
    Object.setPrototypeOf(this, new.target.prototype)
  }

  /** `error_description` as `error_description`, for callers used to the wire format. */
  get error_description(): string | undefined {
    return this.errorDescription
  }

  /**
   * True when the server rejected the grant itself: revoked, expired or reused code or refresh
   * token. Covers the RFC 6749 `invalid_grant` code and the GoTrue-style codes Supabase returns for
   * dead refresh tokens (observed live: `refresh_token_not_found`).
   */
  get isInvalidGrant(): boolean {
    return INVALID_GRANT_CODES.has(this.error)
  }

  /** True when the request never reached (or never got a reply from) the server. */
  get isNetworkError(): boolean {
    return this.error === 'network_error'
  }
}

/** Error codes that mean the refresh token / code is dead and the session cannot be recovered. */
export const INVALID_GRANT_CODES: ReadonlySet<string> = new Set([
  'invalid_grant',
  'refresh_token_not_found',
  'refresh_token_already_used',
  'session_not_found',
  'session_expired',
  'user_not_found',
  'user_banned',
])

export function isOAuthError(value: unknown): value is OAuthError {
  return value instanceof OAuthError || (typeof value === 'object' && value !== null && (value as { name?: unknown }).name === 'OAuthError')
}

function toBase64(text: string): string {
  // Client ids/secrets are ASCII; encode UTF-8 defensively anyway.
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number)
  return btoa(binary)
}

/** Add client credentials to a token request per `token_endpoint_auth_method`. */
export function applyClientAuth(body: URLSearchParams, headers: Record<string, string>, auth: ClientAuth): void {
  switch (auth.method) {
    case 'none':
      body.set('client_id', auth.clientId)
      return
    case 'client_secret_post':
      if (!auth.clientSecret) {
        throw new OAuthError('configuration_error', 'client_secret_post requires a clientSecret')
      }
      body.set('client_id', auth.clientId)
      body.set('client_secret', auth.clientSecret)
      return
    case 'client_secret_basic':
      if (!auth.clientSecret) {
        throw new OAuthError('configuration_error', 'client_secret_basic requires a clientSecret')
      }
      headers['Authorization'] = `Basic ${toBase64(`${encodeURIComponent(auth.clientId)}:${encodeURIComponent(auth.clientSecret)}`)}`
      return
    default: {
      const never: never = auth.method
      throw new OAuthError('configuration_error', `Unknown tokenEndpointAuthMethod: ${String(never)}`)
    }
  }
}

interface ErrorBody {
  error?: unknown
  error_description?: unknown
  error_code?: unknown
  code?: unknown
  msg?: unknown
  message?: unknown
}

/** Turn a non-2xx token endpoint response into an OAuthError. Handles both RFC 6749 and GoTrue-style bodies. */
export async function errorFromResponse(res: Response): Promise<OAuthError> {
  const text = await res.text().catch(() => '')
  let body: unknown = text
  try {
    body = text ? JSON.parse(text) : undefined
  } catch {
    // keep raw text
  }
  const b = (typeof body === 'object' && body !== null ? body : {}) as ErrorBody
  const pick = (...values: unknown[]): string | undefined => {
    for (const v of values) {
      if (typeof v === 'string' && v.length > 0) return v
      if (typeof v === 'number') return String(v)
    }
    return undefined
  }
  const error = pick(b.error, b.error_code, b.code) ?? `http_${res.status}`
  const description = pick(b.error_description, b.msg, b.message) ?? (typeof body === 'string' && body ? body : undefined)
  return new OAuthError(error, description, { status: res.status, response: body })
}

/** POST to the token endpoint and return the parsed, minimally validated token response. */
export async function tokenRequest(
  fetchImpl: typeof fetch,
  tokenUrl: string,
  body: URLSearchParams,
  auth: ClientAuth,
): Promise<TokenResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    Accept: 'application/json',
  }
  applyClientAuth(body, headers, auth)

  let res: Response
  try {
    res = await fetchImpl(tokenUrl, { method: 'POST', headers, body: body.toString() })
  } catch (cause) {
    throw new OAuthError('network_error', cause instanceof Error ? cause.message : 'Token request failed', { cause })
  }

  if (!res.ok) {
    throw await errorFromResponse(res)
  }

  let json: unknown
  try {
    json = await res.json()
  } catch (cause) {
    throw new OAuthError('invalid_response', 'Token endpoint returned a non-JSON body', { status: res.status, cause })
  }
  if (typeof json !== 'object' || json === null || typeof (json as TokenResponse).access_token !== 'string') {
    throw new OAuthError('invalid_response', 'Token endpoint response is missing access_token', { status: res.status, response: json })
  }
  return json as TokenResponse
}
