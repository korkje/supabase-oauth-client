import { base64UrlDecodeToString } from './pkce.js'

/**
 * Claims found in a Supabase access token. Everything is optional because we
 * only decode, never verify, and Supabase may add or remove claims.
 */
export interface JwtClaims {
  /** Subject: the user's id. */
  sub?: string
  /** Audience, normally `authenticated`. */
  aud?: string | string[]
  /** Expiry, seconds since epoch. */
  exp?: number
  /** Issued at, seconds since epoch. */
  iat?: number
  iss?: string
  /** Postgres role, normally `authenticated`. */
  role?: string
  email?: string
  phone?: string
  /** The OAuth client this token was issued to. Use `auth.jwt() ->> 'client_id'` in RLS. */
  client_id?: string
  session_id?: string
  is_anonymous?: boolean
  app_metadata?: Record<string, unknown>
  user_metadata?: Record<string, unknown>
  [claim: string]: unknown
}

/**
 * Decode the payload of a JWT **without verifying its signature**.
 *
 * This is only used to read `exp` and expose claims for convenience. The token
 * came straight from Supabase over TLS, so there is nothing to verify on the
 * client. Servers must verify against the project's JWKS instead.
 */
export function decodeJwtPayload(token: string): JwtClaims {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected three dot-separated segments')
  }
  let json: string
  try {
    json = base64UrlDecodeToString(parts[1] as string)
  } catch {
    throw new Error('Invalid JWT: payload is not valid base64url')
  }
  let payload: unknown
  try {
    payload = JSON.parse(json)
  } catch {
    throw new Error('Invalid JWT: payload is not valid JSON')
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Invalid JWT: payload is not an object')
  }
  return payload as JwtClaims
}
