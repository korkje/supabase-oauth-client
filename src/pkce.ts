/**
 * PKCE (RFC 7636) helpers plus the tiny encoding utilities they need.
 * Web Crypto only: works in browsers, Node 20+, Deno, Bun and Workers.
 */

const ENCODER = new TextEncoder()
const DECODER = new TextDecoder()

function getCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('supabase-oauth-client: Web Crypto (globalThis.crypto) is not available in this environment')
  }
  return c
}

/** Cryptographically random bytes. */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  getCrypto().getRandomValues(bytes)
  return bytes
}

/** Base64url-encode bytes without padding (RFC 4648 §5). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Base64url-decode (padding optional) to bytes. */
export function base64UrlDecode(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/')
  const pad = base64.length % 4
  if (pad === 2) base64 += '=='
  else if (pad === 3) base64 += '='
  else if (pad === 1) throw new Error('Invalid base64url string')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/** Base64url-decode to a UTF-8 string. */
export function base64UrlDecodeToString(input: string): string {
  return DECODER.decode(base64UrlDecode(input))
}

/**
 * Create a PKCE code verifier: 32 random bytes, base64url-encoded, giving a
 * 43-character string from the unreserved character set (RFC 7636 §4.1).
 */
export function createCodeVerifier(): string {
  return base64UrlEncode(randomBytes(32))
}

/** S256 code challenge: base64url(sha256(ascii(verifier))). */
export async function createCodeChallenge(verifier: string): Promise<string> {
  const subtle = getCrypto().subtle
  if (!subtle || typeof subtle.digest !== 'function') {
    throw new Error(
      'supabase-oauth-client: crypto.subtle is not available. Note that browsers only expose it in secure contexts (https or localhost).',
    )
  }
  const digest = await subtle.digest('SHA-256', ENCODER.encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

/** Random, URL-safe `state` value (32 bytes of entropy). */
export function createState(): string {
  return base64UrlEncode(randomBytes(32))
}
