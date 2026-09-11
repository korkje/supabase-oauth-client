import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { base64UrlDecode, base64UrlEncode, createCodeChallenge, createCodeVerifier, createState } from '../src/pkce.js'

describe('base64url', () => {
  it('round-trips arbitrary bytes without padding', () => {
    for (const len of [0, 1, 2, 3, 4, 31, 32, 33, 64]) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + 11) % 256)
      const enc = base64UrlEncode(bytes)
      expect(enc).not.toMatch(/[+/=]/)
      expect(Array.from(base64UrlDecode(enc))).toEqual(Array.from(bytes))
    }
  })

  it('matches Node base64url', () => {
    const bytes = new Uint8Array([251, 255, 254, 0, 1, 2])
    expect(base64UrlEncode(bytes)).toBe(Buffer.from(bytes).toString('base64url'))
  })

  it('rejects malformed input', () => {
    expect(() => base64UrlDecode('a')).toThrow()
  })
})

describe('PKCE', () => {
  it('creates a 43-char verifier from the unreserved set', () => {
    const v = createCodeVerifier()
    expect(v).toHaveLength(43)
    expect(v).toMatch(/^[A-Za-z0-9\-_]+$/)
    expect(createCodeVerifier()).not.toBe(v)
  })

  it('derives the S256 challenge', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    // RFC 7636 appendix B expected value
    expect(await createCodeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    const v2 = createCodeVerifier()
    expect(await createCodeChallenge(v2)).toBe(createHash('sha256').update(v2).digest('base64url'))
  })

  it('creates unique states', () => {
    const states = new Set(Array.from({ length: 50 }, () => createState()))
    expect(states.size).toBe(50)
    expect(createState()).toMatch(/^[A-Za-z0-9\-_]{43}$/)
  })
})
