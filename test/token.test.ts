import { describe, expect, it } from 'vitest'
import { OAuthError, applyClientAuth, isOAuthError, tokenRequest } from '../src/token.js'
import { mockFetch, tokenJson } from './helpers.js'

const URL_ = 'https://x.supabase.co/auth/v1/oauth/token'

describe('applyClientAuth', () => {
  it('none: client_id in body only', () => {
    const body = new URLSearchParams()
    const headers: Record<string, string> = {}
    applyClientAuth(body, headers, { clientId: 'cid', method: 'none' })
    expect(body.get('client_id')).toBe('cid')
    expect(headers).toEqual({})
  })

  it('client_secret_post: id and secret in body', () => {
    const body = new URLSearchParams()
    const headers: Record<string, string> = {}
    applyClientAuth(body, headers, { clientId: 'cid', clientSecret: 'sec', method: 'client_secret_post' })
    expect(body.get('client_id')).toBe('cid')
    expect(body.get('client_secret')).toBe('sec')
    expect(headers).toEqual({})
  })

  it('client_secret_basic: Authorization header, nothing in body', () => {
    const body = new URLSearchParams()
    const headers: Record<string, string> = {}
    applyClientAuth(body, headers, { clientId: 'cid', clientSecret: 'sec', method: 'client_secret_basic' })
    expect(headers['Authorization']).toBe(`Basic ${Buffer.from('cid:sec').toString('base64')}`)
    expect(body.has('client_id')).toBe(false)
  })

  it('requires a secret for confidential methods', () => {
    expect(() => applyClientAuth(new URLSearchParams(), {}, { clientId: 'cid', method: 'client_secret_basic' })).toThrow(OAuthError)
  })
})

describe('tokenRequest', () => {
  it('posts form-encoded and parses the response', async () => {
    const json = tokenJson()
    const fetch = mockFetch({ json })
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'r' })
    const res = await tokenRequest(fetch, URL_, body, { clientId: 'cid', method: 'none' })
    expect(res).toEqual(json)
    const req = fetch.requests[0]!
    expect(req.method).toBe('POST')
    expect(req.headers['content-type']).toMatch(/^application\/x-www-form-urlencoded/)
    expect(req.body.get('client_id')).toBe('cid')
    expect(req.body.get('grant_type')).toBe('refresh_token')
  })

  it('maps RFC 6749 error bodies', async () => {
    const fetch = mockFetch({ status: 400, json: { error: 'invalid_grant', error_description: 'Invalid refresh token' } })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(isOAuthError(err)).toBe(true)
    expect(err).toMatchObject({ error: 'invalid_grant', errorDescription: 'Invalid refresh token', status: 400, isInvalidGrant: true })
    expect(err.error_description).toBe('Invalid refresh token')
    expect(err.message).toBe('invalid_grant: Invalid refresh token')
  })

  it('maps GoTrue-style error bodies', async () => {
    const fetch = mockFetch({ status: 403, json: { code: 403, error_code: 'bad_oauth_state', msg: 'nope' } })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(err).toMatchObject({ error: 'bad_oauth_state', errorDescription: 'nope', status: 403 })
  })

  it('treats GoTrue refresh-token codes as invalid grant (observed live shape)', async () => {
    const fetch = mockFetch({ status: 400, json: { code: 400, error_code: 'refresh_token_not_found', msg: 'Invalid Refresh Token: Refresh Token Not Found' } })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(err).toMatchObject({ error: 'refresh_token_not_found', isInvalidGrant: true, status: 400 })
  })

  it('handles non-JSON error bodies', async () => {
    const fetch = mockFetch({ status: 502, text: 'Bad Gateway' })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(err).toMatchObject({ error: 'http_502', errorDescription: 'Bad Gateway', status: 502 })
  })

  it('wraps fetch rejections as network_error with cause', async () => {
    const fetch = mockFetch({ networkError: 'Failed to fetch' })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(err).toMatchObject({ error: 'network_error', isNetworkError: true })
    expect(err.cause).toBeInstanceOf(TypeError)
  })

  it('rejects 200 responses without access_token', async () => {
    const fetch = mockFetch({ json: { token_type: 'bearer' } })
    const err = await tokenRequest(fetch, URL_, new URLSearchParams(), { clientId: 'cid', method: 'none' }).catch((e) => e)
    expect(err).toMatchObject({ error: 'invalid_response' })
  })
})
