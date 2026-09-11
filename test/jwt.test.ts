import { describe, expect, it } from 'vitest'
import { decodeJwtPayload } from '../src/jwt.js'
import { fakeJwt } from './helpers.js'

describe('decodeJwtPayload', () => {
  it('decodes claims including unicode', () => {
    const claims = decodeJwtPayload(fakeJwt({ sub: 'abc', exp: 123, email: 'ø@example.com', client_id: 'c' }))
    expect(claims).toEqual({ sub: 'abc', exp: 123, email: 'ø@example.com', client_id: 'c' })
  })

  it('rejects garbage', () => {
    expect(() => decodeJwtPayload('nope')).toThrow(/three/)
    expect(() => decodeJwtPayload('a.!!!.c')).toThrow(/base64url/)
    expect(() => decodeJwtPayload(`a.${Buffer.from('[1]').toString('base64url')}.c`)).toThrow(/object/)
    expect(() => decodeJwtPayload(`a.${Buffer.from('{').toString('base64url')}.c`)).toThrow(/JSON/)
  })
})
