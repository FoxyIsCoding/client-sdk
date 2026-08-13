import { describe, it } from 'node:test'
import assert from 'node:assert'
import {
  base64url,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  decodeJwtPayload,
  isTokenExpired,
} from './core.js'

describe('base64url', () => {
  it('encodes bytes to base64url', () => {
    const input = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
    const result = base64url(input.buffer)
    assert.strictEqual(result, 'SGVsbG8')
  })

  it('pads correctly', () => {
    const input = new Uint8Array([0])
    const result = base64url(input.buffer)
    assert.ok(result.length > 0)
    assert.ok(!result.includes('+'))
    assert.ok(!result.includes('/'))
  })
})

describe('generateCodeVerifier', () => {
  it('returns a string of correct length', () => {
    const verifier = generateCodeVerifier()
    assert.strictEqual(typeof verifier, 'string')
    assert.strictEqual(verifier.length, 43) // 32 bytes -> 43 base64url chars
  })

  it('contains only base64url chars', () => {
    const verifier = generateCodeVerifier()
    assert.ok(/^[A-Za-z0-9_-]+$/.test(verifier))
  })
})

describe('generateCodeChallenge', () => {
  it('returns a base64url-encoded SHA-256 hash', async () => {
    const verifier = 'test-verifier-string'
    const challenge = await generateCodeChallenge(verifier)
    assert.strictEqual(typeof challenge, 'string')
    assert.ok(challenge.length > 0)
    assert.ok(/^[A-Za-z0-9_-]+$/.test(challenge))
  })
})

describe('generateState', () => {
  it('returns a string of correct length', () => {
    const state = generateState()
    assert.strictEqual(typeof state, 'string')
    assert.strictEqual(state.length, 22) // 16 bytes -> 22 base64url chars
  })

  it('generates unique values', () => {
    const state1 = generateState()
    const state2 = generateState()
    assert.notStrictEqual(state1, state2)
  })
})

describe('decodeJwtPayload', () => {
  it('decodes a valid JWT payload', () => {
    // Create a mock JWT: header.payload.signature
    const payload = { sub: '123', name: 'Test User', email: 'test@example.com' }
    const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const token = `header.${encoded}.signature`

    const decoded = decodeJwtPayload(token)
    assert.strictEqual(decoded.sub, '123')
    assert.strictEqual(decoded.name, 'Test User')
    assert.strictEqual(decoded.email, 'test@example.com')
  })

  it('throws on invalid token', () => {
    assert.throws(() => decodeJwtPayload('invalid'))
  })
})

describe('isTokenExpired', () => {
  it('returns true for expired tokens', () => {
    // Create a token with exp in the past
    const payload = { sub: '123', exp: 1000000000 }
    const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const token = `header.${encoded}.signature`
    assert.ok(isTokenExpired(token))
  })

  it('returns false for valid tokens', () => {
    const future = Math.floor(Date.now() / 1000) + 3600
    const payload = { sub: '123', exp: future }
    const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const token = `header.${encoded}.signature`
    assert.ok(!isTokenExpired(token))
  })
})
