import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
} from 'node:crypto'
import {
  type VoidAuthConfig,
  type OAuthTokens,
  type OIDCUser,
  type OIDCDiscovery,
  fetchDiscovery,
  decodeJwtPayload,
  DEFAULT_SCOPES,
} from './core.js'

export interface VoidAuthServerConfig extends VoidAuthConfig {
  clientSecret: string
}

export class VoidAuthServer {
  private config: Required<VoidAuthServerConfig>
  private discovery: OIDCDiscovery | null = null
  private jwks: any = null
  private jwksFetchedAt = 0

  constructor(config: VoidAuthServerConfig) {
    this.config = {
      issuer: config.issuer.replace(/\/$/, ''),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      scopes: config.scopes || DEFAULT_SCOPES,
    }
  }

  private async getDiscovery(): Promise<OIDCDiscovery> {
    if (!this.discovery) {
      this.discovery = await fetchDiscovery(this.config.issuer)
    }
    return this.discovery
  }

  generateAuthorizationUrl(options?: {
    scopes?: string[]
    state?: string
    nonce?: string
    codeChallenge?: string
  }): string {
    const scopes = options?.scopes || this.config.scopes
    const state = options?.state || randomBytes(16).toString('hex')
    const nonce = options?.nonce || randomBytes(16).toString('hex')

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
      nonce,
    })

    if (options?.codeChallenge) {
      params.set('code_challenge', options.codeChallenge)
      params.set('code_challenge_method', 'S256')
    }

    return `${this.config.issuer}/oauth/authorize?${params.toString()}`
  }

  generateCodeVerifier(): string {
    return randomBytes(32).toString('base64url')
  }

  generateCodeChallenge(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url')
  }

  async exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens> {
    const discovery = await this.getDiscovery()

    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    }

    if (codeVerifier) body.code_verifier = codeVerifier

    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (!res.ok) {
      const text = await res.text()
      throw new Error(`Token exchange failed: ${res.status} ${text}`)
    }

    const data = await res.json()
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      expiresIn: data.expires_in,
      scope: data.scope,
    }
  }

  async getUserInfo(accessToken: string): Promise<OIDCUser> {
    const discovery = await this.getDiscovery()
    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    if (!res.ok) throw new Error(`Userinfo failed: ${res.status}`)
    return res.json()
  }

  async refreshToken(refreshToken: string): Promise<OAuthTokens> {
    const discovery = await this.getDiscovery()
    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      }),
    })

    if (!res.ok) throw new Error(`Token refresh failed: ${res.status}`)
    const data = await res.json()

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken,
      idToken: data.id_token,
      expiresIn: data.expires_in,
      scope: data.scope,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const discovery = await this.getDiscovery()
    await fetch(discovery.revocation_endpoint || `${this.config.issuer}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      }),
    })
  }

  decodeIdToken(idToken: string): Record<string, any> {
    return decodeJwtPayload(idToken)
  }

  async verifyIdToken(idToken: string): Promise<Record<string, any>> {
    const payload = this.decodeIdToken(idToken)

    if (payload.iss !== this.config.issuer) throw new Error('Invalid issuer')
    if (payload.aud !== this.config.clientId) throw new Error('Invalid audience')

    const now = Math.floor(Date.now() / 1000)
    if (payload.exp && payload.exp < now) throw new Error('Token expired')
    if (payload.nbf && payload.nbf > now) throw new Error('Token not yet valid')

    return payload
  }
}

export interface VoidAuthClientConfig extends VoidAuthConfig {
  clientSecret: string
  sessionSecret: string
  cookieName?: string
  cookieSecure?: boolean
  cookieMaxAge?: number
}

export interface VoidAuthSession {
  user: OIDCUser
  tokens: OAuthTokens
}

export interface CallbackResult {
  session: VoidAuthSession
  setCookie: string
  clearStateCookie?: string
  returnTo: string
}

function encrypt(secret: string, data: object): string {
  const key = createHash('sha256').update(secret).digest()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const enc = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
  ])
  const tag = cipher.getAuthTag()
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${enc.toString('base64url')}`
}

function decrypt(secret: string, value: string): object {
  const key = createHash('sha256').update(secret).digest()
  const [ivB64, tagB64, dataB64] = value.split('.')
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('Malformed session')
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivB64, 'base64url')
  )
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'))
  const dec = Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64url')),
    decipher.final(),
  ])
  return JSON.parse(dec.toString('utf8'))
}

function parseCookies(header?: string): Record<string, string> {
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const name = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (name) out[name] = decodeURIComponent(value)
  }
  return out
}

export class VoidAuthClient extends VoidAuthServer {
  private sessionSecret: string
  private cookieName: string
  private cookieSecure: boolean
  private cookieMaxAge: number
  private returnToName: string

  constructor(config: VoidAuthClientConfig) {
    super(config)
    if (!config.sessionSecret || config.sessionSecret.length < 16) {
      throw new Error('sessionSecret must be at least 16 characters')
    }
    this.sessionSecret = config.sessionSecret
    this.cookieName = config.cookieName || 'va_session'
    this.cookieSecure = config.cookieSecure ?? false
    this.cookieMaxAge = config.cookieMaxAge || 60 * 60 * 24
    this.returnToName = `va_${this.cookieName}_state`
  }

  generateAuthorizationUrl(options?: {
    scopes?: string[]
    state?: string
    nonce?: string
    codeChallenge?: string
    returnTo?: string
  }): string {
    return super.generateAuthorizationUrl(options)
  }

  async exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens> {
    return super.exchangeCode(code, codeVerifier)
  }

  buildLoginUrl(returnTo = '/'): { url: string; stateCookie: string } {
    const state = randomBytes(16).toString('hex')
    const url = super.generateAuthorizationUrl({ state })
    const payload = encrypt(this.sessionSecret, { state, returnTo })
    const stateCookie = `${this.returnToName}=${payload}; Path=/; HttpOnly; ${
      this.cookieSecure ? 'Secure; ' : ''
    }SameSite=Lax; Max-Age=${this.cookieMaxAge}`
    return { url, stateCookie }
  }

  parseSessionCookie(cookieHeader?: string): string | null {
    return parseCookies(cookieHeader)[this.cookieName] || null
  }

  async getSession(cookieHeader?: string): Promise<VoidAuthSession | null> {
    const raw = this.parseSessionCookie(cookieHeader)
    if (!raw) return null
    try {
      const data = decrypt(this.sessionSecret, raw) as {
        tokens: OAuthTokens
        user: OIDCUser
      }
      if (data?.tokens?.accessToken) {
        return data as VoidAuthSession
      }
      return null
    } catch {
      return null
    }
  }

  async requireSession(cookieHeader?: string): Promise<VoidAuthSession> {
    const session = await this.getSession(cookieHeader)
    if (!session) throw new Error('No session')
    return session
  }

  async handleCallback(
    url: string,
    cookieHeader?: string
  ): Promise<CallbackResult> {
    const parsed = new URL(url)
    const code = parsed.searchParams.get('code')
    const state = parsed.searchParams.get('state')
    const error = parsed.searchParams.get('error')
    if (error) throw new Error(`OAuth error: ${error}`)
    if (!code) throw new Error('No authorization code in URL')

    let returnTo = '/'
    const savedState = parseCookies(cookieHeader)[this.returnToName]
    if (savedState) {
      try {
        const saved = decrypt(this.sessionSecret, savedState) as {
          state?: string
          returnTo?: string
        }
        if (saved.state && saved.state !== state) throw new Error('State mismatch')
        if (saved.returnTo) returnTo = saved.returnTo
      } catch {
        returnTo = '/'
      }
    }

    const tokens = await this.exchangeCode(code)
    const user = await this.verifyIdToken(tokens.idToken || '')

    const session: VoidAuthSession = { user, tokens }
    const value = encrypt(this.sessionSecret, session)
    const setCookie = `${this.cookieName}=${value}; Path=/; HttpOnly; ${
      this.cookieSecure ? 'Secure; ' : ''
    }SameSite=Lax; Max-Age=${this.cookieMaxAge}`
    const clearStateCookie = `${this.returnToName}=; Path=/; Max-Age=0`

    return { session, setCookie, clearStateCookie, returnTo }
  }

  destroySession(): string {
    return `${this.cookieName}=; Path=/; Max-Age=0`
  }
}

export type { OAuthTokens, OIDCUser }
