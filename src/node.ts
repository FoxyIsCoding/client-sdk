import { createHash, randomBytes } from 'node:crypto'
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

export type { OAuthTokens, OIDCUser }
