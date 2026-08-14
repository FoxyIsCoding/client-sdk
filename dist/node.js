import { createCipheriv, createDecipheriv, createHash, randomBytes, } from 'node:crypto';
import { fetchDiscovery, decodeJwtPayload, DEFAULT_SCOPES, } from './core.js';
export class VoidAuthServer {
    config;
    discovery = null;
    jwks = null;
    jwksFetchedAt = 0;
    constructor(config) {
        this.config = {
            issuer: config.issuer.replace(/\/$/, ''),
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            redirectUri: config.redirectUri,
            scopes: config.scopes || DEFAULT_SCOPES,
        };
    }
    async getDiscovery() {
        if (!this.discovery) {
            this.discovery = await fetchDiscovery(this.config.issuer);
        }
        return this.discovery;
    }
    generateAuthorizationUrl(options) {
        const scopes = options?.scopes || this.config.scopes;
        const state = options?.state || randomBytes(16).toString('hex');
        const nonce = options?.nonce || randomBytes(16).toString('hex');
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: scopes.join(' '),
            state,
            nonce,
        });
        if (options?.codeChallenge) {
            params.set('code_challenge', options.codeChallenge);
            params.set('code_challenge_method', 'S256');
        }
        return `${this.config.issuer}/oauth/authorize?${params.toString()}`;
    }
    generateCodeVerifier() {
        return randomBytes(32).toString('base64url');
    }
    generateCodeChallenge(verifier) {
        return createHash('sha256').update(verifier).digest('base64url');
    }
    async exchangeCode(code, codeVerifier) {
        const discovery = await this.getDiscovery();
        const body = {
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.config.redirectUri,
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
        };
        if (codeVerifier)
            body.code_verifier = codeVerifier;
        const res = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Token exchange failed: ${res.status} ${text}`);
        }
        const data = await res.json();
        return {
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            idToken: data.id_token,
            expiresIn: data.expires_in,
            scope: data.scope,
        };
    }
    async getUserInfo(accessToken) {
        const discovery = await this.getDiscovery();
        const res = await fetch(discovery.userinfo_endpoint, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!res.ok)
            throw new Error(`Userinfo failed: ${res.status}`);
        return res.json();
    }
    async refreshToken(refreshToken) {
        const discovery = await this.getDiscovery();
        const res = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
            }),
        });
        if (!res.ok)
            throw new Error(`Token refresh failed: ${res.status}`);
        const data = await res.json();
        return {
            accessToken: data.access_token,
            refreshToken: data.refresh_token || refreshToken,
            idToken: data.id_token,
            expiresIn: data.expires_in,
            scope: data.scope,
        };
    }
    async revokeToken(token) {
        const discovery = await this.getDiscovery();
        await fetch(discovery.revocation_endpoint || `${this.config.issuer}/oauth/revoke`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token,
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
            }),
        });
    }
    decodeIdToken(idToken) {
        return decodeJwtPayload(idToken);
    }
    async verifyIdToken(idToken) {
        const payload = this.decodeIdToken(idToken);
        if (payload.iss !== this.config.issuer)
            throw new Error('Invalid issuer');
        if (payload.aud !== this.config.clientId)
            throw new Error('Invalid audience');
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now)
            throw new Error('Token expired');
        if (payload.nbf && payload.nbf > now)
            throw new Error('Token not yet valid');
        return payload;
    }
}
function encrypt(secret, data) {
    const key = createHash('sha256').update(secret).digest();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([
        cipher.update(JSON.stringify(data), 'utf8'),
        cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64url')}.${tag.toString('base64url')}.${enc.toString('base64url')}`;
}
function decrypt(secret, value) {
    const key = createHash('sha256').update(secret).digest();
    const [ivB64, tagB64, dataB64] = value.split('.');
    if (!ivB64 || !tagB64 || !dataB64)
        throw new Error('Malformed session');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    const dec = Buffer.concat([
        decipher.update(Buffer.from(dataB64, 'base64url')),
        decipher.final(),
    ]);
    return JSON.parse(dec.toString('utf8'));
}
function parseCookies(header) {
    const out = {};
    if (!header)
        return out;
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1)
            continue;
        const name = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (name)
            out[name] = decodeURIComponent(value);
    }
    return out;
}
export class VoidAuthClient extends VoidAuthServer {
    sessionSecret;
    cookieName;
    cookieSecure;
    cookieMaxAge;
    returnToName;
    constructor(config) {
        super(config);
        if (!config.sessionSecret || config.sessionSecret.length < 16) {
            throw new Error('sessionSecret must be at least 16 characters');
        }
        this.sessionSecret = config.sessionSecret;
        this.cookieName = config.cookieName || 'va_session';
        this.cookieSecure = config.cookieSecure ?? false;
        this.cookieMaxAge = config.cookieMaxAge || 60 * 60 * 24;
        this.returnToName = `va_${this.cookieName}_state`;
    }
    generateAuthorizationUrl(options) {
        return super.generateAuthorizationUrl(options);
    }
    async exchangeCode(code, codeVerifier) {
        return super.exchangeCode(code, codeVerifier);
    }
    buildLoginUrl(returnTo = '/') {
        const state = randomBytes(16).toString('hex');
        const url = super.generateAuthorizationUrl({ state });
        const payload = encrypt(this.sessionSecret, { state, returnTo });
        const stateCookie = `${this.returnToName}=${payload}; Path=/; HttpOnly; ${this.cookieSecure ? 'Secure; ' : ''}SameSite=Lax; Max-Age=${this.cookieMaxAge}`;
        return { url, stateCookie };
    }
    parseSessionCookie(cookieHeader) {
        return parseCookies(cookieHeader)[this.cookieName] || null;
    }
    async getSession(cookieHeader) {
        const raw = this.parseSessionCookie(cookieHeader);
        if (!raw)
            return null;
        try {
            const data = decrypt(this.sessionSecret, raw);
            if (data?.tokens?.accessToken) {
                return data;
            }
            return null;
        }
        catch {
            return null;
        }
    }
    async requireSession(cookieHeader) {
        const session = await this.getSession(cookieHeader);
        if (!session)
            throw new Error('No session');
        return session;
    }
    async handleCallback(url, cookieHeader) {
        const parsed = new URL(url);
        const code = parsed.searchParams.get('code');
        const state = parsed.searchParams.get('state');
        const error = parsed.searchParams.get('error');
        if (error)
            throw new Error(`OAuth error: ${error}`);
        if (!code)
            throw new Error('No authorization code in URL');
        let returnTo = '/';
        const savedState = parseCookies(cookieHeader)[this.returnToName];
        if (savedState) {
            try {
                const saved = decrypt(this.sessionSecret, savedState);
                if (saved.state && saved.state !== state)
                    throw new Error('State mismatch');
                if (saved.returnTo)
                    returnTo = saved.returnTo;
            }
            catch {
                returnTo = '/';
            }
        }
        const tokens = await this.exchangeCode(code);
        const user = await this.verifyIdToken(tokens.idToken || '');
        const session = { user, tokens };
        const value = encrypt(this.sessionSecret, session);
        const setCookie = `${this.cookieName}=${value}; Path=/; HttpOnly; ${this.cookieSecure ? 'Secure; ' : ''}SameSite=Lax; Max-Age=${this.cookieMaxAge}`;
        const clearStateCookie = `${this.returnToName}=; Path=/; Max-Age=0`;
        return { session, setCookie, clearStateCookie, returnTo };
    }
    destroySession() {
        return `${this.cookieName}=; Path=/; Max-Age=0`;
    }
}
