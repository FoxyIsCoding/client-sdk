import { fetchDiscovery, generateCodeVerifier, generateCodeChallenge, generateState, decodeJwtPayload, isTokenExpired, DEFAULT_SCOPES, } from './core.js';
const STORAGE_KEY = 'voidauth_tokens';
const VERIFIER_KEY = 'voidauth_pkce_verifier';
const STATE_KEY = 'voidauth_state';
export class VoidAuth {
    config;
    tokens = null;
    user = null;
    constructor(config) {
        this.config = {
            issuer: config.issuer.replace(/\/$/, ''),
            clientId: config.clientId,
            redirectUri: config.redirectUri,
            scopes: config.scopes || DEFAULT_SCOPES,
        };
        this.loadFromStorage();
    }
    loadFromStorage() {
        try {
            const raw = sessionStorage.getItem(STORAGE_KEY);
            if (raw) {
                this.tokens = JSON.parse(raw);
                if (this.tokens?.idToken) {
                    try {
                        this.user = decodeJwtPayload(this.tokens.idToken);
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
    saveToStorage() {
        if (this.tokens) {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(this.tokens));
        }
        else {
            sessionStorage.removeItem(STORAGE_KEY);
        }
    }
    async login(returnTo) {
        const discovery = await fetchDiscovery(this.config.issuer);
        const verifier = generateCodeVerifier();
        const state = generateState();
        sessionStorage.setItem(VERIFIER_KEY, verifier);
        sessionStorage.setItem(STATE_KEY, JSON.stringify({ state, returnTo }));
        const challenge = await generateCodeChallenge(verifier);
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: this.config.scopes.join(' '),
            state,
            code_challenge: challenge,
            code_challenge_method: 'S256',
        });
        window.location.href = `${discovery.authorization_endpoint}?${params.toString()}`;
    }
    async handleCallback() {
        const url = new URL(window.location.href);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');
        if (error)
            throw new Error(`OAuth error: ${error}`);
        if (!code)
            throw new Error('No authorization code in URL');
        const saved = JSON.parse(sessionStorage.getItem(STATE_KEY) || '{}');
        if (saved.state && state !== saved.state)
            throw new Error('State mismatch');
        const verifier = sessionStorage.getItem(VERIFIER_KEY);
        if (!verifier)
            throw new Error('No PKCE verifier found');
        const discovery = await fetchDiscovery(this.config.issuer);
        const res = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'authorization_code',
                code,
                redirect_uri: this.config.redirectUri,
                client_id: this.config.clientId,
                code_verifier: verifier,
            }),
        });
        if (!res.ok) {
            const body = await res.text();
            throw new Error(`Token exchange failed: ${res.status} ${body}`);
        }
        const data = await res.json();
        this.tokens = {
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            idToken: data.id_token,
            expiresIn: data.expires_in,
            scope: data.scope,
        };
        if (this.tokens.idToken) {
            this.user = decodeJwtPayload(this.tokens.idToken);
        }
        else {
            this.user = await this.fetchUserinfo(data.access_token);
        }
        this.saveToStorage();
        sessionStorage.removeItem(VERIFIER_KEY);
        sessionStorage.removeItem(STATE_KEY);
        const returnTo = saved.returnTo || '/';
        window.history.replaceState({}, '', returnTo);
        return { user: this.user, tokens: this.tokens };
    }
    async fetchUserinfo(accessToken) {
        const discovery = await fetchDiscovery(this.config.issuer);
        const res = await fetch(discovery.userinfo_endpoint, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!res.ok)
            throw new Error(`Userinfo failed: ${res.status}`);
        return res.json();
    }
    getUser() {
        if (this.user && this.tokens?.idToken && !isTokenExpired(this.tokens.idToken)) {
            return this.user;
        }
        return null;
    }
    getToken() {
        if (this.tokens?.accessToken && !isTokenExpired(this.tokens.accessToken)) {
            return this.tokens.accessToken;
        }
        return null;
    }
    isAuthenticated() {
        return this.getToken() !== null;
    }
    async validateSession() {
        if (!this.tokens?.accessToken)
            return false;
        try {
            await this.fetchUserinfo(this.tokens.accessToken);
            return true;
        }
        catch {
            this.tokens = null;
            this.user = null;
            sessionStorage.removeItem(STORAGE_KEY);
            return false;
        }
    }
    async refresh() {
        if (!this.tokens?.refreshToken)
            throw new Error('No refresh token available');
        const discovery = await fetchDiscovery(this.config.issuer);
        const res = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                refresh_token: this.tokens.refreshToken,
                client_id: this.config.clientId,
            }),
        });
        if (!res.ok)
            throw new Error(`Token refresh failed: ${res.status}`);
        const data = await res.json();
        this.tokens = {
            accessToken: data.access_token,
            refreshToken: data.refresh_token || this.tokens.refreshToken,
            idToken: data.id_token || this.tokens.idToken,
            expiresIn: data.expires_in,
            scope: data.scope,
        };
        if (this.tokens.idToken) {
            this.user = decodeJwtPayload(this.tokens.idToken);
        }
        this.saveToStorage();
        return this.tokens;
    }
    async logout() {
        this.tokens = null;
        this.user = null;
        sessionStorage.removeItem(STORAGE_KEY);
        sessionStorage.removeItem(VERIFIER_KEY);
        sessionStorage.removeItem(STATE_KEY);
    }
}
