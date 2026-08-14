import { type VoidAuthConfig, type OAuthTokens, type OIDCUser } from './core.js';
export interface VoidAuthServerConfig extends VoidAuthConfig {
    clientSecret: string;
}
export declare class VoidAuthServer {
    private config;
    private discovery;
    private jwks;
    private jwksFetchedAt;
    constructor(config: VoidAuthServerConfig);
    private getDiscovery;
    generateAuthorizationUrl(options?: {
        scopes?: string[];
        state?: string;
        nonce?: string;
        codeChallenge?: string;
    }): string;
    generateCodeVerifier(): string;
    generateCodeChallenge(verifier: string): string;
    exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens>;
    getUserInfo(accessToken: string): Promise<OIDCUser>;
    refreshToken(refreshToken: string): Promise<OAuthTokens>;
    revokeToken(token: string): Promise<void>;
    decodeIdToken(idToken: string): Record<string, any>;
    verifyIdToken(idToken: string): Promise<Record<string, any>>;
}
export interface VoidAuthClientConfig extends VoidAuthConfig {
    clientSecret: string;
    sessionSecret?: string;
    cookieName?: string;
    cookieSecure?: boolean;
    cookieMaxAge?: number;
}
export interface VoidAuthSession {
    user: OIDCUser;
    tokens: OAuthTokens;
}
export interface CallbackResult {
    session: VoidAuthSession;
    setCookie: string;
    clearStateCookie?: string;
    returnTo: string;
}
export declare class VoidAuthClient extends VoidAuthServer {
    private sessionSecret;
    private cookieName;
    private cookieSecure;
    private cookieMaxAge;
    private returnToName;
    constructor(config: VoidAuthClientConfig);
    generateAuthorizationUrl(options?: {
        scopes?: string[];
        state?: string;
        nonce?: string;
        codeChallenge?: string;
        returnTo?: string;
    }): string;
    exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens>;
    buildLoginUrl(returnTo?: string): {
        url: string;
        stateCookie: string;
    };
    parseSessionCookie(cookieHeader?: string): string | null;
    getSession(cookieHeader?: string): Promise<VoidAuthSession | null>;
    requireSession(cookieHeader?: string): Promise<VoidAuthSession>;
    handleCallback(url: string, cookieHeader?: string): Promise<CallbackResult>;
    destroySession(): string;
}
export type { OAuthTokens, OIDCUser };
