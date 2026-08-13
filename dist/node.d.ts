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
export type { OAuthTokens, OIDCUser };
