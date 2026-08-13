export interface VoidAuthConfig {
    issuer: string;
    clientId: string;
    redirectUri: string;
    scopes?: string[];
}
export interface OAuthTokens {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    expiresIn?: number;
    scope?: string;
}
export interface OIDCUser {
    sub?: string;
    name?: string;
    preferred_username?: string;
    email?: string;
    email_verified?: boolean;
    updated_at?: number;
    [key: string]: any;
}
export interface OIDCDiscovery {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri: string;
    revocation_endpoint?: string;
    scopes_supported: string[];
    response_types_supported: string[];
    code_challenge_methods_supported: string[];
    claims_supported: string[];
}
export declare function fetchDiscovery(issuer: string): Promise<OIDCDiscovery>;
export declare function base64url(buffer: ArrayBuffer): string;
export declare function generateCodeVerifier(): string;
export declare function generateCodeChallenge(verifier: string): Promise<string>;
export declare function generateState(): string;
export declare function decodeJwtPayload(token: string): OIDCUser;
export declare function isTokenExpired(token: string): boolean;
export declare const DEFAULT_SCOPES: string[];
