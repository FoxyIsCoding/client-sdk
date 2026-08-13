import { type VoidAuthConfig, type OAuthTokens, type OIDCUser } from './core.js';
export declare class VoidAuth {
    private config;
    private tokens;
    private user;
    constructor(config: VoidAuthConfig);
    private loadFromStorage;
    private saveToStorage;
    login(returnTo?: string): Promise<void>;
    handleCallback(): Promise<{
        user: OIDCUser;
        tokens: OAuthTokens;
    }>;
    private fetchUserinfo;
    getUser(): OIDCUser | null;
    getToken(): string | null;
    isAuthenticated(): boolean;
    refresh(): Promise<OAuthTokens>;
    logout(): Promise<void>;
}
export type { VoidAuthConfig, OAuthTokens, OIDCUser };
