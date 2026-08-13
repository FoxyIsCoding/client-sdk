const DISCOVERY_CACHE = new Map();
export async function fetchDiscovery(issuer) {
    const cached = DISCOVERY_CACHE.get(issuer);
    if (cached)
        return cached;
    const url = issuer.replace(/\/$/, '') + '/.well-known/openid-configuration';
    const res = await fetch(url);
    if (!res.ok)
        throw new Error(`Failed to fetch OIDC discovery: ${res.status}`);
    const doc = await res.json();
    DISCOVERY_CACHE.set(issuer, doc);
    return doc;
}
export function base64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (const b of bytes)
        binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64url(array.buffer);
}
export async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64url(digest);
}
export function generateState() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return base64url(array.buffer);
}
export function decodeJwtPayload(token) {
    const parts = token.split('.');
    if (parts.length < 2)
        throw new Error('Invalid JWT');
    const payload = parts[1];
    const decoded = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = decoded + '='.repeat((4 - (decoded.length % 4)) % 4);
    return JSON.parse(atob(padded));
}
export function isTokenExpired(token) {
    try {
        const payload = decodeJwtPayload(token);
        if (!payload.exp)
            return false;
        return Date.now() >= payload.exp * 1000;
    }
    catch {
        return true;
    }
}
export const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
