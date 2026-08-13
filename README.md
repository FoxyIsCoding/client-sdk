# @voidauth/client

VoidAuth OIDC client for browser and Node.js. Supports PKCE, token exchange, user info, and the VoidAuth Storage API.

## Install

```bash
npm install @voidauth/client
```

## Browser (PKCE)

```typescript
import { VoidAuth } from '@voidauth/client/browser'

const auth = new VoidAuth({
  issuer: 'https://auth.stwupid.tech',
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:3000/callback',
  scopes: ['openid', 'profile', 'email'],
})

// Start login (redirects to authorize)
await auth.login()

// After redirect back, exchange code
const { user, tokens } = await auth.handleCallback()
console.log('Logged in:', user.name)

// Check auth
if (auth.isAuthenticated()) {
  const token = auth.getToken()
}

// Logout
await auth.logout()
```

## Node.js

```typescript
import { VoidAuthServer } from '@voidauth/client/node'

const auth = new VoidAuthServer({
  issuer: 'https://auth.stwupid.tech',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:3000/callback',
})

// Exchange authorization code
const { tokens, user } = await auth.exchangeCode('AUTH_CODE')

// Get user info
const userInfo = await auth.getUserInfo(tokens.access_token)

// Refresh token
const refreshed = await auth.refreshToken(tokens.refresh_token)

// Revoke token
await auth.revokeToken(tokens.refresh_token)

// Verify ID token (RS256)
const claims = await auth.verifyIdToken(tokens.id_token)
```

## API Reference

### VoidAuth (Browser)

| Method | Returns | Description |
|---|---|---|
| `login(returnTo?)` | `Promise<void>` | Redirect to authorize endpoint |
| `handleCallback()` | `Promise<{user, tokens}>` | Exchange code for tokens |
| `isAuthenticated()` | `boolean` | Check if logged in |
| `getToken()` | `string \| null` | Get access token |
| `getUser()` | `OIDCUser \| null` | Get current user |
| `refresh()` | `Promise<OAuthTokens>` | Refresh access token |
| `logout()` | `Promise<void>` | Clear tokens |

### VoidAuthServer (Node.js)

| Method | Returns | Description |
|---|---|---|
| `exchangeCode(code)` | `Promise<{tokens, user}>` | Exchange auth code |
| `getUserInfo(accessToken)` | `Promise<OIDCUser>` | Get user info |
| `refreshToken(refreshToken)` | `Promise<OAuthTokens>` | Refresh token |
| `revokeToken(token)` | `Promise<void>` | Revoke token |
| `verifyIdToken(idToken)` | `Promise<OIDCUser>` | Verify ID token |

## License

MIT
