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

## Node.js (Express)

The `VoidAuthClient` class handles the full OAuth flow — login redirect, callback exchange, and an encrypted session cookie — so no cookie-parser or manual session wiring is needed.

```typescript
import express from 'express'
import { VoidAuthClient } from '@voidauth/client/node'

const app = express()

const voidauth = new VoidAuthClient({
  issuer: 'https://auth.stwupid.tech',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:3000/callback',
  sessionSecret: process.env.SESSION_SECRET!, // used to encrypt the session cookie
  cookieSecure: process.env.NODE_ENV === 'production',
})

app.get('/', async (req, res) => {
  const session = await voidauth.getSession(req.headers.cookie)
  if (!session) {
    const { url, stateCookie } = voidauth.buildLoginUrl('/')
    res.setHeader('set-cookie', stateCookie)
    res.redirect(url)
    return
  }
  res.send(`<h1>Hello ${session.user.email}</h1>
    <p>Hidden message: the void whispers</p>`)
})

app.get('/callback', async (req, res) => {
  try {
    const result = await voidauth.handleCallback(
      `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      req.headers.cookie
    )
    res.setHeader('set-cookie', [result.setCookie, result.clearStateCookie!])
    res.redirect(result.returnTo)
  } catch (err) {
    res.status(400).send((err as Error).message)
  }
})

app.get('/logout', (_req, res) => {
  res.setHeader('set-cookie', voidauth.destroySession())
  res.redirect('/')
})
```

Lower-level `VoidAuthServer` is still available if you prefer to manage the session yourself:

```typescript
import { VoidAuthServer } from '@voidauth/client/node'

const auth = new VoidAuthServer({
  issuer: 'https://auth.stwupid.tech',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:3000/callback',
})

// Exchange authorization code
const tokens = await auth.exchangeCode('AUTH_CODE')

// Get user info
const userInfo = await auth.getUserInfo(tokens.accessToken)

// Refresh token
const refreshed = await auth.refreshToken(tokens.refreshToken)

// Revoke token
await auth.revokeToken(tokens.refreshToken)

// Verify ID token (claims: iss, aud, exp, nbf)
const claims = await auth.verifyIdToken(tokens.idToken!)
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
| `exchangeCode(code)` | `Promise<OAuthTokens>` | Exchange auth code |
| `getUserInfo(accessToken)` | `Promise<OIDCUser>` | Get user info |
| `refreshToken(refreshToken)` | `Promise<OAuthTokens>` | Refresh token |
| `revokeToken(token)` | `Promise<void>` | Revoke token |
| `verifyIdToken(idToken)` | `Promise<OIDCUser>` | Verify ID token |

### VoidAuthClient (Node.js, session-aware)

| Method | Returns | Description |
|---|---|---|
| `buildLoginUrl(returnTo?)` | `{url, stateCookie}` | Authorize URL + state cookie to set |
| `handleCallback(url, cookieHeader?)` | `Promise<{session, setCookie, returnTo}>` | Exchange code, build session cookie |
| `getSession(cookieHeader?)` | `Promise<VoidAuthSession \| null>` | Decrypt + return session from cookie |
| `requireSession(cookieHeader?)` | `Promise<VoidAuthSession>` | Throws if no valid session |
| `destroySession()` | `string` | Session-clearing Set-Cookie header |

## License

MIT
