
<div align="center">
  
## - client-sdk -
an sdk for VoidAuth oauth login and OIDC client.
<br>
<br>

```bash
npm install @voidauth/client
```


## Usage:
this package has currently 2 options on how to use it.. Either Browser (PKCE) or Node.js
<br>

#### node.js (express) example:
*the `VoidAuthClient` class handles the OAuth flow unlike the server which handles sessions itself.*

```typescript
import express from 'express'
import { VoidAuthClient } from '@voidauth/client/node'

const app = express()

const voidauth = new VoidAuthClient({
  issuer: 'https://auth.stwupid.tech',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:3000/callback',
  sessionSecret: process.env.SESSION_SECRET, // optional — ephemeral if omitted
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

app.listen(3000, () => console.log('Listening on http://localhost:3000'))
```

lower-level `VoidAuthServer` is still available if you prefer to manage the session yourself:

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
---

### API Reference:


#### VoidAuthServer (Node.js)

| Method | Returns | Description |
|---|---|---|
| `exchangeCode(code)` | `Promise<OAuthTokens>` | Exchange auth code |
| `getUserInfo(accessToken)` | `Promise<OIDCUser>` | Get user info |
| `refreshToken(refreshToken)` | `Promise<OAuthTokens>` | Refresh token |
| `revokeToken(token)` | `Promise<void>` | Revoke token |
| `verifyIdToken(idToken)` | `Promise<OIDCUser>` | Verify ID token |

#### VoidAuthClient (Node.js, session-aware)

| Method | Returns | Description |
|---|---|---|
| `buildLoginUrl(returnTo?)` | `{url, stateCookie}` | Authorize URL + state cookie to set |
| `handleCallback(url, cookieHeader?)` | `Promise<{session, setCookie, returnTo}>` | Exchange code, build session cookie |
| `getSession(cookieHeader?)` | `Promise<VoidAuthSession \| null>` | Decrypt + return session from cookie |
| `requireSession(cookieHeader?)` | `Promise<VoidAuthSession>` | Throws if no valid session |
| `destroySession()` | `string` | Session-clearing Set-Cookie header |

#### - <img src="https://wsrv.nl/?url=https://raw.githubusercontent.com/voidsuite/.github/refs/heads/main/logo.png&w=40"  align="center"/> -

</div>

