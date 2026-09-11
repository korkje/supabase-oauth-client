# supabase-oauth-client

Zero-dependency OAuth 2.1 **client** for [Supabase Auth's OAuth server](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows): authorization code + PKCE, token refresh, and a session you can hand straight to `supabase-js`.

**Direction matters.** This package is for when *a Supabase project is the identity provider* and an application wants tokens issued by it: "Sign in with <your product>" in another app, a CLI, a device, a server acting for a user. If you want to sign users *into* Supabase with Google or GitHub, you do not need this; use `supabase.auth.signInWithOAuth()` in supabase-js.

It exists because supabase-js ships only the *authorization UI* half of the OAuth server (`supabase.auth.oauth.getAuthorizationDetails / approveAuthorization / denyAuthorization`). The client half, building the authorize URL, PKCE, exchanging the code, refreshing, is left to you. This is that half.

Out of scope: the consent UI (that is supabase-js in the identity provider's own web app), and server-side token verification (see [Verifying tokens on a server](#verifying-tokens-on-a-server)).

## Install

```sh
npm install supabase-oauth-client
```

ESM only. Uses Web Crypto and `fetch`; works in browsers (ES2020 output), Node 22+, Deno, Bun, and Workers.

## Overview

```
Client (this package)             Browser (user + identity provider's app)     Supabase Auth
---------------------             ----------------------------------------     -------------
1. begin(): verifier, challenge,
   state -> authorizeUrl
                                  2. Opens authorizeUrl -------------------->  validates client + PKCE,
                                                                               redirects to the provider's
                                                                               consent page ?authorization_id=
                                  3. user signs in if needed, consent page
                                     calls approveAuthorization(id) --------->  issues code, redirects to
                                                                               redirect_uri?code=&state=
4. code + state reach the client
   (same-device redirect, or any
   channel you choose)
5. exchange() / completeFromUrl():
   verify state, POST /auth/v1/oauth/token
   grant_type=authorization_code ------------------------------------------->  access_token, refresh_token,
                                                                               expires_in
6. getAccessToken() feeds supabase-js;
   refresh() runs before expiry ----------------------------------------------> new tokens (refresh token
                                                                               may rotate; stored)
```

Steps 1, 5 and 6 are this package. Step 3 is supabase-js in the identity provider's app. Step 4 is whatever fits your application: the package accepts the code from a redirect URL or from any other source, and treats both the same way.

## Setup in Supabase

Once, in the project that acts as identity provider:

1. **Authentication → OAuth Server**: enable it and set the *authorization path*, for example `/oauth/consent`. Supabase appends it to the project's Site URL and sends users there with `?authorization_id=`.
2. **Authentication → OAuth Apps → Add a new client**: name, one or more redirect URIs (exact matches, no wildcards), and client type. *Public* for browsers, devices and anything that cannot keep a secret; *Confidential* for servers. Note the client id. Confidential clients also show a secret once.

Or programmatically: `supabase.auth.admin.oauth.createClient({ name, redirect_uris, client_type })`.

### The consent page

Lives in the identity provider's web app at the authorization path. Plain supabase-js, not part of this package:

```ts
const id = new URL(location.href).searchParams.get('authorization_id')!

const { data: { session } } = await supabase.auth.getSession()
if (!session) redirectToSignIn({ returnTo: location.href })

const { data: details, error } = await supabase.auth.oauth.getAuthorizationDetails(id) // client name, scopes; for display
if (error?.code === 'oauth_authorization_not_found') showExpiredOrAlreadyUsed()

// Render Approve / Deny (or auto-approve first-party clients), then:
const { data, error } = await supabase.auth.oauth.approveAuthorization(id)
// const { data } = await supabase.auth.oauth.denyAuthorization(id)

location.href = data.redirect_url // -> redirect_uri?code=...&state=...
```

## Usage

### Create the client

```ts
import { createOAuthClient, browserStorage } from 'supabase-oauth-client'

const oauth = createOAuthClient({
  supabaseUrl: 'https://<ref>.supabase.co',
  clientId: '<oauth-client-id>',
  redirectUri: 'https://app.example.com/oauth/callback', // must exactly match a registered URI
  storage: browserStorage(), // localStorage with in-memory fallback; default is in-memory only
})
```

### Path A: same-device redirect

The browser that starts the flow is the one that receives the code. The pending verifier and state must survive the navigation, so use a persistent storage adapter (`localStorage`, `sessionStorage`, `browserStorage()`, or your own).

```ts
// On "Sign in":
const { authorizeUrl } = await oauth.begin()
location.href = authorizeUrl

// On every page load. Resolves null when the URL carries neither code nor error,
// so it is safe to call unconditionally.
try {
  const session = await oauth.completeFromUrl()
  if (session) history.replaceState(null, '', location.pathname) // the package never touches the URL
} catch (e) {
  // OAuthError, e.g. e.error === 'access_denied'
}
```

With the default in-memory storage, `completeFromUrl()` after a real navigation rejects with `no_pending_authorization`, because the verifier died with the previous page.

### Path B: code delivered out of band

The client that needs tokens is not the browser the user authorizes in: a device showing the authorize URL as a QR code, a CLI printing it, a server holding tokens for a user. The redirect URI page receives `code` and `state` and passes them to the client through whatever channel you already have. The client never navigates.

```ts
// Client: start, and show/print/send authorizeUrl however suits you.
const { authorizeUrl, state } = await oauth.begin()

// Client: when { code, state } arrive from your channel.
await oauth.exchange({ code, state }) // verifies state, exchanges, stores, arms the refresh timer
```

```ts
// Redirect URI page (in the browser that authorized): forward the result.
const q = new URL(location.href).searchParams
const result = q.get('error')
  ? { error: q.get('error'), error_description: q.get('error_description'), state: q.get('state') }
  : { code: q.get('code'), state: q.get('state') }
yourChannel.send(result)
```

Call `begin()` again for every new attempt. Each call rotates the verifier and state, and only the latest pending authorization is accepted; a code whose `state` does not match is rejected without disturbing it.

### Hand the session to supabase-js

```ts
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(supabaseUrl, anonKey, {
  accessToken: () => oauth.getAccessToken(),
})

oauth.onChange((event) => {
  switch (event.type) {
    case 'authorized':
    case 'refreshed':
      supabase.realtime.setAuth(event.session.accessToken) // Realtime does not use the accessToken callback
      break
    case 'signed_out':
      // event.reason: 'sign_out' | 'invalid_grant' (revoked / expired refresh token) | 'expired'
      break
  }
})
```

- `getAccessToken()` returns a token valid for at least `refreshLeewaySeconds` more seconds, refreshing first if needed, or `null` when signed out. Concurrent callers share one refresh request.
- If a refresh fails while the current token is still valid, the current token is returned and the background timer keeps retrying. Once the token is actually expired and refresh still fails, it rejects.
- The background timer refreshes `refreshLeewaySeconds` (default 60) before expiry, with exponential backoff (1 s → 60 s) on network and 5xx errors. On `invalid_grant` it clears the session and emits `signed_out`.

## API

### `createOAuthClient(options): OAuthClient`

| option | default | notes |
| --- | --- | --- |
| `supabaseUrl` | required | `https://<ref>.supabase.co` |
| `clientId` | required | OAuth client id |
| `redirectUri` | required | must exactly match a registered URI |
| `scope` | `'email'` | space-separated. Do not add `openid` unless the project uses asymmetric (RS256/ES256) signing keys |
| `clientSecret` | | enables confidential mode. **Server-side only** |
| `tokenEndpointAuthMethod` | `'none'`, or `'client_secret_basic'` when a secret is set | also `'client_secret_post'` |
| `storage` | in-memory | anything with `getItem/setItem/removeItem` (sync or async), e.g. `localStorage`, `browserStorage()` |
| `storageKey` | `sb-oauth-<clientId>` | prefix for the two keys written (`.session`, `.pending`) |
| `fetch` | `globalThis.fetch` | inject for tests or custom runtimes |
| `refreshLeewaySeconds` | `60` | refresh this long before expiry |
| `autoRefresh` | `true` | `false` disables the timer; `getAccessToken()` still refreshes lazily |
| `now` | `Date.now` | clock, for tests |

### `OAuthClient`

| method | what it does |
| --- | --- |
| `begin(opts?)` | New verifier + state (every call), stores them as *the* pending authorization, returns `{ authorizeUrl, state, codeChallenge }`. `opts`: `scope`, `nonce`, `extraParams` |
| `exchange({ code, state })` | Rejects with `no_pending_authorization` or `state_mismatch` (pending is kept on mismatch). Otherwise exchanges, stores the session, arms the timer, emits `authorized`. A server error burns the pending authorization (the code was single-use anyway); a network error keeps it so you can retry |
| `completeFromUrl(url?)` | Parses `code`/`state` or `error`/`error_description` from `url` (default `location.href`) and delegates to `exchange()`. `null` if neither is present. Rejects with the server's `error`, clearing the matching pending authorization |
| `getAccessToken()` | Valid token or `null`. Coalesced refresh. Suitable for supabase-js `accessToken` |
| `getSession()` | `{ accessToken, refreshToken, expiresAt, tokenType, scope, idToken, claims } \| null` from memory |
| `initialize()` | Await storage load. Only needed with async storage adapters |
| `refresh()` | Force a refresh (coalesced). Stores a rotated refresh token if the server sends one |
| `signOut()` | Clears local tokens, stops the timer, emits `signed_out` with `reason: 'sign_out'`. There is no server call for public clients; the *user* revokes server-side with `supabase.auth.oauth.revokeGrant({ clientId })` in the identity provider's app (`listGrants()` shows what is granted) |
| `cancel()` | Drops the pending verifier/state without touching the session |
| `getPendingState()` | `state` of the pending authorization or `null` |
| `onChange(listener)` | Events below. Returns an unsubscribe function |
| `tokenUrl`, `authorizeEndpoint` | The endpoints in use |

### Events

```ts
type OAuthEvent =
  | { type: 'authorized'; session }
  | { type: 'refreshed'; session }
  | { type: 'signed_out'; reason: 'sign_out' | 'invalid_grant' | 'expired'; error? }
  | { type: 'error'; error } // a background refresh failed and will be retried; foreground calls reject instead
```

### `OAuthError`

Every rejection from this package is an `OAuthError` with:

- `error`: the OAuth error code from the server (`invalid_grant`, `invalid_client`, `invalid_request`, `access_denied`, `server_error`, ...) or a local code: `no_pending_authorization`, `state_mismatch`, `no_session`, `network_error`, `invalid_response`, `signed_out`, `configuration_error`.
- `errorDescription` (also as `error_description`), `status` (HTTP status if any), `response` (parsed body), `cause` (the underlying `fetch` error for `network_error`).
- Helpers: `isInvalidGrant`, `isNetworkError`, and the `isOAuthError(value)` guard.

### Storage adapters

- default: `memoryStorage()`
- `browserStorage(store = localStorage)`: probes the store on creation and falls back to memory when it is unavailable or throws (private mode, storage disabled). Every call is guarded.
- Anything implementing `TokenStorage` (`getItem`, `setItem`, `removeItem`; values may be promises). With async adapters, `getSession()` is `null` until `initialize()` resolves; the async methods wait automatically.

Also exported for reuse: `decodeJwtPayload`, `createCodeVerifier`, `createCodeChallenge`, `createState`, `base64UrlEncode`, `base64UrlDecode`.

## Confidential clients (server-side)

Register a confidential client and pass the secret. Never ship a secret to a browser or device.

```ts
const oauth = createOAuthClient({
  supabaseUrl, clientId, redirectUri,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  tokenEndpointAuthMethod: 'client_secret_basic', // default when a secret is set; or 'client_secret_post'
  storage: myKvAdapter,
})
```

The refresh timer calls `unref()` on its Node timer so it never keeps a process alive on its own.

## Scoping access with RLS

Access tokens from the OAuth server are ordinary Supabase JWTs (`sub`, `role: authenticated`, ...) with one extra claim, `client_id`. Policies in the identity provider's database can use it to give a given client narrower rights than first-party sessions:

```sql
create policy "partner app may read its user's rows"
on public.things for select
to authenticated
using (
  user_id = auth.uid()
  and (auth.jwt() ->> 'client_id') = '<oauth-client-id>'
);

-- or: forbid writes from any OAuth client
create policy "only first-party sessions may insert"
on public.things for insert
to authenticated
with check (auth.jwt() ->> 'client_id' is null);
```

## Security notes

- Each `begin()` creates a fresh verifier and state. The package holds one pending authorization at a time and rejects codes whose `state` does not match it.
- The authorization code is valid for 10 minutes and single-use. The verifier never leaves the client; Supabase sees the S256 challenge at `/oauth/authorize` and the verifier at the token endpoint.
- Tokens are stored as JSON under `storageKey` in whatever storage you provide. `localStorage` is readable by any script on the origin; that is the same trade-off supabase-js makes.
- The JWT payload is decoded, never verified, purely to read `exp` and expose `claims`. Do not make authorization decisions on the client from `claims`.
- Do not request the `openid` scope unless you need an ID token *and* the project uses asymmetric signing keys; with the default HS256 secret Supabase rejects it.

## Verifying tokens on a server

Verify the access token like any Supabase JWT: fetch `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json` (asymmetric keys) or use the project's JWT secret (HS256), check `aud`, `exp`, and, if you care which app is calling, `client_id`. Discovery metadata is at `/auth/v1/.well-known/oauth-authorization-server`.

## Verified against a live project

Checked on 2026-09-11 against a Supabase project with the OAuth server enabled (beta), using `scripts/live-test.mjs`:

- **CORS**: `POST /auth/v1/oauth/token` answers browser preflights with `access-control-allow-origin: *` and needs no `apikey` header, so public clients can run in browsers and on devices.
- **Refresh tokens are issued with the default `email` scope.** `offline_access` is listed in discovery but not required.
- **The access token** is a normal HS256 Supabase JWT (`aud: authenticated`, `role: authenticated`, `session_id`, full `user_metadata`) plus `client_id` and `scope` claims, and `amr: [{ method: 'oauth_provider/authorization_code' }]`. PostgREST, GoTrue's `/user` and `/oauth/userinfo` all accept it. Expect it to be over 1 KB when `user_metadata` is populated.
- **The token response carries no `scope` field**, unlike the docs example; `session.scope` is `null` and the scope is readable from `session.claims.scope`.
- **Refresh rotates** the refresh token. Reusing the previous one shortly after rotation still succeeds (Supabase's reuse grace window); the client always stores the newest token so this never matters in practice.
- **Error shapes are mixed.** Code reuse and PKCE mistakes come back RFC-style (`invalid_grant` "Invalid authorization code", `invalid_request`). A revoked or unknown refresh token comes back GoTrue-style: `{ code: 400, error_code: 'refresh_token_not_found', msg: ... }`. An unknown client id is `error_code: 'invalid_credentials'`. `OAuthError.error` carries whichever code was sent, and `isInvalidGrant` covers both families, so a revoked grant reliably ends in `signed_out` with `reason: 'invalid_grant'`.
- **Revocation** via `supabase.auth.oauth.revokeGrant({ clientId })` in the identity provider's app takes effect immediately; the next refresh fails as above.
- **supabase-js naming differs from the docs**: the grant methods are `supabase.auth.oauth.listGrants()` and `revokeGrant({ clientId })` (auth-js 2.116), not `getUserGrants()` / `revokeGrant(clientId)`.
- **A used or unknown `authorization_id`** makes `getAuthorizationDetails` fail with `oauth_authorization_not_found` (404). Consent pages should handle that, e.g. after a reload.

Still unverified: how long a pending authorization lives between `/oauth/authorize` and `approveAuthorization`, whether `expires_in` follows the project's JWT expiry setting (it was 3600 s on a default project), and whether Realtime picks up tokens from the `accessToken` callback without `setAuth`.

## Development

```sh
npm ci
npm run typecheck
npm test
npm run build
```

`scripts/live-test.mjs` runs the real flow against a project (needs `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `OAUTH_CLIENT_ID`; a public OAuth client with redirect URI `http://localhost:5173/oauth/callback`, Site URL `http://localhost:3000` and authorization path `/oauth/consent`). It serves a throwaway consent page locally, prints an authorize URL to open, then exercises exchange, code reuse, refresh, refresh-token reuse and revocation, and prints its findings.

Releases are cut from GitHub only. `package.json` stays at `0.0.0` in git; the version comes from the release tag (`v0.2.0` → `0.2.0`). A release marked as a pre-release publishes to the `next` dist-tag, otherwise to `latest`. Publishing uses npm trusted publishing (OIDC), so no token lives in the repo.

## License

MIT
