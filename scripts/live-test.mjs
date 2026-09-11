// Live integration test against a real Supabase project.
//
// Runs two tiny local servers that stand in for the identity provider's app:
//   http://localhost:3000/oauth/consent   the consent page (supabase-js from a CDN)
//   http://localhost:5173/oauth/callback  the registered redirect URI; receives code+state
// and drives the OAuth client from dist/ through the whole flow, recording what the
// server actually returns. Build first: `npm run build`.
//
// Env: SUPABASE_URL, SUPABASE_ANON_KEY, OAUTH_CLIENT_ID, optional OAUTH_SCOPE (default 'email'),
//      optional LOG_FILE (progress is also appended there), optional REDIRECT_URI, SITE_URL.

import http from 'node:http'
import fs from 'node:fs'
import { createOAuthClient, OAuthError, memoryStorage, decodeJwtPayload } from '../dist/index.js'

const env = (k, d) => process.env[k] ?? d ?? (() => { throw new Error(`missing env ${k}`) })()
const SUPABASE_URL = env('SUPABASE_URL').replace(/\/+$/, '')
const ANON_KEY = env('SUPABASE_ANON_KEY')
const CLIENT_ID = env('OAUTH_CLIENT_ID')
const SCOPE = process.env.OAUTH_SCOPE ?? 'email'
const REDIRECT_URI = process.env.REDIRECT_URI ?? 'http://localhost:5173/oauth/callback'
const SITE_URL = process.env.SITE_URL ?? 'http://localhost:3000'
const LOG_FILE = process.env.LOG_FILE

const findings = {}
function log(...args) {
  const line = args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a, null, 2))).join(' ')
  console.log(line)
  if (LOG_FILE) fs.appendFileSync(LOG_FILE, line + '\n')
}
const redact = (t) => (typeof t === 'string' && t.length > 16 ? `${t.slice(0, 8)}…${t.slice(-6)} (${t.length} chars)` : t)
const now = () => Math.floor(Date.now() / 1000)

// ------------------------------------------------------------------ consent page
const consentHtml = `<!doctype html><meta charset="utf-8"><title>Consent (live test)</title>
<style>body{font:15px system-ui;max-width:640px;margin:40px auto;padding:0 16px}pre{background:#f4f4f4;padding:12px;overflow:auto}button{font:inherit;padding:8px 14px;margin-right:8px}input{font:inherit;padding:6px;width:100%;margin:4px 0 10px}</style>
<h1>Consent page (live test)</h1>
<div id="status">Loading…</div>
<form id="login" hidden>
  <p>Sign in to this Supabase project. Credentials go straight to Supabase from this page.</p>
  <label>Email <input id="email" type="email" autocomplete="username" required></label>
  <label>Password <input id="password" type="password" autocomplete="current-password"></label>
  <button type="submit">Sign in with password</button>
  <button type="button" id="magic">Send magic link instead</button>
  <p>Or use a provider (redirects back here):</p>
  <button type="button" data-provider="google">Sign in with Google</button>
  <button type="button" data-provider="apple">Sign in with Apple</button>
</form>
<div id="consent" hidden>
  <p>Signed in as <b id="who"></b>. Authorization details from <code>getAuthorizationDetails</code>:</p>
  <pre id="details"></pre>
  <button id="approve">Approve</button><button id="deny">Deny</button>
  <button id="revoke">Revoke grant for this client</button>
  <button id="signout">Sign out</button>
</div>
<pre id="out"></pre>
<script type="module">
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm'
const supabase = createClient(${JSON.stringify(SUPABASE_URL)}, ${JSON.stringify(ANON_KEY)})
const $ = (id) => document.getElementById(id)
const out = (label, v) => { $('out').textContent += label + ' ' + JSON.stringify(v, null, 2) + '\\n'; fetch('/log', { method: 'POST', body: JSON.stringify({ label, v }) }) }

// Let supabase-js finish reading any tokens from the URL hash (provider redirect) before touching the URL.
await supabase.auth.getSession()
let id = new URL(location.href).searchParams.get('authorization_id')
if (id) sessionStorage.setItem('authorization_id', id)
else { id = sessionStorage.getItem('authorization_id'); if (id) history.replaceState(null, '', '/oauth/consent?authorization_id=' + id) }

async function render() {
  const { data: { session } } = await supabase.auth.getSession()
  $('login').hidden = !!session
  $('consent').hidden = !session
  if (!session) { $('status').textContent = id ? 'Not signed in.' : 'No authorization_id in URL.'; return }
  $('status').textContent = ''
  $('who').textContent = session.user.email ?? session.user.id
  if (!id) { $('details').textContent = '(no authorization_id in URL)'; return }
  const res = await supabase.auth.oauth.getAuthorizationDetails(id)
  $('details').textContent = JSON.stringify(res, null, 2)
  out('getAuthorizationDetails', res)
}
supabase.auth.onAuthStateChange(() => render())
render()

$('login').onsubmit = async (e) => {
  e.preventDefault()
  const res = await supabase.auth.signInWithPassword({ email: $('email').value, password: $('password').value })
  if (res.error) out('signInWithPassword error', res.error)
}
$('magic').onclick = async () => {
  const res = await supabase.auth.signInWithOtp({ email: $('email').value, options: { emailRedirectTo: location.href } })
  out('signInWithOtp', res.error ?? 'sent; open the link in this browser')
}
for (const b of document.querySelectorAll('[data-provider]')) {
  b.onclick = async () => {
    const res = await supabase.auth.signInWithOAuth({ provider: b.dataset.provider, options: { redirectTo: location.origin + '/oauth/consent' } })
    if (res.error) out('signInWithOAuth error', res.error)
  }
}
$('approve').onclick = async () => {
  const res = await supabase.auth.oauth.approveAuthorization(id)
  out('approveAuthorization', res)
  const url = res.data?.redirect_url ?? res.data?.redirectUrl
  if (url) setTimeout(() => { location.href = url }, 800)
}
$('deny').onclick = async () => {
  const res = await supabase.auth.oauth.denyAuthorization(id)
  out('denyAuthorization', res)
  const url = res.data?.redirect_url ?? res.data?.redirectUrl
  if (url) setTimeout(() => { location.href = url }, 800)
}
$('revoke').onclick = async () => {
  // auth-js 2.116: oauth.listGrants() and oauth.revokeGrant({ clientId }); the docs' getUserGrants()/revokeGrant(id) do not exist.
  const grants = await supabase.auth.oauth.listGrants()
  out('listGrants', grants)
  const res = await supabase.auth.oauth.revokeGrant({ clientId: ${JSON.stringify(CLIENT_ID)} })
  out('revokeGrant', res)
  const after = await supabase.auth.oauth.listGrants()
  out('listGrants after revoke', after)
  fetch('/revoked', { method: 'POST' })
}
window.addEventListener('unhandledrejection', (e) => out('UNHANDLED', { message: e.reason?.message ?? String(e.reason), stack: e.reason?.stack }))
window.addEventListener('error', (e) => out('ERROR', { message: e.message }))
$('signout').onclick = () => supabase.auth.signOut()
</script>`

let resolveCode, resolveRevoked
const codeArrived = new Promise((r) => (resolveCode = r))
const revoked = new Promise((r) => (resolveRevoked = r))

const readBody = (req) => new Promise((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b)) })

const siteServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, SITE_URL)
  if (url.pathname === '/oauth/consent' || url.pathname === '/') return res.writeHead(200, { 'content-type': 'text/html' }).end(consentHtml)
  if (url.pathname === '/log' && req.method === 'POST') {
    try { const { label, v } = JSON.parse(await readBody(req)); log(`[browser] ${label}:`, v); findings[`browser:${label}`] = v } catch {}
    return res.writeHead(204).end()
  }
  if (url.pathname === '/revoked' && req.method === 'POST') { resolveRevoked(); return res.writeHead(204).end() }
  res.writeHead(404).end('not found')
})
const redirectServer = http.createServer((req, res) => {
  const url = new URL(req.url, REDIRECT_URI)
  if (url.pathname === new URL(REDIRECT_URI).pathname) {
    const params = Object.fromEntries(url.searchParams)
    log('[redirect] received:', { ...params, code: redact(params.code) })
    resolveCode(params)
    return res.writeHead(200, { 'content-type': 'text/html' }).end(
      `<!doctype html><meta charset="utf-8"><body style="font:15px system-ui;margin:40px"><h1>Code received</h1><p>Back to the terminal. Keep this browser open for the revoke step.</p><p><a href="${SITE_URL}/oauth/consent">Back to consent page</a></p><pre>${JSON.stringify(params, null, 2)}</pre>`,
    )
  }
  res.writeHead(404).end('not found')
})
await new Promise((r) => siteServer.listen(new URL(SITE_URL).port, r))
await new Promise((r) => redirectServer.listen(new URL(REDIRECT_URI).port, r))

// ------------------------------------------------------------------ the client under test
const storage = memoryStorage()
const RESUME = process.env.RESUME_REFRESH_TOKEN
if (RESUME) {
  // Turn a known-good refresh token into a stored session so the client picks it up on construction.
  const r = await fetch(`${SUPABASE_URL}/auth/v1/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: RESUME, client_id: CLIENT_ID }) })
  const body = await r.json()
  if (!r.ok) { log('resume refresh failed', { status: r.status, body }); process.exit(1) }
  const claims = decodeJwtPayload(body.access_token)
  storage.setItem(`sb-oauth-${CLIENT_ID}.session`, JSON.stringify({ accessToken: body.access_token, refreshToken: body.refresh_token, expiresAt: claims.exp, tokenType: body.token_type, scope: body.scope ?? null, idToken: null, claims }))
  log('resumed from refresh token; rotated to', redact(body.refresh_token))
}
const oauth = createOAuthClient({ supabaseUrl: SUPABASE_URL, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scope: SCOPE, autoRefresh: false, storage })
oauth.onChange((e) => log('[event]', e.type, e.type === 'signed_out' ? e.reason : ''))

if (!RESUME) {
const started = now()
const { authorizeUrl, state } = await oauth.begin()
log('\n=== STEP 1: open this URL in a browser and approve ===\n' + authorizeUrl + '\n')

const params = await codeArrived
findings.redirect_params = { ...params, code: redact(params.code) }
if (params.error) { log('authorization ended with error', params); process.exit(1) }
findings.seconds_from_authorize_to_code = now() - started
if (params.state !== state) log('!! state mismatch', { expected: state, got: params.state })

// Raw fetch helper for probing error shapes
async function rawToken(body) {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) })
  return { status: res.status, body: await res.json().catch(() => null) }
}

log('=== STEP 2: exchange')
const session = await oauth.exchange({ code: params.code, state: params.state })
findings.exchange = {
  tokenType: session.tokenType, scope: session.scope, hasRefreshToken: !!session.refreshToken, hasIdToken: !!session.idToken,
  expiresInSeconds: session.expiresAt - now(), claims: { ...session.claims, email: session.claims.email ? '<redacted>' : undefined },
  accessToken: redact(session.accessToken), refreshToken: redact(session.refreshToken),
}
log('exchange ok:', findings.exchange)

log('=== STEP 3: reuse the same code (expect failure)')
findings.code_reuse = await rawToken({ grant_type: 'authorization_code', code: params.code, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' })
log(findings.code_reuse)

log('=== STEP 4: token accepted by PostgREST and userinfo?')
// A table that does not exist: a valid JWT yields 404 "relation does not exist", an invalid one 401 PGRST301.
const rest = await fetch(`${SUPABASE_URL}/rest/v1/zz_probe_table_that_does_not_exist?select=*`, { headers: { apikey: ANON_KEY, authorization: `Bearer ${session.accessToken}` } })
findings.postgrest = { status: rest.status, jwtAccepted: rest.status !== 401, body: await rest.json().catch(() => null) }
const ui = await fetch(`${SUPABASE_URL}/auth/v1/oauth/userinfo`, { headers: { authorization: `Bearer ${session.accessToken}` } })
findings.userinfo = { status: ui.status, body: await ui.json().catch(() => null) }
if (findings.userinfo.body?.email) findings.userinfo.body.email = '<redacted>'
log({ postgrest: findings.postgrest, userinfo: findings.userinfo })

if (session.refreshToken) {
  log('=== STEP 5: refresh')
  const oldRefresh = session.refreshToken
  const refreshed = await oauth.refresh()
  findings.refresh = { rotated: refreshed.refreshToken !== oldRefresh, expiresInSeconds: refreshed.expiresAt - now(), scope: refreshed.scope, newAccessTokenDiffers: refreshed.accessToken !== session.accessToken }
  log(findings.refresh)

  log('=== STEP 6: reuse the OLD refresh token (expect failure)')
  findings.refresh_reuse = await rawToken({ grant_type: 'refresh_token', refresh_token: oldRefresh, client_id: CLIENT_ID })
  log(findings.refresh_reuse)
  log('   ...and does the CURRENT refresh token still work after that?')
  const after = await oauth.refresh().then(() => 'yes', (e) => ({ no: e.error, description: e.errorDescription, status: e.status }))
  findings.current_refresh_after_reuse = after
  log(after)
} else {
  log(`!! no refresh token issued with scope "${SCOPE}". Re-run with OAUTH_SCOPE="${SCOPE} offline_access".`)
}
} // !RESUME

log(`\n=== STEP 7: in the browser, open ${SITE_URL}/oauth/consent and click "Revoke grant for this client". Waiting (Ctrl+C to skip)…`)
await Promise.race([revoked, new Promise((r) => setTimeout(r, 8 * 60_000))])
if (oauth.getSession()?.refreshToken) {
  const r = await oauth.refresh().then(() => 'refresh still works after revoke?!', (e) => ({ error: e.error, description: e.errorDescription, status: e.status, isInvalidGrant: e instanceof OAuthError && e.isInvalidGrant }))
  findings.refresh_after_revoke = r
  log('refresh after revoke:', r, 'session now:', oauth.getSession() ? 'present' : 'cleared')
}

log('\n=== FINDINGS ===')
log(findings)
if (LOG_FILE) fs.writeFileSync(LOG_FILE.replace(/\.log$/, '') + '.findings.json', JSON.stringify(findings, null, 2))
process.exit(0)
