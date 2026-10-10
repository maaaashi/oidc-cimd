// Minimal OpenID Provider supporting OAuth Client ID Metadata Documents (CIMD).
// For learning purposes only. No dependencies (Node.js 22+).
const http = require('node:http');
const crypto = require('node:crypto');
const dpop = require('../lib/dpop.js');

const PORT = 3000;
const ISSUER = process.env.ISSUER || 'http://localhost:3000';
// The spec requires https client_id URLs. Allow http://localhost only for local demos.
const ALLOW_HTTP_LOCALHOST = process.env.ALLOW_HTTP_LOCALHOST_CLIENT_ID === 'true';
const MAX_DOC_BYTES = 5 * 1024;
const DEFAULT_CACHE_SEC = 300;
const MAX_CACHE_SEC = 24 * 60 * 60;
// RFC 8707: resource servers (APIs) this OP issues access tokens for.
const KNOWN_RESOURCES = (process.env.RESOURCES || '').split(',').filter(Boolean);
// "mcp:tools" is what the demo MCP servers (rs/server.js) require.
const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'mcp:tools'];

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const kid = crypto.randomBytes(8).toString('hex');
const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };

const USERS = {
  alice: { password: 'password', sub: 'user-alice', name: 'Alice Example', email: 'alice@example.com' },
};

const pending = new Map(); // authorization request id -> request
const codes = new Map(); // authorization code -> grant
const refreshTokens = new Map(); // refresh token -> grant
const metadataCache = new Map(); // client_id -> { metadata, fetchedAt, expiresAt }

const b64url = (v) => Buffer.from(v).toString('base64url');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const log = (...a) => console.log(`[op] ${new Date().toISOString()}`, ...a);
// Collapsible explanation for OIDC/OAuth beginners. `body` is trusted HTML.
const hint = (title, body, open = false) =>
  `<details class="hint"${open ? ' open' : ''}><summary>💡 ${title}</summary>${body}</details>`;

const SCOPE_DESCRIPTIONS = {
  openid: 'OIDC でログインする (ID トークンを発行する)',
  profile: '名前などのプロフィール',
  email: 'メールアドレス',
  'mcp:tools': 'MCP サーバーのツールを使う',
};

function signJwt(payload, typ = 'JWT') {
  const header = { alg: 'RS256', typ, kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(input), privateKey);
  return `${input}.${b64url(sig)}`;
}

class ClientMetadataError extends Error {}

// --- CIMD: client_id URL validation -----------------------------------------
function validateClientIdUrl(clientId) {
  let u;
  try {
    u = new URL(clientId);
  } catch {
    throw new ClientMetadataError('client_id is not a valid URL');
  }
  const isLocalhost = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(ALLOW_HTTP_LOCALHOST && u.protocol === 'http:' && isLocalhost)) {
    throw new ClientMetadataError('client_id URL MUST use the https scheme');
  }
  if (u.pathname === '/' || u.pathname === '') throw new ClientMetadataError('client_id URL MUST contain a path component');
  if (clientId.includes('#')) throw new ClientMetadataError('client_id URL MUST NOT contain a fragment');
  if (u.username || u.password) throw new ClientMetadataError('client_id URL MUST NOT contain a username or password');
  // new URL() normalizes dot segments, so check the raw string.
  if (/\/\.\.?(\/|\?|$)/.test(clientId)) throw new ClientMetadataError('client_id URL MUST NOT contain dot path segments');
}

function cacheSeconds(cacheControl) {
  if (!cacheControl) return DEFAULT_CACHE_SEC;
  if (/no-store|no-cache/i.test(cacheControl)) return 0;
  const m = /max-age=(\d+)/i.exec(cacheControl);
  return m ? Math.min(Number(m[1]), MAX_CACHE_SEC) : DEFAULT_CACHE_SEC;
}

// --- CIMD: fetch + validate the client metadata document --------------------
async function getClientMetadata(clientId) {
  validateClientIdUrl(clientId);

  const cached = metadataCache.get(clientId);
  if (cached && cached.expiresAt > Date.now()) {
    log(`client metadata cache hit: ${clientId}`);
    return cached.metadata;
  }

  log(`fetching client metadata document: GET ${clientId}`);
  let res;
  try {
    res = await fetch(clientId, {
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: { accept: 'application/json' },
    });
  } catch (e) {
    throw new ClientMetadataError(`failed to fetch client metadata document: ${e.cause?.message || e.message}`);
  }
  if (res.status !== 200) throw new ClientMetadataError(`client metadata document returned HTTP ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_DOC_BYTES) throw new ClientMetadataError(`client metadata document exceeds ${MAX_DOC_BYTES} bytes`);

  let metadata;
  try {
    metadata = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new ClientMetadataError('client metadata document is not valid JSON');
  }
  if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
    throw new ClientMetadataError('client metadata document must be a JSON object');
  }

  // The document's client_id MUST exactly match the URL it was fetched from.
  if (metadata.client_id !== clientId) {
    throw new ClientMetadataError(
      `client_id in document ("${metadata.client_id}") does not match the document URL ("${clientId}")`,
    );
  }
  // Shared secrets are meaningless in a publicly hosted document.
  if ('client_secret' in metadata || 'client_secret_expires_at' in metadata) {
    throw new ClientMetadataError('client metadata document MUST NOT contain client_secret');
  }
  if (/^client_secret_/.test(metadata.token_endpoint_auth_method ?? '')) {
    throw new ClientMetadataError('token_endpoint_auth_method MUST NOT be a client_secret_* method');
  }
  if (metadata.token_endpoint_auth_method !== 'none') {
    throw new ClientMetadataError('this demo OP only supports token_endpoint_auth_method "none" (public client + PKCE)');
  }
  if (
    !Array.isArray(metadata.redirect_uris) ||
    metadata.redirect_uris.length === 0 ||
    !metadata.redirect_uris.every((r) => typeof r === 'string')
  ) {
    throw new ClientMetadataError('redirect_uris must be a non-empty array of strings');
  }

  const ttl = cacheSeconds(res.headers.get('cache-control'));
  if (ttl > 0) metadataCache.set(clientId, { metadata, fetchedAt: Date.now(), expiresAt: Date.now() + ttl * 1000 });
  log(`client metadata OK: "${metadata.client_name}" (cache ${ttl}s)`);
  return metadata;
}

// --- HTTP helpers -----------------------------------------------------------
function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}
const sendJson = (res, status, obj, headers = {}) =>
  send(res, status, JSON.stringify(obj, null, 2), { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
const redirect = (res, location) => send(res, 302, '', { location });

async function readForm(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

// --- RFC 8707: resource parameter validation --------------------------------
function validateResources(resources) {
  for (const r of resources) {
    try {
      new URL(r);
    } catch {
      return `resource "${r}" is not an absolute URI`;
    }
    if (r.includes('#')) return `resource "${r}" MUST NOT contain a fragment`;
    if (!KNOWN_RESOURCES.includes(r)) return `resource "${r}" is not a resource server known to this OP`;
  }
  return null;
}

function page(title, body) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>${esc(title)}</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#222;background:#f5f3ef}
 .card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:24px;margin-bottom:16px}
 h1{font-size:20px} .op{color:#a33;font-weight:bold} code{background:#eee;padding:1px 4px;border-radius:4px}
 pre{background:#1e1e1e;color:#ddd;padding:12px;border-radius:6px;overflow:auto;font-size:12px}
 .client{display:flex;gap:16px;align-items:center} .client img{width:56px;height:56px}
 .err{background:#fee;border-color:#e99} button{padding:8px 20px;font-size:15px;margin-right:8px;cursor:pointer}
 input{padding:6px;margin:4px 0 10px;width:200px} table{border-collapse:collapse} td{padding:4px 8px;border-bottom:1px solid #eee;vertical-align:top}
 .hint{background:#fffbea;border:1px solid #f0d98a;border-radius:8px;padding:8px 14px;margin:12px 0;font-size:14px;line-height:1.7}
 .hint summary{cursor:pointer;font-weight:bold;color:#8a6d00} .hint dt{font-weight:bold;margin-top:6px} .hint dd{margin:0 0 0 1.5em}
</style></head><body><p class="op">Demo OP (${esc(ISSUER)})</p>${body}</body></html>`;
}

const errorPage = (res, message) =>
  send(
    res,
    400,
    page('Error', `<div class="card err"><h1>認可リクエストを処理できません</h1><p>${esc(message)}</p>
<p>redirect_uri を検証できていないため、クライアントへはリダイレクトしません。</p>
${hint(
  'なぜクライアントに戻さないの?',
  `<p>通常、認可リクエストのエラーは <code>redirect_uri</code> に <code>error=...</code> を付けてクライアントに返します。
しかし client_id や redirect_uri が正しいと確認できていない段階では、その redirect_uri が攻撃者のサイトかもしれません。
そのため OP は自分の画面でエラーを表示して止まります (open redirector 対策)。</p>`,
  true,
)}</div>`),
    { 'content-type': 'text/html; charset=utf-8' },
  );

function consentPage(id, req, error) {
  const c = req.client;
  const host = new URL(req.clientId).host;
  return page(
    'Authorize',
    `<div class="card">
  ${error ? `<p class="err card">${esc(error)}</p>` : ''}
  <div class="client">
    ${c.logo_uri ? `<img src="${esc(c.logo_uri)}" alt="">` : ''}
    <div><h1>${esc(c.client_name || '(no client_name)')} がアクセスを求めています</h1>
    <div>このアプリのドメイン: <b>${esc(host)}</b>${c.client_uri ? ` ・ <a href="${esc(c.client_uri)}">${esc(c.client_uri)}</a>` : ''}</div></div>
  </div>
  <p>要求スコープ:</p><ul>${req.scope
    .split(' ')
    .map((s) => `<li><code>${esc(s)}</code> ${esc(SCOPE_DESCRIPTIONS[s] ?? '')}</li>`)
    .join('')}</ul>
  <p>アクセス先 API (resource): ${
    req.resources.length ? req.resources.map((r) => `<code>${esc(r)}</code>`).join(' ') : '(指定なし)'
  }</p>
  <p>戻り先: <code>${esc(req.redirectUri)}</code></p>
  <form method="post" action="/authorize/decision">
    <input type="hidden" name="id" value="${esc(id)}">
    <div>ユーザー名<br><input name="username" value="alice"></div>
    <div>パスワード<br><input name="password" type="password" value="password"></div>
    <button name="action" value="approve">許可</button><button name="action" value="deny">拒否</button>
  </form>
  ${hint(
    'この画面は何? (同意画面)',
    `<p>ここは OP (ログインを担当するサーバー) の画面です。パスワードを入力するのはアプリではなく OP なので、
アプリ側にパスワードが渡ることはありません。</p>
<p>ログインと同時に「このアプリに、これらの情報・権限を渡してよいか」の <b>同意</b> を求めています。</p>
<dl>
<dt>要求スコープ</dt><dd>アプリが欲しがっている情報や権限です。</dd>
<dt>アクセス先 API (resource)</dt><dd>発行するアクセストークンを使える API です。ここに無い API 用のトークンは後から要求しても発行されません。</dd>
<dt>戻り先</dt><dd>許可後にブラウザが戻る URL です。メタデータの <code>redirect_uris</code> と完全一致したものだけが使えます。</dd>
</dl>
<p><b>注意:</b> アプリ名やロゴはアプリ自身が書いた自己申告なので、誰でも好きに名乗れます。
信頼できるのは「ドメイン (<code>${esc(host)}</code>)」の方です。CIMD 対応の OP では、ドメインを目立たせて表示することが推奨されています。</p>`,
  )}
</div>
<div class="card"><h1>OP が取得した Client ID Metadata Document</h1>
<p>client_id: <code>${esc(req.clientId)}</code></p><pre>${esc(JSON.stringify(c, null, 2))}</pre>
<p>事前のクライアント登録なしに、この URL から取得した情報だけで同意画面を表示しています。</p>
${hint(
  'OP がこのドキュメントについて確認したこと',
  `<ul>
<li>client_id の URL の形式 (https であること、パスがあること など。このデモでは http://localhost も許可)</li>
<li>リダイレクトせずに取得でき、サイズが 5KB 以下の JSON であること</li>
<li>中の <code>client_id</code> が取得元 URL と完全に一致すること (なりすまし防止)</li>
<li><code>client_secret</code> を含まないこと (公開ドキュメントに秘密は置けない)</li>
<li>リクエストの <code>redirect_uri</code> が <code>redirect_uris</code> に含まれること</li>
</ul>
<p>取得したドキュメントは <code>Cache-Control</code> に従って一定時間キャッシュされ、毎回取りに行くことはしません。</p>`,
)}</div>`,
  );
}

// --- Endpoints --------------------------------------------------------------
const discovery = () => ({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: SUPPORTED_SCOPES,
  token_endpoint_auth_methods_supported: ['none'],
  code_challenge_methods_supported: ['S256'],
  // RFC 9449: this OP issues DPoP-bound tokens when the token request carries a DPoP proof.
  dpop_signing_alg_values_supported: dpop.SUPPORTED_ALGS,
  authorization_response_iss_parameter_supported: true,
  client_id_metadata_document_supported: true,
});

async function handleAuthorize(res, params) {
  const clientId = params.get('client_id');
  if (!clientId) return errorPage(res, 'client_id is missing');

  let client;
  try {
    client = await getClientMetadata(clientId);
  } catch (e) {
    if (!(e instanceof ClientMetadataError)) throw e;
    log(`client metadata rejected: ${e.message}`);
    return errorPage(res, e.message);
  }

  const redirectUri = params.get('redirect_uri');
  if (!client.redirect_uris.includes(redirectUri)) {
    log(`redirect_uri rejected: ${redirectUri}`);
    return errorPage(res, `redirect_uri "${redirectUri}" is not listed in the client metadata document's redirect_uris`);
  }

  // From here on, errors are returned to the (verified) redirect_uri.
  const state = params.get('state');
  const redirectError = (error, description) => {
    const u = new URL(redirectUri);
    u.searchParams.set('error', error);
    u.searchParams.set('error_description', description);
    if (state) u.searchParams.set('state', state);
    u.searchParams.set('iss', ISSUER);
    return redirect(res, u.href);
  };

  if (params.get('response_type') !== 'code') return redirectError('unsupported_response_type', 'only "code" is supported');
  // Plain OAuth (e.g. MCP clients asking only for "mcp:tools") is allowed; an ID token is issued only with "openid".
  const scope = params.get('scope') || '';
  const unknownScope = scope.split(' ').find((s) => s && !SUPPORTED_SCOPES.includes(s));
  if (!scope.trim()) return redirectError('invalid_scope', 'scope is required');
  if (unknownScope) return redirectError('invalid_scope', `unsupported scope "${unknownScope}"`);
  if (!params.get('code_challenge') || params.get('code_challenge_method') !== 'S256') {
    return redirectError('invalid_request', 'PKCE with S256 is required');
  }
  // RFC 8707: the resource parameter may be repeated to request access to multiple APIs.
  const resources = params.getAll('resource');
  const resourceError = validateResources(resources);
  if (resourceError) {
    log(`resource rejected: ${resourceError}`);
    return redirectError('invalid_target', resourceError);
  }

  const id = rand(16);
  const req = {
    clientId,
    client,
    redirectUri,
    state,
    scope,
    resources,
    nonce: params.get('nonce'),
    codeChallenge: params.get('code_challenge'),
    expiresAt: Date.now() + 10 * 60 * 1000,
  };
  pending.set(id, req);
  send(res, 200, consentPage(id, req), { 'content-type': 'text/html; charset=utf-8' });
}

async function handleDecision(req, res) {
  const form = Object.fromEntries(await readForm(req));
  const authReq = pending.get(form.id);
  pending.delete(form.id);
  if (!authReq || authReq.expiresAt < Date.now()) return errorPage(res, 'authorization request not found or expired');

  const back = new URL(authReq.redirectUri);
  if (authReq.state) back.searchParams.set('state', authReq.state);
  back.searchParams.set('iss', ISSUER);

  if (form.action !== 'approve') {
    back.searchParams.set('error', 'access_denied');
    back.searchParams.set('error_description', 'the user denied the request');
    return redirect(res, back.href);
  }

  const user = USERS[form.username];
  if (!user || user.password !== form.password) {
    const id = rand(16);
    pending.set(id, authReq);
    return send(res, 200, consentPage(id, authReq, 'ユーザー名またはパスワードが違います'), {
      'content-type': 'text/html; charset=utf-8',
    });
  }

  const code = rand();
  codes.set(code, { ...authReq, user, expiresAt: Date.now() + 60 * 1000 });
  log(`issued authorization code for ${form.username} -> ${authReq.clientId}`);
  back.searchParams.set('code', code);
  redirect(res, back.href);
}

async function handleToken(req, res) {
  const params = await readForm(req);
  const form = Object.fromEntries(params);
  const tokenError = (error, description, status = 400) => {
    log(`token error: ${error} - ${description}`);
    return sendJson(res, status, { error, error_description: description });
  };

  // RFC 9449: a valid DPoP proof binds the issued tokens to the client's key (its thumbprint, jkt).
  // Checked first, so that a bad proof does not use up the authorization code.
  let jkt;
  if (req.headers.dpop !== undefined) {
    try {
      jkt = dpop.verifyDpopProof(req.headers.dpop, { htm: 'POST', htu: `${ISSUER}/token` });
    } catch (e) {
      return tokenError('invalid_dpop_proof', e.message);
    }
  }

  let grant;
  if (form.grant_type === 'authorization_code') {
    grant = codes.get(form.code);
    codes.delete(form.code);
    if (!grant || grant.expiresAt < Date.now()) return tokenError('invalid_grant', 'code is invalid or expired');
    if (form.redirect_uri !== grant.redirectUri) return tokenError('invalid_grant', 'redirect_uri does not match');
    const challenge = b64url(crypto.createHash('sha256').update(form.code_verifier ?? '').digest());
    if (challenge !== grant.codeChallenge) return tokenError('invalid_grant', 'PKCE verification failed');
  } else if (form.grant_type === 'refresh_token') {
    grant = refreshTokens.get(form.refresh_token);
    if (!grant || grant.expiresAt < Date.now()) {
      refreshTokens.delete(form.refresh_token);
      return tokenError('invalid_grant', 'refresh_token is invalid or expired');
    }
    // RFC 9449 §5: a public client's refresh token is bound to its DPoP key, so a stolen one is useless.
    // Checked before rotation so that a thief cannot use up the legitimate client's refresh token.
    if (grant.jkt && grant.jkt !== jkt) {
      return tokenError('invalid_grant', 'refresh_token is bound to a different DPoP key');
    }
    refreshTokens.delete(form.refresh_token); // rotation: public clients get a new refresh token each time
  } else {
    return tokenError('unsupported_grant_type', 'only authorization_code and refresh_token are supported');
  }
  if (form.client_id !== grant.clientId) return tokenError('invalid_client', 'client_id does not match', 401);

  // Re-check the client metadata (served from cache while fresh).
  let client;
  try {
    client = await getClientMetadata(grant.clientId);
  } catch (e) {
    if (!(e instanceof ClientMetadataError)) throw e;
    return tokenError('invalid_client', e.message, 401);
  }
  // RFC 9449 §5.2: a client can declare in its metadata that it always uses DPoP.
  if (client.dpop_bound_access_tokens === true && !jkt) {
    return tokenError('invalid_dpop_proof', 'this client requires DPoP-bound access tokens');
  }

  // RFC 8707: the token request may narrow the audience to a subset of the authorized resources.
  const requested = params.getAll('resource');
  const notAuthorized = requested.find((r) => !grant.resources.includes(r));
  if (notAuthorized) return tokenError('invalid_target', `resource "${notAuthorized}" was not authorized for this grant`);
  const audience = requested.length ? requested : grant.resources;

  const now = Math.floor(Date.now() / 1000);
  const scopes = grant.scope.split(' ');
  // RFC 9068 style JWT access token, audience-restricted to the requested resource(s).
  const accessToken = signJwt(
    {
      iss: ISSUER,
      sub: grant.user.sub,
      aud: audience.length === 0 ? ISSUER : audience.length === 1 ? audience[0] : audience,
      client_id: grant.clientId,
      scope: grant.scope,
      iat: now,
      exp: now + 300,
      jti: rand(16),
      ...(jkt && { cnf: { jkt } }), // RFC 9449 §6: the key this token is bound to
    },
    'at+jwt',
  );

  const refreshToken = rand();
  refreshTokens.set(refreshToken, {
    clientId: grant.clientId,
    user: grant.user,
    scope: grant.scope,
    resources: grant.resources, // keeps the originally authorized resources, not just this token's audience
    jkt,
    expiresAt: Date.now() + 60 * 60 * 1000,
  });

  const body = {
    access_token: accessToken,
    token_type: jkt ? 'DPoP' : 'Bearer',
    expires_in: 300,
    scope: grant.scope,
    refresh_token: refreshToken,
  };
  if (form.grant_type === 'authorization_code' && scopes.includes('openid')) {
    body.id_token = signJwt({
      iss: ISSUER,
      sub: grant.user.sub,
      aud: grant.clientId, // the client_id is the metadata document URL
      iat: now,
      exp: now + 300,
      ...(grant.nonce && { nonce: grant.nonce }),
      ...(scopes.includes('profile') && { name: grant.user.name }),
      ...(scopes.includes('email') && { email: grant.user.email }),
    });
  }
  log(`issued tokens (${form.grant_type}) to ${grant.clientId}, aud=${JSON.stringify(audience)}${jkt ? `, DPoP jkt=${jkt}` : ''}`);
  sendJson(res, 200, body);
}

function handleIndex(res) {
  const rows = [...metadataCache.entries()]
    .map(
      ([id, c]) => `<tr><td><code>${esc(id)}</code></td><td>${esc(c.metadata.client_name)}</td>
<td>${new Date(c.fetchedAt).toLocaleTimeString()}</td><td>${Math.max(0, Math.round((c.expiresAt - Date.now()) / 1000))}s</td></tr>`,
    )
    .join('');
  send(
    res,
    200,
    page(
      'Demo OP',
      `<div class="card"><h1>CIMD 対応 デモ OP</h1>
<p><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a> の
<code>client_id_metadata_document_supported: true</code> がサポートの目印です。</p>
${hint(
  'OP とは? discovery とは?',
  `<p>OP (OpenID Provider) は、ユーザーのログインを担当し、ID トークンやアクセストークンを発行するサーバーです。</p>
<p><code>/.well-known/openid-configuration</code> (discovery) は OP の自己紹介 JSON です。
クライアントはここを読むだけで、ログイン画面 (<code>authorization_endpoint</code>)・トークン発行 (<code>token_endpoint</code>)・
署名検証用の公開鍵 (<code>jwks_uri</code>) などの URL や、対応している機能を知ることができます。</p>`,
  true,
)}</div>
<div class="card"><h1>キャッシュ中の Client ID Metadata Document</h1>
<p>OP は client_id の URL から取得したドキュメントを、<code>Cache-Control: max-age</code> の間だけ覚えておきます。
ログインを試した後にこのページを再読み込みすると、ここに表示されます。</p>
${rows ? `<table><tr><td>client_id</td><td>client_name</td><td>取得時刻</td><td>残りTTL</td></tr>${rows}</table>` : '<p>まだありません</p>'}
</div>`,
    ),
    { 'content-type': 'text/html; charset=utf-8' },
  );
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, ISSUER);
  try {
    switch (`${req.method} ${url.pathname}`) {
      case 'GET /':
        return handleIndex(res);
      case 'GET /.well-known/openid-configuration':
      case 'GET /.well-known/oauth-authorization-server':
        return sendJson(res, 200, discovery(), { 'cache-control': 'max-age=60' });
      case 'GET /jwks':
        return sendJson(res, 200, { keys: [publicJwk] }, { 'cache-control': 'max-age=60' });
      case 'GET /authorize':
        return await handleAuthorize(res, url.searchParams);
      case 'POST /authorize/decision':
        return await handleDecision(req, res);
      case 'POST /token':
        return await handleToken(req, res);
      default:
        return send(res, 404, 'not found');
    }
  } catch (e) {
    console.error(e);
    send(res, 500, 'internal error');
  }
});

server.listen(PORT, () => log(`listening on ${ISSUER} (allow http localhost client_id: ${ALLOW_HTTP_LOCALHOST})`));
