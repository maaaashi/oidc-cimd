// Minimal OIDC Relying Party that identifies itself with a Client ID Metadata Document.
// No pre-registration with the OP is needed: the client_id IS the URL of /client-metadata.json.
const http = require('node:http');
const crypto = require('node:crypto');

const PORT = 4000;
const BASE = process.env.CLIENT_BASE || 'http://localhost:4000';
const ISSUER = process.env.ISSUER || 'http://localhost:3000';

const API_A = process.env.API_A || 'http://localhost:5000';
const API_B = process.env.API_B || 'http://localhost:5001';

const CLIENT_ID = `${BASE}/client-metadata.json`;
const REDIRECT_URI = `${BASE}/callback`;

const metadata = {
  client_id: CLIENT_ID,
  client_name: 'CIMD Demo Client',
  client_uri: BASE,
  logo_uri: `${BASE}/logo.svg`,
  redirect_uris: [REDIRECT_URI],
  grant_types: ['authorization_code'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
  scope: 'openid profile email',
};

// A document whose client_id does not match its own URL (the OP must reject it).
const mismatchedMetadata = { ...metadata, client_id: `${BASE}/someone-else.json` };

const LOGO = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#2b6cb0"/>
<text x="32" y="41" font-size="24" text-anchor="middle" fill="#fff" font-family="sans-serif">CI</text></svg>`;

const flows = new Map(); // state -> { verifier, nonce, clientId, redirectUri }
const NOT_AUTHORIZED_RESOURCE = 'http://localhost:5002';

const b64url = (v) => Buffer.from(v).toString('base64url');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const log = (...a) => console.log(`[client] ${new Date().toISOString()}`, ...a);
const json = (v) => esc(JSON.stringify(v, null, 2));

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}
const html = (res, body, status = 200) => send(res, status, page(body), { 'content-type': 'text/html; charset=utf-8' });

function page(body) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>CIMD Demo Client</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222;background:#eef3f8}
 .card{background:#fff;border:1px solid #cdd;border-radius:10px;padding:24px;margin-bottom:16px}
 h1{font-size:20px} .rp{color:#2b6cb0;font-weight:bold} code{background:#eee;padding:1px 4px;border-radius:4px}
 pre{background:#1e1e1e;color:#ddd;padding:12px;border-radius:6px;overflow:auto;font-size:12px}
 .btn{display:inline-block;background:#2b6cb0;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none}
 .err{background:#fee;border-color:#e99} li{margin:6px 0} .ok{color:#276749;font-weight:bold}
</style></head><body><p class="rp">Demo Client / RP (${esc(BASE)})</p>${body}</body></html>`;
}

let discoveryCache;
async function discover() {
  if (!discoveryCache) {
    const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
    discoveryCache = await res.json();
    if (!discoveryCache.client_id_metadata_document_supported) {
      log('WARNING: OP does not advertise client_id_metadata_document_supported');
    }
  }
  return discoveryCache;
}

function decodeJwt(jwt) {
  const [h, p, s] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url')),
    payload: JSON.parse(Buffer.from(p, 'base64url')),
    signingInput: `${h}.${p}`,
    signature: Buffer.from(s, 'base64url'),
  };
}

async function verifyIdToken(idToken, op, nonce) {
  const { header, payload, signingInput, signature } = decodeJwt(idToken);
  if (header.alg !== 'RS256') throw new Error(`unexpected alg ${header.alg}`);
  const { keys } = await (await fetch(op.jwks_uri)).json();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('signing key not found in JWKS');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  if (!crypto.verify('sha256', Buffer.from(signingInput), key, signature)) throw new Error('invalid signature');
  if (payload.iss !== op.issuer) throw new Error('iss mismatch');
  if (payload.aud !== CLIENT_ID) throw new Error('aud mismatch');
  if (payload.nonce !== nonce) throw new Error('nonce mismatch');
  if (payload.exp * 1000 < Date.now()) throw new Error('id_token expired');
  return { header, payload };
}

// Builds an authorization request. Variants intentionally break things to show what the OP checks.
async function handleLogin(res, variant) {
  const op = await discover();
  const variants = {
    normal: {},
    'unregistered-redirect': { redirectUri: `${BASE}/evil-callback` },
    'mismatched-client-id': { clientId: `${BASE}/mismatched-metadata.json` },
    'missing-document': { clientId: `${BASE}/not-found.json` },
    'no-path': { clientId: BASE },
    'unknown-resource': { resources: [API_A, 'http://localhost:9999'] },
  };
  const {
    clientId = CLIENT_ID,
    redirectUri = REDIRECT_URI,
    resources = [API_A, API_B], // RFC 8707: ask for consent to both APIs up front
  } = variants[variant] || variants.normal;

  const state = rand(16);
  const nonce = rand(16);
  const verifier = rand(32);
  flows.set(state, { verifier, nonce, clientId, redirectUri });

  const u = new URL(op.authorization_endpoint);
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
  });
  for (const r of resources) q.append('resource', r);
  u.search = q.toString();
  log(`redirecting to OP (${variant || 'normal'}): ${u.href}`);
  send(res, 302, '', {
    location: u.href,
    // Cookies are not port-isolated, so use a name distinct from the OP's.
    'set-cookie': `rp_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
  });
}

async function handleCallback(req, res, params) {
  const cookieState = /(?:^|;\s*)rp_state=([^;]+)/.exec(req.headers.cookie || '')?.[1];
  const state = params.get('state');
  const flow = flows.get(state);
  flows.delete(state);

  if (params.get('error')) {
    return html(
      res,
      `<div class="card err"><h1>OP からエラーが返されました</h1><pre>${json(Object.fromEntries(params))}</pre>
<a href="/">戻る</a></div>`,
    );
  }
  if (!flow || state !== cookieState) return html(res, `<div class="card err"><h1>state が不正です</h1><a href="/">戻る</a></div>`, 400);

  const op = await discover();
  if (params.get('iss') !== op.issuer) return html(res, `<div class="card err"><h1>iss が一致しません</h1></div>`, 400);

  const tokenRequest = async (pairs) => {
    const r = await fetch(op.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(pairs),
    });
    return { status: r.status, body: await r.json() };
  };
  const callApi = async (api, accessToken) => {
    try {
      const r = await fetch(`${api}/api/data`, { headers: { authorization: `Bearer ${accessToken}` } });
      return { status: r.status, body: await r.json() };
    } catch (e) {
      return { status: 'error', body: { error: `cannot reach ${api}: ${e.cause?.code || e.message}` } };
    }
  };
  const atClaims = (t) => (t.body.access_token ? decodeJwt(t.body.access_token).payload : undefined);

  // 1) Code exchange. Public client: no secret, just the metadata URL + PKCE.
  //    resource narrows the access token to API A only.
  const t1 = await tokenRequest([
    ['grant_type', 'authorization_code'],
    ['code', params.get('code')],
    ['redirect_uri', flow.redirectUri],
    ['client_id', flow.clientId],
    ['code_verifier', flow.verifier],
    ['resource', API_A],
  ]);
  if (t1.status !== 200) {
    return html(res, `<div class="card err"><h1>トークンリクエスト失敗</h1><pre>${json(t1.body)}</pre></div>`, 400);
  }
  let idToken;
  try {
    idToken = await verifyIdToken(t1.body.id_token, op, flow.nonce);
  } catch (e) {
    return html(res, `<div class="card err"><h1>ID トークン検証失敗</h1><p>${esc(e.message)}</p></div>`, 400);
  }
  const tokenA = t1.body.access_token;

  // 2) Refresh token grant asking for a token for API B (authorized at /authorize, so it is allowed).
  const t2 = await tokenRequest([
    ['grant_type', 'refresh_token'],
    ['refresh_token', t1.body.refresh_token],
    ['client_id', flow.clientId],
    ['resource', API_B],
  ]);
  const tokenB = t2.body.access_token;

  // 3) Call the APIs. A token for API A must not work at API B.
  const callAwithA = await callApi(API_A, tokenA);
  const callBwithA = await callApi(API_B, tokenA);
  const callBwithB = tokenB ? await callApi(API_B, tokenB) : { status: '-', body: 'no token' };

  // 4) Asking for a resource that was never authorized fails with invalid_target.
  const t3 = await tokenRequest([
    ['grant_type', 'refresh_token'],
    ['refresh_token', t2.body.refresh_token ?? ''],
    ['client_id', flow.clientId],
    ['resource', NOT_AUTHORIZED_RESOURCE],
  ]);

  log(`login succeeded: sub=${idToken.payload.sub}`);

  const badge = (status, expected) =>
    `<b style="color:${status === expected ? '#276749' : '#c53030'}">HTTP ${status}</b> (期待値 ${expected})`;
  const step = (title, desc, r, expected, extra = '') =>
    `<div class="card"><h2>${title}</h2><p>${desc}</p><p>${badge(r.status, expected)}</p>${extra}<pre>${json(r.body)}</pre></div>`;

  html(
    res,
    `<div class="card"><h1 class="ok">ログイン成功: ${esc(idToken.payload.name)}</h1>
<p>ID トークンの <code>aud</code> は client_id (= メタデータ URL)、アクセストークンの <code>aud</code> は API (resource) です。</p>
<h2>ID Token (署名検証済み)</h2><pre>${json(idToken.payload)}</pre></div>
${step(
  '① 認可コード → トークン (resource=API A)',
  `<code>resource=${esc(API_A)}</code> を付けてトークンを要求`,
  t1,
  200,
  `<p>アクセストークンの中身:</p><pre>${json(atClaims(t1))}</pre><p>レスポンス全体:</p>`,
)}
${step(
  '② リフレッシュトークン → トークン (resource=API B)',
  `同じ同意の範囲内なので、別 API 用のトークンに切り替えられる`,
  t2,
  200,
  `<p>アクセストークンの中身:</p><pre>${json(atClaims(t2))}</pre><p>レスポンス全体:</p>`,
)}
${step('③ API A を API A 用トークンで呼ぶ', `GET ${esc(API_A)}/api/data`, callAwithA, 200)}
${step('④ API B を API A 用トークンで呼ぶ', '<code>aud</code> が違うので API B は拒否する (トークンの使い回し防止)', callBwithA, 401)}
${step('⑤ API B を API B 用トークンで呼ぶ', `GET ${esc(API_B)}/api/data`, callBwithB, 200)}
${step(
  '⑥ 同意していない resource を要求',
  `<code>resource=${esc(NOT_AUTHORIZED_RESOURCE)}</code> は認可リクエストに含めていないので <code>invalid_target</code>`,
  t3,
  400,
)}
<a class="btn" href="/">トップへ</a>`,
  );
}

function handleIndex(res) {
  html(
    res,
    `<div class="card"><h1>OIDC × Client ID Metadata Document デモ</h1>
<p>このクライアントは OP に事前登録されていません。<br>
client_id = <code><a href="/client-metadata.json">${esc(CLIENT_ID)}</a></code></p>
<p><a class="btn" href="/login">OP でログイン</a></p>
<p>ログイン後、Resource Indicators (RFC 8707) で API ごとに <code>aud</code> を絞ったアクセストークンを取得し、
<code>${esc(API_A)}</code> / <code>${esc(API_B)}</code> を呼び分けます。</p></div>
<div class="card"><h1>Client ID Metadata Document</h1><pre>${json(metadata)}</pre></div>
<div class="card"><h1>失敗パターンを試す</h1><ul>
<li><a href="/login?variant=unregistered-redirect">メタデータに無い redirect_uri を使う</a></li>
<li><a href="/login?variant=mismatched-client-id">ドキュメント内の client_id が URL と一致しない</a>
 (<a href="/mismatched-metadata.json">doc</a>)</li>
<li><a href="/login?variant=missing-document">ドキュメントが存在しない (404)</a></li>
<li><a href="/login?variant=no-path">パスの無い client_id URL</a></li>
<li><a href="/login?variant=unknown-resource">OP が知らない resource を要求する</a></li>
</ul></div>
<div class="card"><p>OP: <a href="${esc(ISSUER)}/">${esc(ISSUER)}</a> (キャッシュ状況) ・
<a href="${esc(ISSUER)}/.well-known/openid-configuration">discovery</a></p></div>`,
  );
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE);
  try {
    switch (`${req.method} ${url.pathname}`) {
      case 'GET /':
        return handleIndex(res);
      case 'GET /client-metadata.json':
        log(`client metadata document requested by ${req.headers['user-agent']}`);
        return send(res, 200, JSON.stringify(metadata, null, 2), {
          'content-type': 'application/json',
          'cache-control': 'max-age=60',
        });
      case 'GET /mismatched-metadata.json':
        return send(res, 200, JSON.stringify(mismatchedMetadata, null, 2), { 'content-type': 'application/json' });
      case 'GET /logo.svg':
        return send(res, 200, LOGO, { 'content-type': 'image/svg+xml' });
      case 'GET /login':
        return await handleLogin(res, url.searchParams.get('variant'));
      case 'GET /callback':
        return await handleCallback(req, res, url.searchParams);
      default:
        return send(res, 404, 'not found');
    }
  } catch (e) {
    console.error(e);
    send(res, 500, `internal error: ${e.message}`);
  }
});

server.listen(PORT, () => log(`listening on ${BASE}, client_id=${CLIENT_ID}`));
