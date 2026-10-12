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
  scope: 'openid profile email mcp:tools',
  // RFC 9126 §6: this client always pushes its authorization requests, so the OP refuses ones sent via the browser's URL.
  require_pushed_authorization_requests: true,
};

// A document whose client_id does not match its own URL (the OP must reject it).
const mismatchedMetadata = { ...metadata, client_id: `${BASE}/someone-else.json` };

const LOGO = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#2b6cb0"/>
<text x="32" y="41" font-size="24" text-anchor="middle" fill="#fff" font-family="sans-serif">CI</text></svg>`;

const flows = new Map(); // state -> { verifier, nonce, clientId, redirectUri, mcp? }
const NOT_AUTHORIZED_RESOURCE = 'http://localhost:5002';

const b64url = (v) => Buffer.from(v).toString('base64url');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const log = (...a) => console.log(`[client] ${new Date().toISOString()}`, ...a);
const json = (v) => esc(JSON.stringify(v, null, 2));
// Collapsible explanation for OIDC/OAuth beginners. `body` is trusted HTML.
const hint = (title, body, open = false) =>
  `<details class="hint"${open ? ' open' : ''}><summary>💡 ${title}</summary>${body}</details>`;

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
 .hint{background:#fffbea;border:1px solid #f0d98a;border-radius:8px;padding:8px 14px;margin:12px 0;font-size:14px;line-height:1.7}
 .hint summary{cursor:pointer;font-weight:bold;color:#8a6d00} .hint dt{font-weight:bold;margin-top:6px} .hint dd{margin:0 0 0 1.5em}
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

// RFC 9449 DPoP: this client's key pair. Tokens requested with a proof from this key are bound to it (cnf.jkt),
// so they are useless to anyone who does not hold the private key. A real client would keep one per installation
// or session, ideally in non-exportable storage.
const dpopKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
// An attacker's own key pair, to show what happens when someone steals the tokens but not the private key.
const attackerKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

// A DPoP proof is a short-lived JWT, signed by the client's key, that is valid for one HTTP request only.
function createDpopProof(key, htm, htu, accessToken) {
  const { kty, crv, x, y } = key.publicKey.export({ format: 'jwk' });
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty, crv, x, y } };
  const payload = {
    jti: rand(16),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
    // At a resource server, the proof also carries the hash of the access token it is sent with.
    ...(accessToken && { ath: b64url(crypto.createHash('sha256').update(accessToken).digest()) }),
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64url(sig)}`;
}

// With `key`, a DPoP proof is sent so that the issued tokens are bound to that key.
async function requestToken(op, pairs, key) {
  const proof = key && createDpopProof(key, 'POST', op.token_endpoint);
  const r = await fetch(op.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(proof && { dpop: proof }) },
    body: new URLSearchParams(pairs),
  });
  return { status: r.status, body: await r.json(), proof };
}

// Builds an authorization request. Variants intentionally break things to show what the OP checks.
async function handleLogin(res, variant) {
  const op = await discover();
  const variants = {
    normal: { par: true },
    'unregistered-redirect': { redirectUri: `${BASE}/evil-callback` },
    'mismatched-client-id': { clientId: `${BASE}/mismatched-metadata.json` },
    'missing-document': { clientId: `${BASE}/not-found.json` },
    'no-path': { clientId: BASE },
    'unknown-resource': { par: true, resources: [API_A, 'http://localhost:9999'] },
    // RFC 9126 PAR variants.
    'no-par': {},
    'par-tampered': {
      par: true,
      // Someone edits the URL in the browser. The OP must ignore all of this.
      tamper: [
        ['scope', 'openid profile email mcp:tools'],
        ['resource', NOT_AUTHORIZED_RESOURCE],
        ['redirect_uri', `${BASE}/evil-callback`],
      ],
    },
    'par-replay': { par: true, replay: true },
    'par-client-mismatch': { par: true, authorizeClientId: 'https://evil.example/client-metadata.json' },
  };
  // The normal flow pushes its request (PAR). The other failure variants use the front channel on purpose,
  // to show the OP's own checks on a request it receives through the browser.
  const {
    clientId = CLIENT_ID,
    redirectUri = REDIRECT_URI,
    resources = [API_A, API_B], // RFC 8707: ask for consent to both APIs up front
    par = false,
    ...parOptions
  } = variants[variant] || variants.normal;

  const nonce = rand(16);
  const q = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, scope: 'openid profile email', nonce });
  for (const r of resources) q.append('resource', r);
  // The PAR request carries a DPoP proof too, which binds the authorization code to dpopKey (RFC 9449 §10.1).
  await redirectToAuthorize(res, op, q, { nonce, clientId, redirectUri }, variant || 'normal', { par, key: dpopKey, ...parOptions });
}

// URLSearchParams -> plain object for display; repeated parameters (resource) become arrays.
function formObject(params) {
  const o = {};
  for (const [k, v] of params) o[k] = k in o ? [].concat(o[k], v) : v;
  return o;
}

// Adds state + PKCE to the authorization request, remembers the flow, and sends the browser to the OP.
// With `par`, the request is first pushed to the OP (RFC 9126) and the browser carries only client_id + request_uri.
// tamper / replay / authorizeClientId break the PAR flow on purpose to show what the OP checks.
async function redirectToAuthorize(res, op, query, flow, label, { par = false, key, tamper = [], replay = false, authorizeClientId } = {}) {
  const state = rand(16);
  const verifier = rand(32);
  query.set('response_type', 'code');
  query.set('state', state);
  query.set('code_challenge', b64url(crypto.createHash('sha256').update(verifier).digest()));
  query.set('code_challenge_method', 'S256');
  const u = new URL(op.authorization_endpoint);

  let parTrace;
  if (par) {
    const endpoint = op.pushed_authorization_request_endpoint;
    if (!endpoint) throw new Error('the authorization server does not offer a PAR endpoint');
    const proof = key && createDpopProof(key, 'POST', endpoint);
    // A public client authenticates at the PAR endpoint the same way as at the token endpoint: client_id only.
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(proof && { dpop: proof }) },
      body: query,
    });
    parTrace = { endpoint, request: formObject(query), proof, status: r.status, body: await r.json() };
    log(`PAR (${label}): HTTP ${r.status} ${JSON.stringify(parTrace.body)}`);
    if (r.status !== 201) return parErrorPage(res, parTrace);

    u.search = new URLSearchParams({ client_id: authorizeClientId ?? query.get('client_id'), request_uri: parTrace.body.request_uri });
    for (const [k, v] of tamper) u.searchParams.append(k, v);
    // Someone who saw the URL (e.g. in a log) uses the request_uri before the user does.
    if (replay) await fetch(u.href, { redirect: 'manual' });
    parTrace.authorizeUrl = u.href;
  } else {
    u.search = query.toString();
  }

  flows.set(state, { ...flow, verifier, par: parTrace });
  log(`redirecting to OP (${label}): ${u.href}`);
  send(res, 302, '', {
    location: u.href,
    // Cookies are not port-isolated, so use a name distinct from the OP's.
    'set-cookie': `rp_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
  });
}

function parErrorPage(res, parTrace) {
  html(
    res,
    `<div class="card err"><h1>PAR が OP に拒否されました</h1>
<p><code>POST ${esc(parTrace.endpoint)}</code> <b>HTTP ${esc(parTrace.status)}</b></p>
<p>送ったパラメーター:</p><pre>${json(parTrace.request)}</pre><p>レスポンス:</p><pre>${json(parTrace.body)}</pre>
${hint(
  'エラーがブラウザを経由せずに返ってくる',
  `<p>PAR ではクライアントが OP に直接リクエストを送るので、エラーも JSON でそのままクライアントに返ってきます。
ブラウザは OP の画面にすら移動していません。</p>
<p>フロントチャネル (URL) で送った場合は、OP はエラーを <code>redirect_uri</code> 経由で返すか、
redirect_uri が信用できなければ自分の画面に表示するしかありませんでした。
PAR なら、ユーザーを OP に送る前に「このリクエストは受け付けられる」と確認できます。</p>`,
  true,
)}<a href="/">戻る</a></div>`,
    400,
  );
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
${hint(
  'このエラーの意味',
  `<p>OP は戻り先 (redirect_uri) が正しいと確認できた後のエラーを、<code>error</code> パラメーター付きでクライアントに返します。</p>
<dl>
<dt>access_denied</dt><dd>ユーザーが同意画面で「拒否」を押しました。</dd>
<dt>invalid_target</dt><dd><code>resource</code> に、OP が知らない (または許可されていない) API を指定しました。</dd>
<dt>invalid_scope</dt><dd>OP が対応していない scope を要求しました。</dd>
<dt>invalid_request</dt><dd>必須のパラメーター (PKCE など) が足りません。
または、PAR が必須のクライアント (メタデータに <code>require_pushed_authorization_requests: true</code>) が、PAR を使わずに URL でリクエストを送りました。</dd>
</dl>`,
  true,
)}
<a href="/">戻る</a></div>`,
    );
  }
  if (!flow || state !== cookieState) return html(res, `<div class="card err"><h1>state が不正です</h1>
${hint(
  'state のチェックとは',
  `<p>ログイン開始時に作った <code>state</code> (Cookie にも保存) と、戻ってきた URL の <code>state</code> が一致しませんでした。
攻撃者が自分のアカウントの認可コードを踏ませる攻撃 (CSRF) を防ぐため、一致しない場合は処理を中断します。
ブラウザの戻るボタンや、ページの再読み込みでも起こります。</p>`,
  true,
)}<a href="/">戻る</a></div>`, 400);

  // The MCP flow discovered its authorization server dynamically; the OIDC flow uses the configured ISSUER.
  const op = flow.mcp?.as ?? (await discover());
  if (params.get('iss') !== op.issuer) return html(res, `<div class="card err"><h1>iss が一致しません</h1></div>`, 400);
  if (flow.mcp) return handleMcpCallback(res, params, flow, op);

  // This flow uses DPoP throughout: every token request and API call carries a proof from dpopKey.
  const tokenRequest = (pairs, key = dpopKey) => requestToken(op, pairs, key);
  // Options let the attack steps send the token as Bearer, sign with another key, or replay an old proof.
  const callApi = async (api, accessToken, { scheme = 'DPoP', key = dpopKey, proof, path = '/api/data', query = '' } = {}) => {
    const url = `${api}${path}`;
    // htu is the URL without the query.
    proof ??= key && createDpopProof(key, 'GET', url, accessToken);
    try {
      const r = await fetch(`${url}${query}`, { headers: { authorization: `${scheme} ${accessToken}`, ...(proof && { dpop: proof }) } });
      const body = await r.json();
      const wwwAuthenticate = r.headers.get('www-authenticate');
      return { status: r.status, body: wwwAuthenticate ? { 'www-authenticate': wwwAuthenticate, body } : body, proof };
    } catch (e) {
      return { status: 'error', body: { error: `cannot reach ${api}: ${e.cause?.code || e.message}` } };
    }
  };
  const atClaims = (t) => (t.body.access_token ? decodeJwt(t.body.access_token).payload : undefined);
  const proofClaims = (proof) => {
    const { header, payload } = decodeJwt(proof);
    return { header, payload };
  };

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

  // 4) DPoP: suppose an attacker has stolen the access token / refresh token (but not dpopKey's private key).
  const stolenAsBearer = await callApi(API_A, tokenA, { scheme: 'Bearer', key: null });
  const stolenWithOwnKey = await callApi(API_A, tokenA, { key: attackerKey });
  const replayedProof = await callApi(API_A, tokenA, { proof: callAwithA.proof });
  // Uses t2's refresh token before step 5 does; the OP checks the key binding before rotating it.
  const stolenRefresh = await tokenRequest(
    [
      ['grant_type', 'refresh_token'],
      ['refresh_token', t2.body.refresh_token ?? ''],
      ['client_id', flow.clientId],
      ['resource', API_A],
    ],
    attackerKey,
  );

  // 5) Asking for a resource that was never authorized fails with invalid_target.
  const t3 = await tokenRequest([
    ['grant_type', 'refresh_token'],
    ['refresh_token', t2.body.refresh_token ?? ''],
    ['client_id', flow.clientId],
    ['resource', NOT_AUTHORIZED_RESOURCE],
  ]);

  // 6) RFC 8693 Token Exchange: API A calls API B on the user's behalf. The client only talks to API A.
  const downstream = (api, token, mode) => callApi(api, token, { path: '/api/downstream', query: `?mode=${mode}` });
  const exchangeAtoB = await downstream(API_A, tokenA, 'exchange');
  const passthrough = await downstream(API_A, tokenA, 'passthrough');
  const escalate = await downstream(API_A, tokenA, 'escalate');
  const exchangeBtoA = tokenB ? await downstream(API_B, tokenB, 'exchange') : { status: '-', body: 'no token' };

  log(`login succeeded: sub=${idToken.payload.sub}`);

  const step = (title, desc, r, expected, extra = '', explain = '') =>
    `<div class="card"><h2>${title}</h2><p>${desc}</p>${explain && hint('解説', explain)}<p>${statusBadge(r.status, expected)}</p>${extra}<pre>${json(r.body)}</pre></div>`;

  html(
    res,
    `<div class="card"><h1 class="ok">ログイン成功: ${esc(idToken.payload.name)}</h1>
<p>ID トークンの <code>aud</code> は client_id (= メタデータ URL)、アクセストークンの <code>aud</code> は API (resource) です。</p>
<h2>ID Token (署名検証済み)</h2><pre>${json(idToken.payload)}</pre>
${hint(
  'ID トークンの読み方',
  `<p>ID トークンは OP が署名した「この人がログインしました」という証明書です。JWT という形式で、
<code>ヘッダー.中身.署名</code> を Base64URL でつないだ文字列になっています。上に表示しているのは「中身」の部分です。</p>
<dl>
<dt>iss (issuer)</dt><dd>発行者。どの OP が発行したかを表します。</dd>
<dt>sub (subject)</dt><dd>ユーザーの一意な ID。名前やメールアドレスは変わることがあるので、ユーザーを識別するときはこれを使います。</dd>
<dt>aud (audience)</dt><dd>宛先。このアプリ (client_id) 宛てに発行されたことを表します。他のアプリ宛ての ID トークンは受け取ってはいけません。</dd>
<dt>iat / exp</dt><dd>発行時刻と有効期限 (1970 年からの秒数)。</dd>
<dt>nonce</dt><dd>ログイン開始時にこのアプリが作った乱数。一致すれば「今回のログインで発行されたもの」とわかります。</dd>
<dt>name / email</dt><dd>scope の <code>profile</code> / <code>email</code> で要求したユーザー情報です。</dd>
</dl>
<p>このアプリは受け取った ID トークンについて、OP の公開鍵 (<code>/jwks</code>) による <b>署名</b>、<code>iss</code>・<code>aud</code>・<code>nonce</code>・<code>exp</code> を検証してからログイン成功としています。</p>`,
  true,
)}
${hint(
  'ID トークンとアクセストークンの違い',
  `<dl>
<dt>ID トークン = 身分証明書 (クライアントが読む)</dt><dd>「誰がログインしたか」をクライアントに伝えます。<code>aud</code> は client_id です。</dd>
<dt>アクセストークン = 入館証 (API に見せる)</dt><dd>API を呼ぶときに <code>Authorization: Bearer &lt;トークン&gt;</code> ヘッダーで送ります。<code>aud</code> は API です。</dd>
</dl>
<p>ID トークンを API に送ったり、アクセストークンを持っていることを「ログインした証拠」とみなしたりしてはいけません。</p>`,
)}</div>
${flow.par ? parCard(flow.par, proofClaims) : ''}
${step(
  '① 認可コード → トークン (resource=API A)',
  `<code>resource=${esc(API_A)}</code> を付けてトークンを要求`,
  t1,
  200,
  `<p>送った DPoP proof (<code>DPoP</code> ヘッダー) の中身:</p><pre>${json(proofClaims(t1.proof))}</pre>
<p>アクセストークンの中身 (<code>cnf.jkt</code> に注目):</p><pre>${json(atClaims(t1))}</pre><p>レスポンス全体:</p>`,
  `<p>認可コード・PKCE の <code>code_verifier</code>・client_id を OP の <code>/token</code> に送ってトークンと交換します。
このアプリは公開クライアントなのでクライアントシークレットは送りません。</p>
<p><code>resource</code> (RFC 8707 Resource Indicators) は「このトークンをどの API で使うか」の指定です。
するとアクセストークンの <code>aud</code> がその API になります。入館証に「A 棟専用」と書いてもらうイメージです。</p>
<p>レスポンスには <code>access_token</code> (API 用)・<code>id_token</code> (ログイン証明)・<code>refresh_token</code> (トークン再発行用) が含まれます。</p>
<p>このリクエストには <b>DPoP proof</b> も付けています (RFC 9449)。クライアントが自分で作った鍵ペアの秘密鍵で署名した小さな JWT で、
ヘッダーに公開鍵 (<code>jwk</code>) が入っています。OP は署名を確かめ、その公開鍵のハッシュ (thumbprint) を
アクセストークンの <code>cnf.jkt</code> に書き込みます。<code>token_type</code> も <code>Bearer</code> ではなく <code>DPoP</code> になります。
入館証に「この鍵を持っている人専用」と書いてもらうイメージです。</p>`,
)}
${step(
  '② リフレッシュトークン → トークン (resource=API B)',
  `同じ同意の範囲内なので、別 API 用のトークンに切り替えられる`,
  t2,
  200,
  `<p>アクセストークンの中身:</p><pre>${json(atClaims(t2))}</pre><p>レスポンス全体:</p>`,
  `<p>アクセストークンは盗まれたときの被害を小さくするため短命 (このデモでは 5 分) です。
<b>リフレッシュトークン</b> を使うと、ユーザーにもう一度ログインしてもらわずに新しいアクセストークンをもらえます。</p>
<p>最初の認可リクエストで API A と API B の両方に同意済みなので、今度は API B 用のトークンを発行してもらえます。
なお、リフレッシュトークンは使うたびに新しいものに入れ替わります (ローテーション)。</p>
<p>リフレッシュトークンも ① の DPoP の鍵に紐付いているので、同じ鍵で作った proof を付けないと使えません (⑩ で確認)。</p>`,
)}
${step(
  '③ API A を API A 用トークンで呼ぶ',
  `GET ${esc(API_A)}/api/data`,
  callAwithA,
  200,
  `<p>送った DPoP proof の中身:</p><pre>${json(proofClaims(callAwithA.proof))}</pre><p>レスポンス:</p>`,
  `<p>API はトークンを受け取ると、OP の公開鍵で署名を確かめ、発行者 (<code>iss</code>)・有効期限 (<code>exp</code>)・
宛先 (<code>aud</code>) が自分であることを確認します。</p>
<p>さらにトークンに <code>cnf.jkt</code> があるので、<code>Authorization: DPoP &lt;トークン&gt;</code> と一緒に送られた DPoP proof も検証します。</p>
<dl>
<dt>署名と jwk</dt><dd>proof の署名が、ヘッダーの公開鍵で正しく検証できること。その公開鍵の thumbprint がトークンの <code>cnf.jkt</code> と一致すること。</dd>
<dt>htm / htu</dt><dd>この proof が「GET」「<code>${esc(API_A)}/api/data</code>」へのリクエスト専用に作られたこと。</dd>
<dt>ath</dt><dd>このアクセストークンのハッシュ。別のトークン用に作った proof を流用できないようにします。</dd>
<dt>iat / jti</dt><dd>作られたばかりであること、一度も使われていない ID であること。</dd>
</dl>
<p>すべて OK なのでデータが返ります。</p>`,
)}
${step(
  '④ API B を API A 用トークンで呼ぶ',
  '<code>aud</code> が違うので API B は拒否する (トークンの使い回し防止)',
  callBwithA,
  401,
  '',
  `<p>署名も期限も正しいトークンですが、宛先が API A なので API B は受け付けません。</p>
<p>もし <code>aud</code> のチェックが無いと、たとえば悪意のある API がトークンを受け取ったとき、
それを別の API に送ってユーザーになりすませてしまいます。<code>aud</code> を絞ることで、漏れたときの被害がその API だけに限定されます。</p>`,
)}
${step('⑤ API B を API B 用トークンで呼ぶ', `GET ${esc(API_B)}/api/data`, callBwithB, 200, '', `<p>② で取得した API B 宛てのトークンなので受け付けられます。</p>`)}
${step(
  '⑥ 同意していない resource を要求',
  `<code>resource=${esc(NOT_AUTHORIZED_RESOURCE)}</code> は認可リクエストに含めていないので <code>invalid_target</code>`,
  t3,
  400,
  '',
  `<p>リフレッシュトークンで発行できるのは、ユーザーが最初に同意した範囲 (API A / API B) のトークンだけです。
同意していない API 向けのトークンをこっそり手に入れることはできません。</p>`,
)}
<div class="card"><h1>DPoP (RFC 9449): 盗まれたトークンを使わせない</h1>
<p>ここからは、攻撃者がアクセストークンやリフレッシュトークンを盗んだ (でもクライアントの秘密鍵は持っていない) 場面を試します。</p>
${hint(
  'DPoP とは? aud による制限との違い',
  `<p>普通のアクセストークンは <b>Bearer トークン</b> (持参人トークン) です。「持っている人なら誰でも使える」ので、
ログや通信経路、悪意のある API などから漏れると、そのまま悪用されてしまいます。</p>
<dl>
<dt>aud (RFC 8707) で絞れるもの</dt><dd><b>どの API で</b> 使えるか。漏れても被害はその API だけになりますが、その API では使えてしまいます。</dd>
<dt>DPoP で絞れるもの</dt><dd><b>誰が</b> 使えるか。トークンを特定の鍵に紐付け、その秘密鍵で署名した proof を毎回要求します。
秘密鍵はクライアントの外に出ないので、トークンだけ盗んでも使えません。</dd>
</dl>
<p>クライアントシークレットを持てない公開クライアント (このアプリのような CIMD のクライアントやスマホアプリ) でも、
その場で鍵ペアを作るだけで使えるのが特徴です。事前に鍵を OP へ登録する必要もありません。</p>
<p>なお、このデモの MCP 風フローは Bearer のままです。MCP の認可仕様が <code>Authorization: Bearer</code> を前提としているためです。
このクライアントが常に DPoP を使うなら、CIMD のメタデータに <code>"dpop_bound_access_tokens": true</code> と書けば、
OP は DPoP 無しのトークンリクエストを拒否します。</p>`,
)}</div>
${step(
  '⑦ 盗んだアクセストークンを Bearer として使う',
  'DPoP に紐付いたトークンは <code>Authorization: Bearer</code> では受け付けられない',
  stolenAsBearer,
  401,
  '',
  `<p>攻撃者は proof を作れないので、トークンを普通の Bearer トークンとして送ってみます。
API はトークンの <code>cnf.jkt</code> を見て「DPoP 専用のトークンだ」とわかるので、Bearer では拒否します。
<code>WWW-Authenticate: DPoP ...</code> は「DPoP で来てください」という意味です。</p>`,
)}
${step(
  '⑧ 盗んだアクセストークンに、攻撃者自身の鍵で作った proof を付ける',
  '署名は正しくても、鍵がトークンに書かれた <code>cnf.jkt</code> と違うので拒否される',
  stolenWithOwnKey,
  401,
  `<p>攻撃者の proof の公開鍵 (正規のクライアントの鍵とは別物):</p><pre>${json(stolenWithOwnKey.proof && proofClaims(stolenWithOwnKey.proof).header.jwk)}</pre><p>レスポンス:</p>`,
  `<p>proof は誰でも作れます。自分で鍵ペアを作って署名すればよいだけです。
しかしトークンには「正規のクライアントの公開鍵の thumbprint」が OP の署名付きで書き込まれています。
攻撃者の鍵の thumbprint はそれと一致しないので、API は拒否します (<code>invalid_dpop_proof</code>)。</p>`,
)}
${step(
  '⑨ ③ で送った proof をそのまま使い回す (リプレイ)',
  'トークンと proof の両方を盗んでも、proof は 1 回しか使えない',
  replayedProof,
  401,
  '',
  `<p>通信を盗み見て、トークンと proof の組をまるごと手に入れた場合です。proof は正規の鍵で署名されていますが、
<code>jti</code> (proof ごとの一意な ID) がすでに使われているので拒否されます。
proof は <code>iat</code> から短時間 (このデモでは 60 秒) しか有効でなく、<code>htm</code>/<code>htu</code> で特定のリクエスト専用になっているので、
別の API や別の操作にも流用できません。</p>`,
)}
${step(
  '⑩ 盗んだリフレッシュトークンを、攻撃者の鍵で使う',
  'リフレッシュトークンも鍵に紐付いているので、新しいトークンは発行されない',
  stolenRefresh,
  400,
  '',
  `<p>リフレッシュトークンはアクセストークンより長生きなので、盗まれたときの被害も大きくなります。
シークレットを持たない公開クライアントの場合、OP は DPoP で発行したリフレッシュトークンを同じ鍵に紐付けます。
攻撃者の鍵の proof では <code>invalid_grant</code> になります。</p>
<p>このデモの OP は、鍵が違う場合はリフレッシュトークンを消費しない (ローテーションしない) ようにしています。
攻撃者が正規のクライアントのリフレッシュトークンを使えなくする、という嫌がらせを防ぐためです。⑥ はこの後、同じリフレッシュトークンを正しい鍵で使っています。</p>`,
)}
<div class="card"><h1>Token Exchange (RFC 8693): API が別の API をユーザーの代わりに呼ぶ</h1>
<p>クライアントは API A の <code>/api/downstream</code> を呼ぶだけです。API A は処理の途中で API B のデータが必要になり、
ユーザー (alice) の代わりに API B を呼びます。</p>
<pre>Client ──GET /api/downstream (DPoP AT, aud=API A)──▶ API A
API A  ──POST /token  grant_type=token-exchange
                      subject_token=&lt;受け取った AT&gt;  resource=API B  scope=profile
                      Authorization: Basic (API A の client_id / secret)──▶ OP
       ◀── AT (aud=API B, sub=alice, act.sub=API A)
API A  ──GET /api/data (Bearer 新しい AT)──▶ API B</pre>
${hint(
  'なぜ受け取ったトークンをそのまま転送してはいけないの?',
  `<p>API A が受け取ったトークンの <code>aud</code> は API A です。これを API B に転送する (トークンパススルー) と、</p>
<ul>
<li>API B が <code>aud</code> を正しく検証していれば、④ と同じく拒否されます</li>
<li>検証が甘い API B なら通ってしまい、「API A 宛てのトークンがどこでも使える」状態になります (④ で防いだはずの問題が戻ってくる)</li>
<li>API B のログには「クライアントが直接呼んだ」としか残らず、API A が間に入ったことがわかりません</li>
</ul>
<p>そこで API A は OP に「このトークンを持ってきたユーザーの代わりに、API B を呼ぶためのトークンをください」と頼みます。これが Token Exchange です。
MCP の仕様がトークンパススルーを禁止しているのも同じ理由で、MCP サーバーが上流の API を呼ぶときの正しいやり方がこれです。</p>`,
  true,
)}
${hint(
  'OP は何を確認している?',
  `<dl>
<dt>API A 自身の認証 (<code>client_secret_basic</code>)</dt><dd>交換を頼んでいるのが本当に API A であること。API A は CIMD の公開クライアントとは違い、シークレットを持てるサーバーなので、事前登録したコンフィデンシャルクライアントにしています。</dd>
<dt>subject_token の検証</dt><dd>OP 自身が発行した、期限内のアクセストークンであること。</dd>
<dt>subject_token の <code>aud</code> が API A であること</dt><dd>API A は「自分宛てに届いたトークン」しか交換できません。どこかで拾った他の API 宛てのトークンは交換できません。</dd>
<dt>交換先 (<code>resource</code>) が許可されていること</dt><dd>どの API がどの API を呼んでよいかは OP 側のポリシーで決めます (このデモでは API A → API B だけを許可)。</dd>
<dt>scope を広げないこと</dt><dd>新しいトークンの scope は subject_token の scope の範囲内に限られます。絞ることはできますが、広げることはできません。</dd>
<dt>有効期限を延ばさないこと</dt><dd>新しいトークンの <code>exp</code> は subject_token の <code>exp</code> を超えません。リフレッシュトークンも発行しません。</dd>
</dl>`,
)}</div>
${step(
  '⑪ API A → (Token Exchange) → API B',
  'API A が受け取ったトークンを API B 用に交換して呼ぶ',
  exchangeAtoB,
  200,
  '',
  `<p><code>token_exchange.issued_token_claims</code> が OP の発行した新しいトークンです。次の点に注目してください。</p>
<dl>
<dt>sub</dt><dd>alice のまま。API A は alice <b>として</b> ではなく、alice の <b>代わりに</b> 呼んでいます。</dd>
<dt>act (actor)</dt><dd>「実際に呼んでいるのは API A」という記録です (RFC 8693 §4.1)。API B は「alice 本人ではなく API A が代理で来た」とわかるので、
代理アクセスを拒否したり、監査ログに残したりできます。さらに API B が別の API を呼ぶと <code>act</code> が入れ子になり、代理の連鎖をたどれます。</dd>
<dt>aud / client_id</dt><dd>宛先は API B、トークンを受け取ったクライアントは API A です。</dd>
<dt>scope</dt><dd>元のトークンの <code>openid profile email</code> から、API B に必要な <code>profile</code> だけに絞っています。</dd>
<dt>exp</dt><dd>元のトークンの期限を超えません。</dd>
</dl>
<p>元のトークンは DPoP でクライアントの鍵に紐付いていましたが、新しいトークンは API A がシークレットで認証して受け取った Bearer トークンです。
API A も DPoP proof を付けて交換すれば、API A の鍵に紐付けることもできます。</p>`,
)}
${step(
  '⑫ API A が受け取ったトークンをそのまま API B に転送する (パススルー)',
  'トークンの <code>aud</code> は API A なので API B は拒否する',
  passthrough,
  502,
  '',
  `<p>交換をせずに、受け取ったトークンをそのまま API B に送った場合です。API B は <code>aud</code> が自分ではないので 401 を返し、
API A はクライアントに 502 を返しています。<code>aud</code> を API ごとに絞っておくことが、パススルーへの防御にもなっています。</p>`,
)}
${step(
  '⑬ 交換時に元のトークンに無い scope を要求する',
  '<code>scope=profile mcp:tools</code> → <code>invalid_scope</code>',
  escalate,
  502,
  '',
  `<p>元のトークンの scope は <code>openid profile email</code> で、ユーザーは <code>mcp:tools</code> に同意していません。
API A が交換を利用して権限を広げることはできないので、OP は <code>invalid_scope</code> で拒否します。</p>`,
)}
${step(
  '⑭ API B → (Token Exchange) → API A',
  'OP のポリシーで API B → API A は許可していないので <code>invalid_target</code>',
  exchangeBtoA,
  502,
  '',
  `<p>API B も OP に登録されたクライアントで、正しい API B 宛てのトークンを持っています。
しかし OP のポリシーでは API B に交換先を許可していないので、<code>invalid_target</code> になります。
どの API がどの API をユーザーの代わりに呼んでよいかは、各 API ではなく OP が一元的に管理します。</p>`,
)}
<a class="btn" href="/">トップへ</a>`,
  );
}

// Shows the pushed authorization request (RFC 9126) that started this flow.
function parCard(par, proofClaims) {
  const tampered = [...new URL(par.authorizeUrl).searchParams.keys()].some((k) => k !== 'client_id' && k !== 'request_uri');
  return `<div class="card"><h2>⓪ PAR: 認可リクエストを OP に直接送る (RFC 9126)</h2>
<p><code>POST ${esc(par.endpoint)}</code> ${statusBadge(par.status, 201)}</p>
${hint(
  '解説',
  `<p>ログインボタンを押したとき、このアプリはブラウザを OP に移動させる <b>前に</b>、認可リクエストの中身を
OP の <code>/par</code> に直接 POST しました。OP は client_id のメタデータ・redirect_uri・scope・resource・PKCE をここで検証し、
中身を預かって <code>request_uri</code> (使い捨ての参照番号) を返します。</p>
<p>ブラウザの URL に載るのは <code>client_id</code> と <code>request_uri</code> だけです。PAR を使わない場合と比べてみてください。</p>
<dl>
<dt>改ざんできない</dt><dd>URL に scope や redirect_uri を書き足しても、OP は POST された中身しか使いません。</dd>
<dt>漏れない</dt><dd>要求内容がブラウザの履歴やアクセスログに残りません。</dd>
<dt>先に検証できる</dt><dd>リクエストに誤りがあれば、ユーザーを OP に送る前に JSON のエラーで分かります。</dd>
<dt>URL の長さを気にしなくてよい</dt><dd>パラメーターが多くても POST の本文なので問題ありません (RAR の <code>authorization_details</code> などで効いてきます)。</dd>
</dl>
<p>このリクエストには DPoP proof も付けています。OP はその鍵の thumbprint (<code>dpop_jkt</code>) を認可コードに紐付けるので、
認可コードは ① で同じ鍵の proof を付けたときしかトークンに交換できません (RFC 9449 §10)。
PKCE と同じく「コードを要求した本人しか使えない」ようにする仕組みです。</p>`,
)}
<p>送ったパラメーター (本文):</p><pre>${json(par.request)}</pre>
${par.proof ? `<p>送った DPoP proof の中身:</p><pre>${json(proofClaims(par.proof))}</pre>` : ''}
<p>レスポンス:</p><pre>${json(par.body)}</pre>
<p>ブラウザが移動した URL:</p><pre>${esc(par.authorizeUrl)}</pre>
${tampered ? `<p class="err card">URL に <code>request_uri</code> 以外のパラメーターを書き足しましたが、OP の同意画面にも、発行されたトークンにも反映されていません (OP が無視した)。
アクセストークンの <code>aud</code> や <code>scope</code> が、上の「送ったパラメーター」どおりであることを確認してください。</p>` : ''}</div>`;
}

// --- MCP-style flow: start from nothing but the MCP server URL --------------
// MCP authorization spec: 401 + WWW-Authenticate -> Protected Resource Metadata (RFC 9728)
// -> Authorization Server Metadata (RFC 8414) -> authorize with CIMD + PKCE + resource (RFC 8707).
const MCP_SERVERS = [`${API_A}/mcp`, `${API_B}/mcp`];
const MCP_PROTOCOL_VERSION = '2025-06-18';
const MCP_INITIALIZE = {
  method: 'initialize',
  params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: metadata.client_name, version: '0.1.0' } },
};

// Parses the auth-params of `Bearer k="v", k2="v2"`.
function parseChallenge(header) {
  const params = {};
  for (const [, k, v] of (header || '').matchAll(/(\w+)="([^"]*)"/g)) params[k] = v;
  return params;
}

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'error' });
  return { status: r.status, body: r.ok ? await r.json() : null };
}

async function mcpPost(endpoint, accessToken, message) {
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      ...(accessToken && { authorization: `Bearer ${accessToken}` }),
    },
    body: JSON.stringify({ jsonrpc: '2.0', ...message }),
  });
  const text = await r.text();
  return { status: r.status, wwwAuthenticate: r.headers.get('www-authenticate'), body: text ? JSON.parse(text) : null };
}

// The resource identifier must be the endpoint itself or a parent of it (same origin, path prefix).
function resourceCovers(resource, endpoint) {
  try {
    const r = new URL(resource);
    const e = new URL(endpoint);
    const base = r.pathname.replace(/\/$/, '');
    return r.origin === e.origin && (e.pathname === base || e.pathname.startsWith(`${base}/`));
  } catch {
    return false;
  }
}

// RFC 8414 §3.1 inserts the well-known segment before the issuer's path; OIDC discovery appends it.
function asMetadataUrls(issuer) {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/$/, '');
  return [`${u.origin}/.well-known/oauth-authorization-server${path}`, `${u.origin}${path}/.well-known/openid-configuration`];
}

// Each step is recorded so the result page can show how the client found its way to the OP.
async function discoverMcpAuthorization(endpoint) {
  const trace = [];
  const fail = (message) => Object.assign(new Error(message), { trace });

  // 1) Call the MCP server without a token. It answers 401 and points at its resource metadata.
  const r0 = await mcpPost(endpoint, null, { id: 0, ...MCP_INITIALIZE });
  trace.push({ title: 'MCP サーバーにトークン無しでアクセス', req: `POST ${endpoint}`, status: r0.status, body: { 'www-authenticate': r0.wwwAuthenticate, body: r0.body },
    hint: `<p>クライアントはまだトークンを持っていないので、MCP サーバーは <code>401 Unauthorized</code> を返します。
そのとき <code>WWW-Authenticate</code> ヘッダーの <code>resource_metadata</code> で「認可について書いた説明書はここ」と教えてくれます。
<code>scope</code> は、このサーバーを使うのに必要な権限です。</p>` });
  if (r0.status !== 401) throw fail(`expected 401 from the MCP server, got ${r0.status}`);
  const challenge = parseChallenge(r0.wwwAuthenticate);

  // 2) RFC 9728: Protected Resource Metadata (fall back to the well-known URI if not advertised).
  const prmUrl = challenge.resource_metadata || `${new URL(endpoint).origin}/.well-known/oauth-protected-resource`;
  const prm = await getJson(prmUrl);
  trace.push({ title: 'Protected Resource Metadata を取得 (RFC 9728)', req: `GET ${prmUrl}`, status: prm.status, body: prm.body,
    hint: `<p>Protected Resource Metadata は API (リソースサーバー) の自己紹介です。</p>
<dl><dt>resource</dt><dd>この API の識別子。トークンを要求するときの <code>resource</code> に使います。</dd>
<dt>authorization_servers</dt><dd>この API が信頼する認可サーバー (OP)。ここでトークンをもらえばよいとわかります。</dd>
<dt>scopes_supported</dt><dd>この API で使える scope。</dd></dl>
<p>クライアントは <code>resource</code> が接続先の URL と一致するか確認します。偽のサーバーが「別の API 用のトークンを取ってこい」と
誘導して、そのトークンを盗むのを防ぐためです。</p>` });
  if (prm.status !== 200) throw fail('could not fetch protected resource metadata');
  const { resource, authorization_servers: authServers = [], scopes_supported: scopes = [] } = prm.body;
  // Otherwise a malicious server could make us obtain (and send it) a token for some other resource.
  if (!resourceCovers(resource, endpoint)) throw fail(`resource "${resource}" does not match the MCP server ${endpoint}`);
  const issuer = authServers[0];
  if (!issuer) throw fail('protected resource metadata has no authorization_servers');

  // 3) RFC 8414 Authorization Server Metadata, then OpenID Connect discovery as a fallback.
  let as;
  for (const url of asMetadataUrls(issuer)) {
    const r = await getJson(url);
    trace.push({ title: '認可サーバーのメタデータを取得 (RFC 8414)', req: `GET ${url}`, status: r.status, body: r.body,
      hint: `<p>認可サーバーの自己紹介です (OIDC の discovery と同じ形式)。ログイン画面 (<code>authorization_endpoint</code>) や
トークン発行 (<code>token_endpoint</code>) の URL がわかります。</p>
<p>クライアントはさらに、<code>issuer</code> が期待どおりか、PKCE (<code>S256</code>) に対応しているか、
CIMD に対応しているか (<code>client_id_metadata_document_supported</code>) を確認します。
CIMD に対応していれば、事前登録なしでメタデータ URL を client_id として使えます。</p>` });
    if (r.status === 200) {
      as = r.body;
      break;
    }
  }
  if (!as) throw fail(`could not fetch authorization server metadata for ${issuer}`);
  if (as.issuer !== issuer) throw fail(`issuer in metadata ("${as.issuer}") does not match "${issuer}"`);
  if (!as.code_challenge_methods_supported?.includes('S256')) throw fail('authorization server does not support PKCE S256');
  if (!as.client_id_metadata_document_supported) {
    // A real MCP client would fall back to Dynamic Client Registration or a pre-registered client_id here.
    throw fail('authorization server does not support Client ID Metadata Documents');
  }

  // Prefer the scope from the challenge, then everything the resource says it supports.
  const scope = challenge.scope || scopes.join(' ');
  return { trace, resource, as, scope };
}

async function handleMcpLogin(res, endpoint) {
  // Only known servers: this client should not be a proxy that fetches arbitrary URLs.
  if (!MCP_SERVERS.includes(endpoint)) {
    return html(res, `<div class="card err"><h1>不明な MCP サーバーです</h1><a href="/">戻る</a></div>`, 400);
  }
  let d;
  try {
    d = await discoverMcpAuthorization(endpoint);
  } catch (e) {
    if (!e.trace) throw e;
    log(`MCP discovery failed: ${e.message}`);
    return html(res, `<div class="card err"><h1>認可サーバーの発見に失敗</h1><p>${esc(e.message)}</p></div>${traceCards(e.trace)}`, 400);
  }
  log(`MCP discovery: ${endpoint} -> resource=${d.resource}, as=${d.as.issuer}, scope="${d.scope}"`);
  // Same CIMD client_id as the OIDC flow: the OP has never seen this client, and does not need to.
  const q = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: d.scope, resource: d.resource });
  // This client requires PAR for itself (see its metadata), so it pushes the request whenever the AS offers PAR.
  // No DPoP key here: the MCP authorization spec uses Bearer tokens.
  await redirectToAuthorize(res, d.as, q, { clientId: CLIENT_ID, redirectUri: REDIRECT_URI, mcp: { endpoint, ...d } }, 'mcp', {
    par: Boolean(d.as.pushed_authorization_request_endpoint),
  });
}

const traceCards = (trace, start = 1) =>
  trace
    .map(
      (t, i) => `<div class="card"><h2>${start + i}. ${esc(t.title)}</h2><p><code>${esc(t.req)}</code>
${t.expected === undefined ? `<b>HTTP ${esc(t.status)}</b>` : statusBadge(t.status, t.expected)}</p>
${t.note ? `<p>${t.note}</p>` : ''}${t.hint ? hint('解説', t.hint) : ''}<pre>${json(t.body)}</pre></div>`,
    )
    .join('');

const statusBadge = (status, expected) =>
  `<b style="color:${status === expected ? '#276749' : '#c53030'}">HTTP ${esc(status)}</b> (期待値 ${esc(expected)})`;

async function handleMcpCallback(res, params, flow, as) {
  const { endpoint, resource, trace } = flow.mcp;

  // 4) Code exchange, again with resource so the token is bound to this MCP server only.
  const t = await requestToken(as, [
    ['grant_type', 'authorization_code'],
    ['code', params.get('code')],
    ['redirect_uri', flow.redirectUri],
    ['client_id', flow.clientId],
    ['code_verifier', flow.verifier],
    ['resource', resource],
  ]);
  const at = t.body.access_token;
  const steps = [];
  if (flow.par) {
    steps.push({
      title: '認可リクエストを PAR で送る (RFC 9126)',
      req: `POST ${flow.par.endpoint}`,
      status: flow.par.status,
      expected: 201,
      note: `ブラウザが移動した URL: <code>${esc(flow.par.authorizeUrl)}</code>`,
      hint: `<p>認可サーバーのメタデータに <code>pushed_authorization_request_endpoint</code> があったので、
認可リクエストの中身 (scope・resource・PKCE など) を先に OP へ直接 POST し、<code>request_uri</code> を受け取りました。
ブラウザの URL には <code>client_id</code> と <code>request_uri</code> だけが載ります。</p>
<p>このクライアントは CIMD のメタデータに <code>require_pushed_authorization_requests: true</code> と書いているので、
PAR を使わないリクエストは OP に拒否されます。</p>`,
      body: { request: flow.par.request, response: flow.par.body },
    });
  }
  steps.push(
    {
      title: 'トークンリクエスト (CIMD client_id + PKCE + resource)',
      req: `POST ${as.token_endpoint}  resource=${resource}`,
      status: t.status,
      expected: 200,
      note: 'scope に <code>openid</code> が無いので ID トークンは発行されない (MCP は OIDC ではなく OAuth)',
      hint: `<p>ユーザーが同意画面で許可した後、認可コードをトークンに交換します。<code>resource</code> に MCP サーバーの識別子を指定するので、
アクセストークンの <code>aud</code> はこの MCP サーバーだけになります。</p>
<p>MCP サーバーが知りたいのは「誰が何をしてよいか」だけなので、OAuth のアクセストークンだけで十分です。
「ログインしたのは誰か」をアプリが知る必要は無いので、ID トークン (OIDC) は使いません。</p>`,
      body: at ? { access_token_claims: decodeJwt(at).payload, response: t.body } : t.body,
    },
  );
  if (!at) return html(res, `<div class="card err"><h1>トークンリクエスト失敗</h1></div>${traceCards([...trace, ...steps])}`, 400);

  // 5) Talk MCP with the token.
  const init = await mcpPost(endpoint, at, { id: 1, ...MCP_INITIALIZE });
  await mcpPost(endpoint, at, { method: 'notifications/initialized' });
  const list = await mcpPost(endpoint, at, { id: 2, method: 'tools/list' });
  const call = await mcpPost(endpoint, at, { id: 3, method: 'tools/call', params: { name: 'whoami', arguments: {} } });
  steps.push(
    {
      title: 'MCP initialize',
      req: `POST ${endpoint}`,
      status: init.status,
      expected: 200,
      body: init.body,
      hint: `<p>MCP のメッセージは JSON-RPC 形式です。最初に <code>initialize</code> でプロトコルのバージョンや機能をすり合わせます。
以降のリクエストにはすべて <code>Authorization: Bearer &lt;アクセストークン&gt;</code> ヘッダーを付けています。</p>`,
    },
    {
      title: 'MCP tools/list',
      req: `POST ${endpoint}`,
      status: list.status,
      expected: 200,
      body: list.body,
      hint: '<p>サーバーが提供するツールの一覧を取得します。AI アプリはこの一覧を見て、どのツールを使うか決めます。</p>',
    },
    {
      title: 'MCP tools/call whoami',
      req: `POST ${endpoint}`,
      status: call.status,
      expected: 200,
      body: call.body,
      hint: '<p>ツールを実行します。<code>whoami</code> はアクセストークンの中身から「誰が・どのクライアント経由で」呼んだかを返します。</p>',
    },
  );

  // 6) The same token must not work at the other MCP server (audience mismatch).
  const other = MCP_SERVERS.find((s) => s !== endpoint);
  const cross = await mcpPost(other, at, { id: 1, ...MCP_INITIALIZE });
  steps.push({
    title: '同じトークンを別の MCP サーバーに送る',
    req: `POST ${other}`,
    status: cross.status,
    expected: 401,
    note: 'トークンの <code>aud</code> は最初の MCP サーバーだけなので拒否される (トークンのパススルー防止)',
    hint: `<p>MCP サーバーがもらったトークンをそのまま別のサーバーに転送する「トークンパススルー」は、MCP の仕様で禁止されています。
<code>aud</code> を接続先ごとに絞っておけば、仮に転送されても受け取った側が拒否するので安全です。</p>`,
    body: { 'www-authenticate': cross.wwwAuthenticate, body: cross.body },
  });

  log(`MCP flow succeeded for ${endpoint}`);
  html(
    res,
    `<div class="card"><h1 class="ok">MCP サーバーに接続しました: ${esc(endpoint)}</h1>
<p>クライアントが最初に知っていたのは MCP サーバーの URL だけです。認可サーバー・resource・scope は
<code>WWW-Authenticate</code> → RFC 9728 → RFC 8414 の順にたどって発見し、OP への事前登録もしていません (CIMD)。</p></div>
${traceCards([...trace, ...steps])}
<a class="btn" href="/">トップへ</a>`,
  );
}

function handleIndex(res) {
  html(
    res,
    `<div class="card"><h1>OIDC × Client ID Metadata Document デモ</h1>
${hint(
  'はじめに: このデモの登場人物',
  `<dl>
<dt>ユーザー (あなた = alice)</dt><dd>ログインする人です。</dd>
<dt>クライアント / RP (このページ, <code>${esc(BASE)}</code>)</dt>
<dd>ユーザーにログインしてもらいたいアプリです。OP の判定を「信頼する (rely)」側なので Relying Party (RP) とも呼びます。</dd>
<dt>OP / 認可サーバー (<code>${esc(ISSUER)}</code>)</dt>
<dd>ID とパスワードを確認して「この人は alice です」と証明するサーバーです。
「Google でログイン」の Google 側にあたります。OAuth の文脈では「認可サーバー (Authorization Server)」と呼ばれます。</dd>
<dt>API A / API B (リソースサーバー, <code>${esc(API_A)}</code> / <code>${esc(API_B)}</code>)</dt>
<dd>正しいアクセストークンを見せたときだけデータを返す API です。</dd>
</dl>`,
  true,
)}
${hint(
  'OAuth と OpenID Connect (OIDC) の違い',
  `<dl>
<dt>OAuth 2.0 = 認可 (何をしてよいか)</dt>
<dd>「このアプリが私の代わりに API を使ってよい」という許可を出す仕組みです。
結果として <b>アクセストークン</b> (API に入るための入館証) がもらえます。</dd>
<dt>OpenID Connect = 認証 (誰なのか)</dt>
<dd>OAuth の上に「ログインしたのは誰か」を伝える仕組みを足したものです。
結果として <b>ID トークン</b> (OP が署名した身分証明書) がもらえます。
scope に <code>openid</code> を含めると OIDC のリクエストになります。</dd>
</dl>`,
)}
${hint(
  'Client ID Metadata Document (CIMD) とは?',
  `<p>ふつう OIDC を使うアプリは、事前に OP の管理画面で「アプリ名・戻り先 URL」などを登録し、
<code>client_id</code> を発行してもらう必要があります。</p>
<p>CIMD では逆に、アプリが <b>自分の情報を書いた JSON を自分のサイトで公開し、その URL を client_id として名乗ります</b>。
OP は初めて見るアプリでも、その URL を取りに行けば名前・ロゴ・戻り先がわかります。</p>
<p>MCP クライアントのように「たくさんの見知らぬサーバーに接続するアプリ」でも、サーバーごとに事前登録をしなくて済むのが利点です。</p>`,
)}
<p>このクライアントは OP に事前登録されていません。<br>
client_id = <code><a href="/client-metadata.json">${esc(CLIENT_ID)}</a></code></p>
<p><a class="btn" href="/login">OP でログイン</a></p>
<p>認可リクエストは PAR (RFC 9126) で OP に直接送り、ブラウザの URL には <code>request_uri</code> だけを載せます。
ログイン後、Resource Indicators (RFC 8707) で API ごとに <code>aud</code> を絞ったアクセストークンを取得し、
<code>${esc(API_A)}</code> / <code>${esc(API_B)}</code> を呼び分けます。
トークンは DPoP (RFC 9449) でこのアプリの鍵に紐付け、盗まれたトークンが使えないことも確認します。
最後に、API A がユーザーの代わりに API B を呼ぶ Token Exchange (RFC 8693) も試します。</p>
${hint(
  'ボタンを押すと何が起きる? (認可コードフロー)',
  `<ol>
<li>ブラウザが OP の <code>/authorize</code> に移動します。URL には <code>client_id</code>・<code>redirect_uri</code> (戻り先)・
<code>scope</code> (欲しい情報や権限)・<code>state</code>・<code>nonce</code>・PKCE の <code>code_challenge</code>・<code>resource</code> (使いたい API) が付きます。</li>
<li>OP は client_id の URL からメタデータ JSON を取得し、正しい内容か検証します。</li>
<li>OP の画面でログインし、「許可」を押します (同意)。</li>
<li>OP はブラウザを <code>redirect_uri</code> (このアプリの <code>/callback</code>) に戻します。URL には一度しか使えない短命な <b>認可コード</b> が付いています。</li>
<li>クライアントはサーバー同士の通信で、認可コードを OP の <code>/token</code> に送り、トークンと交換します。</li>
<li>クライアントは ID トークンの署名などを検証し、ログイン完了です。</li>
</ol>
<p><b>なぜいきなりトークンを返さないの?</b> ブラウザの URL は履歴やログに残りやすく、盗まれる危険があります。
そこで URL には使い捨てのコードだけを載せ、トークン本体は裏側の通信で受け取ります。</p>
<dl>
<dt>state</dt><dd>ログイン開始時に作る乱数。戻ってきたとき一致するか確かめ、他人が仕掛けたログイン (CSRF) を防ぎます。</dd>
<dt>nonce</dt><dd>ID トークンの中に埋め込まれて返ってくる乱数。古い ID トークンの使い回し (リプレイ) を防ぎます。</dd>
<dt>PKCE (code_verifier / code_challenge)</dt>
<dd>開始時に秘密の乱数 (verifier) を作り、そのハッシュ (challenge) だけを OP に送ります。コード交換時に verifier 本体を見せることで、
「コードを要求した本人」であることを証明します。途中でコードを盗まれても、verifier が無いのでトークンに交換できません。</dd>
</dl>`,
)}</div>
<div class="card"><h1>MCP 風フロー (RFC 9728 + CIMD)</h1>
<p>MCP サーバーの URL だけを手がかりに、認可サーバーを自動で発見して接続します。</p><ul>
${MCP_SERVERS.map((s) => `<li><a href="/mcp-login?server=${encodeURIComponent(s)}">${esc(s)} に接続</a></li>`).join('')}
</ul>
${hint(
  'MCP とは? なぜ「発見」が必要?',
  `<p>MCP (Model Context Protocol) は、Claude などの AI アプリが外部のツールやデータにつながるためのプロトコルです。
MCP サーバーの認可には OAuth が使われます。</p>
<p>MCP クライアントは、ユーザーが追加した任意の MCP サーバーに接続します。そのため
「このサーバーはどの認可サーバーのトークンを受け付けるのか」を事前に知りません。そこで次の順にたどって自動で調べます。</p>
<ol>
<li>トークン無しでアクセス → <code>401</code> と一緒に <code>WWW-Authenticate</code> ヘッダーで「説明書 (メタデータ) の場所」を教えてもらう</li>
<li>Protected Resource Metadata (RFC 9728) を読み、認可サーバーの URL を知る</li>
<li>認可サーバーのメタデータ (RFC 8414) を読み、ログイン画面やトークン発行の URL を知る</li>
<li>CIMD の client_id で認可 → 事前登録なしでトークンを取得</li>
</ol>`,
)}</div>
<div class="card"><h1>Client ID Metadata Document</h1>
<p>このアプリの「自己紹介」です。OP はこの JSON を client_id の URL から取得します。</p><pre>${json(metadata)}</pre>
${hint(
  '各項目の意味',
  `<dl>
<dt>client_id</dt><dd>このドキュメント自身の URL。OP は「取得した URL と中身の client_id が完全に一致するか」を確認します。
一致しないと、他人のアプリになりすませてしまうからです。</dd>
<dt>client_name / logo_uri / client_uri</dt><dd>OP の同意画面に表示されるアプリ名・ロゴ・ホームページです。</dd>
<dt>redirect_uris</dt><dd>ログイン後に戻ってよい URL の一覧。OP はここに無い URL へは決してリダイレクトしません。
攻撃者のサイトに認可コードが送られるのを防ぐ、最重要の項目です。</dd>
<dt>grant_types / response_types</dt><dd>認可コードフロー (<code>authorization_code</code> / <code>code</code>) を使うという宣言です。</dd>
<dt>token_endpoint_auth_method: none</dt><dd>クライアントシークレット (アプリのパスワード) を使わない「公開クライアント」であることを示します。
この JSON は誰でも読めるので、秘密は書けません。代わりに PKCE で安全性を確保します。</dd>
<dt>scope</dt><dd>このアプリが要求する可能性のある権限の一覧です。</dd>
<dt>require_pushed_authorization_requests: true</dt><dd>このアプリは必ず PAR (RFC 9126) で認可リクエストを送る、という宣言です。
OP は、このアプリの client_id でブラウザの URL から直接届いた認可リクエストを拒否します。
攻撃者が URL を組み立てて、このアプリになりすましたリクエストをユーザーに踏ませることも難しくなります。</dd>
</dl>`,
)}</div>
<div class="card"><h1>失敗パターンを試す</h1><ul>
<li><a href="/login?variant=unregistered-redirect">メタデータに無い redirect_uri を使う</a></li>
<li><a href="/login?variant=mismatched-client-id">ドキュメント内の client_id が URL と一致しない</a>
 (<a href="/mismatched-metadata.json">doc</a>)</li>
<li><a href="/login?variant=missing-document">ドキュメントが存在しない (404)</a></li>
<li><a href="/login?variant=no-path">パスの無い client_id URL</a></li>
<li><a href="/login?variant=unknown-resource">OP が知らない resource を要求する</a></li>
</ul>
${hint(
  'それぞれ何を防いでいる?',
  `<dl>
<dt>メタデータに無い redirect_uri</dt><dd>攻撃者が戻り先を自分のサイトに書き換えて、認可コードを盗むのを防ぎます。</dd>
<dt>client_id が URL と一致しない</dt><dd>攻撃者が自分のサーバーに「私は有名アプリです」と書いた JSON を置いて、なりすますのを防ぎます。</dd>
<dt>ドキュメントが存在しない</dt><dd>正体を確認できないアプリは受け付けません。</dd>
<dt>パスの無い client_id URL</dt><dd>仕様で、client_id の URL にはパス (<code>/client-metadata.json</code> など) が必須と決められています。</dd>
<dt>OP が知らない resource</dt><dd>OP が管理していない API 向けのトークンは発行しません。</dd>
</dl>
<p>最初の 4 つは OP の動きを見るため、あえて PAR を使わずブラウザの URL で送っています。OP の画面でエラーになり、クライアントには戻りません。
戻り先 (redirect_uri) が信用できるとまだ確認できていないので、そこへエラーを送るのも危険だからです。</p>
<p>最後の 1 つは PAR で送っているので、ブラウザを OP に移動させる前に <code>invalid_target</code> が JSON で直接クライアントに返されます。</p>`,
)}</div>
<div class="card"><h1>PAR (RFC 9126) の動きを試す</h1><ul>
<li><a href="/login?variant=no-par">PAR を使わずに、従来どおり URL で認可リクエストを送る</a></li>
<li><a href="/login?variant=par-tampered">PAR の後、ブラウザの URL に scope・resource・redirect_uri を書き足す</a></li>
<li><a href="/login?variant=par-replay">request_uri を他の誰かが先に使う (再利用)</a></li>
<li><a href="/login?variant=par-client-mismatch">request_uri を別の client_id と組み合わせる</a></li>
</ul>
${hint(
  'それぞれ何が起きる?',
  `<dl>
<dt>PAR を使わない</dt><dd>URL に全パラメーターが並びます (OP に移動したらアドレスバーを見てください)。
このアプリはメタデータで PAR を必須にしているので、OP は <code>error=invalid_request</code> でクライアントに返します。</dd>
<dt>URL に書き足す</dt><dd>OP は <code>request_uri</code> が指す POST 済みの中身しか使わないので、書き足した値は無視されます。
同意画面に「無視しました」と表示され、ログインはそのまま成功します。発行されたトークンの scope や aud を確認してください。</dd>
<dt>request_uri の再利用</dt><dd><code>request_uri</code> は 1 回しか使えません。ここではクライアントが先に一度使ってからブラウザを送るので、OP はエラー画面を表示します。</dd>
<dt>別の client_id と組み合わせる</dt><dd><code>request_uri</code> は PAR を送ったクライアントに紐付いています。他のクライアントを名乗って使うことはできません。</dd>
</dl>
<p>「失敗パターンを試す」の <b>OP が知らない resource を要求する</b> も PAR で送っています。エラーが JSON で直接クライアントに返る様子が見られます。</p>`,
)}</div>
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
      case 'GET /mcp-login':
        return await handleMcpLogin(res, url.searchParams.get('server'));
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
