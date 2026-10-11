// Minimal resource server (API + MCP server) that only accepts access tokens whose `aud` is its own
// resource identifier (RFC 8707 / RFC 9068), and advertises its authorization server via
// OAuth 2.0 Protected Resource Metadata (RFC 9728), as the MCP authorization spec requires.
// No dependencies (Node.js 22+).
const http = require('node:http');
const crypto = require('node:crypto');
const dpop = require('../lib/dpop.js');

const PORT = Number(process.env.PORT || 5000);
const RESOURCE = process.env.RESOURCE || `http://localhost:${PORT}`; // this API's resource identifier
const NAME = process.env.NAME || 'API';
const ISSUER = process.env.ISSUER || 'http://localhost:3000';
const MCP_SCOPE = 'mcp:tools';
// RFC 8693: this API is also a confidential client of the OP, so that it can exchange the tokens it receives
// for tokens to the downstream API it calls on the user's behalf. Its client_id is its resource identifier.
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const DOWNSTREAM = process.env.DOWNSTREAM;
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
// RFC 9728 §3.1: for a resource without a path, the metadata lives at the root well-known URI.
const RESOURCE_METADATA_URL = `${RESOURCE}/.well-known/oauth-protected-resource`;

const log = (...a) => console.log(`[${NAME}] ${new Date().toISOString()}`, ...a);

let asMetadata;
async function getAsMetadata() {
  asMetadata ??= await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
  return asMetadata;
}

let jwksCache;
async function getKey(kid) {
  if (!jwksCache?.some((k) => k.kid === kid)) {
    jwksCache = (await (await fetch((await getAsMetadata()).jwks_uri)).json()).keys;
  }
  const jwk = jwksCache.find((k) => k.kid === kid);
  if (!jwk) throw new Error('signing key not found');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function verifyAccessToken(token) {
  const [h, p, s] = token.split('.');
  if (!s) throw new Error('malformed token');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  if (header.alg !== 'RS256' || header.typ !== 'at+jwt') throw new Error('not an RS256 at+jwt access token');
  if (!crypto.verify('sha256', Buffer.from(`${h}.${p}`), await getKey(header.kid), Buffer.from(s, 'base64url'))) {
    throw new Error('invalid signature');
  }
  if (payload.iss !== ISSUER) throw new Error('iss mismatch');
  if (payload.exp * 1000 < Date.now()) throw new Error('token expired');
  // The crucial check: a token meant for another API must be rejected here.
  const aud = [].concat(payload.aud);
  if (!aud.includes(RESOURCE)) throw new Error(`audience ${JSON.stringify(payload.aud)} does not include ${RESOURCE}`);
  return payload;
}

// RFC 9449 §7: a DPoP-bound token (cnf.jkt) is only usable with a fresh proof signed by that same key.
// Errors carry the code and scheme for the WWW-Authenticate challenge.
const dpopError = (error, message) => Object.assign(new Error(message), { error, scheme: 'DPoP' });
function checkTokenBinding(req, scheme, token, at) {
  const jkt = at.cnf?.jkt;
  if (!jkt) {
    if (scheme === 'DPoP') throw dpopError('invalid_token', 'access token is not DPoP-bound');
    return;
  }
  // Otherwise anyone holding a copy of the token could use it as a plain bearer token.
  if (scheme !== 'DPoP') throw dpopError('invalid_token', 'DPoP-bound access token must be sent with the DPoP scheme, not Bearer');
  let proofJkt;
  try {
    const { pathname } = new URL(req.url, RESOURCE);
    proofJkt = dpop.verifyDpopProof(req.headers.dpop, { htm: req.method, htu: `${RESOURCE}${pathname}`, accessToken: token });
  } catch (e) {
    throw dpopError('invalid_dpop_proof', e.message);
  }
  if (proofJkt !== jkt) throw dpopError('invalid_dpop_proof', 'DPoP proof is signed by a different key than the token is bound to');
}

// RFC 9728 §5.1: tell the client where to find this resource's metadata (and thus its authorization server).
function challenge(params, scheme = 'Bearer') {
  const all = { ...params, resource_metadata: RESOURCE_METADATA_URL, ...(scheme === 'DPoP' && { algs: dpop.SUPPORTED_ALGS.join(' ') }) };
  return `${scheme} ${Object.entries(all)
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, "'")}"`)
    .join(', ')}`;
}

const sendJson = (res, status, obj, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(obj, null, 2));
};

// Returns the verified token payload, or sends 401/403 and returns undefined.
async function authorize(req, res, requiredScope) {
  const m = /^(Bearer|DPoP) (.+)$/.exec(req.headers.authorization || '');
  if (!m) {
    log('401 no token -> pointing client to protected resource metadata');
    // RFC 6750 §3.1: no error code when the request simply lacked credentials.
    sendJson(res, 401, { error: 'unauthorized' }, { 'www-authenticate': challenge({ ...(requiredScope && { scope: requiredScope }) }) });
    return;
  }
  let at;
  const [, scheme, token] = m;
  try {
    at = await verifyAccessToken(token);
    checkTokenBinding(req, scheme, token, at);
  } catch (e) {
    const error = e.error || 'invalid_token';
    log(`401 ${error}: ${e.message}`);
    sendJson(
      res,
      401,
      { error, error_description: e.message },
      { 'www-authenticate': challenge({ error, error_description: e.message }, e.scheme) },
    );
    return;
  }
  if (requiredScope && !at.scope?.split(' ').includes(requiredScope)) {
    log(`403 insufficient_scope (have "${at.scope}")`);
    sendJson(
      res,
      403,
      { error: 'insufficient_scope', error_description: `scope "${requiredScope}" is required` },
      { 'www-authenticate': challenge({ error: 'insufficient_scope', scope: requiredScope }) },
    );
    return;
  }
  return at;
}

// --- RFC 8693: call the downstream API on the user's behalf -----------------
const decodePayload = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));

async function exchangeToken(subjectToken, { resource, scope }) {
  const { token_endpoint } = await getAsMetadata();
  const params = {
    grant_type: TOKEN_EXCHANGE_GRANT,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TYPE,
    resource,
    scope,
  };
  // client_secret_basic: form-urlencode, then base64 (the client_id contains ":").
  const basic = Buffer.from(`${encodeURIComponent(RESOURCE)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64');
  const r = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${basic}` },
    body: new URLSearchParams(params),
  });
  const body = await r.json();
  // Returned for the demo page, with the secrets left out.
  return {
    request: {
      endpoint: `POST ${token_endpoint}`,
      authorization: `Basic (client_id=${RESOURCE}, client_secret=***)`,
      params: { ...params, subject_token: `${subjectToken.slice(0, 16)}...` },
    },
    status: r.status,
    response: body,
    ...(body.access_token && { issued_token_claims: decodePayload(body.access_token) }),
  };
}

// mode: "exchange" (the right way), "passthrough" (forward the received token as is: must fail),
// "escalate" (ask for a scope the user never granted: must fail).
async function callDownstream(subjectToken, mode) {
  const url = `${DOWNSTREAM}/api/data`;
  const result = { mode };
  let token = subjectToken;
  if (mode !== 'passthrough') {
    // Ask only for what the downstream call needs ("profile"), narrowing the received token's scope.
    const scope = mode === 'escalate' ? `profile ${MCP_SCOPE}` : 'profile';
    result.token_exchange = await exchangeToken(subjectToken, { resource: DOWNSTREAM, scope });
    if (result.token_exchange.status !== 200) return result;
    token = result.token_exchange.response.access_token;
  }
  const r = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  const body = await r.json();
  result.downstream = {
    request: `GET ${url}`,
    status: r.status,
    body: r.ok ? body : { 'www-authenticate': r.headers.get('www-authenticate'), body },
  };
  return result;
}

// --- Minimal MCP server (Streamable HTTP transport, JSON responses only) ----
const MCP_TOOLS = [
  {
    name: 'whoami',
    description: `Returns who is calling ${NAME}, based on the access token`,
    inputSchema: { type: 'object', properties: {} },
  },
];

function handleMcpMessage(msg, at) {
  const result = (r) => ({ jsonrpc: '2.0', id: msg.id, result: r });
  switch (msg.method) {
    case 'initialize':
      return result({
        protocolVersion: '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: `${NAME}-mcp`, version: '0.1.0' },
      });
    case 'tools/list':
      return result({ tools: MCP_TOOLS });
    case 'tools/call':
      if (msg.params?.name !== 'whoami') {
        return { jsonrpc: '2.0', id: msg.id, error: { code: -32602, message: `unknown tool: ${msg.params?.name}` } };
      }
      return result({
        content: [{ type: 'text', text: `You are ${at.sub}, calling ${NAME} (${RESOURCE}) via client ${at.client_id}` }],
      });
    default:
      return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } };
  }
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

http
  .createServer(async (req, res) => {
    const route = `${req.method} ${new URL(req.url, RESOURCE).pathname}`;
    try {
      switch (route) {
        // RFC 9728: public, unauthenticated metadata about this protected resource.
        case 'GET /.well-known/oauth-protected-resource':
          log('protected resource metadata requested');
          return sendJson(
            res,
            200,
            {
              resource: RESOURCE,
              authorization_servers: [ISSUER],
              scopes_supported: [MCP_SCOPE],
              bearer_methods_supported: ['header'],
              // RFC 9728 / RFC 9449: DPoP-bound tokens are accepted (and checked), but Bearer is still allowed.
              dpop_signing_alg_values_supported: dpop.SUPPORTED_ALGS,
              dpop_bound_access_tokens_required: false,
              resource_name: `${NAME} (demo MCP server)`,
            },
            { 'cache-control': 'max-age=60' },
          );

        case 'GET /api/data': {
          const at = await authorize(req, res);
          if (!at) return;
          log(`200 sub=${at.sub} client_id=${at.client_id}${at.act ? ` act=${JSON.stringify(at.act)}` : ''}`);
          return sendJson(res, 200, {
            api: NAME,
            resource: RESOURCE,
            message: `Hello ${at.sub} from ${NAME}`,
            client_id: at.client_id,
            ...(at.act && { act: at.act }), // RFC 8693: called by another API on the user's behalf
          });
        }

        // Calls DOWNSTREAM on behalf of the user who called this API (RFC 8693 token exchange).
        case 'GET /api/downstream': {
          const at = await authorize(req, res);
          if (!at) return;
          const token = /^(?:Bearer|DPoP) (.+)$/.exec(req.headers.authorization)[1];
          const mode = new URL(req.url, RESOURCE).searchParams.get('mode') || 'exchange';
          const result = await callDownstream(token, mode);
          const ok = result.downstream?.status === 200;
          log(`downstream (${mode}) -> ${ok ? 'OK' : 'failed'}`);
          return sendJson(res, ok ? 200 : 502, { api: NAME, ...result });
        }

        case 'POST /mcp': {
          const at = await authorize(req, res, MCP_SCOPE);
          if (!at) return;
          const msg = await readJson(req);
          // Notifications (no id) get no JSON-RPC response.
          if (msg.id === undefined) return res.writeHead(202).end();
          log(`mcp ${msg.method} sub=${at.sub}`);
          return sendJson(res, 200, handleMcpMessage(msg, at));
        }

        default:
          return sendJson(res, 404, { error: 'not_found' });
      }
    } catch (e) {
      console.error(e);
      sendJson(res, 500, { error: 'server_error' });
    }
  })
  .listen(PORT, () => log(`listening on ${RESOURCE}`));
