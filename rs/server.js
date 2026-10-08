// Minimal resource server (API + MCP server) that only accepts access tokens whose `aud` is its own
// resource identifier (RFC 8707 / RFC 9068), and advertises its authorization server via
// OAuth 2.0 Protected Resource Metadata (RFC 9728), as the MCP authorization spec requires.
// No dependencies (Node.js 22+).
const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 5000);
const RESOURCE = process.env.RESOURCE || `http://localhost:${PORT}`; // this API's resource identifier
const NAME = process.env.NAME || 'API';
const ISSUER = process.env.ISSUER || 'http://localhost:3000';
const MCP_SCOPE = 'mcp:tools';
// RFC 9728 §3.1: for a resource without a path, the metadata lives at the root well-known URI.
const RESOURCE_METADATA_URL = `${RESOURCE}/.well-known/oauth-protected-resource`;

const log = (...a) => console.log(`[${NAME}] ${new Date().toISOString()}`, ...a);

let jwksCache;
async function getKey(kid) {
  if (!jwksCache?.some((k) => k.kid === kid)) {
    const op = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
    jwksCache = (await (await fetch(op.jwks_uri)).json()).keys;
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

// RFC 9728 §5.1: tell the client where to find this resource's metadata (and thus its authorization server).
function challenge(params) {
  const all = { ...params, resource_metadata: RESOURCE_METADATA_URL };
  return `Bearer ${Object.entries(all)
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, "'")}"`)
    .join(', ')}`;
}

const sendJson = (res, status, obj, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(obj, null, 2));
};

// Returns the verified token payload, or sends 401/403 and returns undefined.
async function authorize(req, res, requiredScope) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) {
    log('401 no token -> pointing client to protected resource metadata');
    // RFC 6750 §3.1: no error code when the request simply lacked credentials.
    sendJson(res, 401, { error: 'unauthorized' }, { 'www-authenticate': challenge({ ...(requiredScope && { scope: requiredScope }) }) });
    return;
  }
  let at;
  try {
    at = await verifyAccessToken(m[1]);
  } catch (e) {
    log(`401 ${e.message}`);
    sendJson(
      res,
      401,
      { error: 'invalid_token', error_description: e.message },
      { 'www-authenticate': challenge({ error: 'invalid_token', error_description: e.message }) },
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
              resource_name: `${NAME} (demo MCP server)`,
            },
            { 'cache-control': 'max-age=60' },
          );

        case 'GET /api/data': {
          const at = await authorize(req, res);
          if (!at) return;
          log(`200 sub=${at.sub} client_id=${at.client_id}`);
          return sendJson(res, 200, { api: NAME, resource: RESOURCE, message: `Hello ${at.sub} from ${NAME}`, client_id: at.client_id });
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
