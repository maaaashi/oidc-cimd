// Minimal resource server (API) that only accepts access tokens whose `aud` is its own
// resource identifier (RFC 8707 / RFC 9068). No dependencies (Node.js 22+).
const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 5000);
const RESOURCE = process.env.RESOURCE || `http://localhost:${PORT}`; // this API's resource identifier
const NAME = process.env.NAME || 'API';
const ISSUER = process.env.ISSUER || 'http://localhost:3000';

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

const sendJson = (res, status, obj, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(obj, null, 2));
};

http
  .createServer(async (req, res) => {
    if (req.method !== 'GET' || new URL(req.url, RESOURCE).pathname !== '/api/data') {
      return sendJson(res, 404, { error: 'not_found' });
    }
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    try {
      if (!m) throw new Error('missing bearer token');
      const at = await verifyAccessToken(m[1]);
      log(`200 sub=${at.sub} client_id=${at.client_id}`);
      sendJson(res, 200, { api: NAME, resource: RESOURCE, message: `Hello ${at.sub} from ${NAME}`, client_id: at.client_id });
    } catch (e) {
      log(`401 ${e.message}`);
      sendJson(
        res,
        401,
        { error: 'invalid_token', error_description: e.message },
        { 'www-authenticate': `Bearer error="invalid_token", error_description="${e.message.replace(/"/g, "'")}"` },
      );
    }
  })
  .listen(PORT, () => log(`listening on ${RESOURCE}`));
