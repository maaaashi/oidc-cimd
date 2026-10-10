// DPoP (RFC 9449) proof verification, shared by the OP (token endpoint) and the resource servers.
// No dependencies (Node.js 22+).
const crypto = require('node:crypto');

const SUPPORTED_ALGS = ['ES256'];
const MAX_AGE_SEC = 60; // how old (or how far in the future) a proof's iat may be
const seenJti = new Map(); // jti -> expiresAt. Per process; a real deployment needs a shared store.

const b64url = (v) => Buffer.from(v).toString('base64url');
const sha256 = (v) => b64url(crypto.createHash('sha256').update(v).digest());

// RFC 7638 JWK thumbprint: hash of the required members in lexicographic order. This is the `jkt`.
function jwkThumbprint(jwk) {
  if (jwk.kty !== 'EC') throw new Error(`unsupported key type ${jwk.kty}`);
  const { crv, kty, x, y } = jwk;
  return sha256(JSON.stringify({ crv, kty, x, y }));
}

// Returns the thumbprint (jkt) of the key that signed the proof, or throws.
// `accessToken` is given by resource servers: the proof must then carry its hash (ath).
function verifyDpopProof(proof, { htm, htu, accessToken }) {
  if (typeof proof !== 'string' || !proof) throw new Error('DPoP header is missing');
  // Node joins repeated headers with ", "; a JWT never contains a comma.
  if (proof.includes(',')) throw new Error('exactly one DPoP header is required');

  const [h, p, s] = proof.split('.');
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url'));
    payload = JSON.parse(Buffer.from(p, 'base64url'));
  } catch {
    throw new Error('DPoP proof is not a well-formed JWT');
  }
  if (!s) throw new Error('DPoP proof is not signed');
  if (header.typ !== 'dpop+jwt') throw new Error('DPoP proof typ must be "dpop+jwt"');
  if (!SUPPORTED_ALGS.includes(header.alg)) throw new Error(`unsupported DPoP proof alg "${header.alg}"`);
  if (typeof header.jwk !== 'object' || header.jwk === null) throw new Error('DPoP proof has no jwk header');
  if ('d' in header.jwk) throw new Error('DPoP proof jwk must not contain a private key');

  // The proof is signed by the key in its own header: it proves possession of that key, nothing more.
  // Binding comes from comparing this key's thumbprint with the token's cnf.jkt.
  let key;
  try {
    key = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
  } catch {
    throw new Error('DPoP proof jwk is not a valid public key');
  }
  const ok = crypto.verify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('DPoP proof signature is invalid');

  // The proof is only valid for this one request (method + URL without query/fragment).
  if (payload.htm !== htm) throw new Error(`DPoP proof htm "${payload.htm}" does not match ${htm}`);
  const stripped = (u) => {
    const x = new URL(u);
    return `${x.origin}${x.pathname}`;
  };
  let proofHtu;
  try {
    proofHtu = stripped(payload.htu);
  } catch {
    throw new Error('DPoP proof htu is not a URL');
  }
  if (proofHtu !== stripped(htu)) throw new Error(`DPoP proof htu "${payload.htu}" does not match ${htu}`);

  // At a resource server, the proof must be made for this exact access token.
  if (accessToken !== undefined && payload.ath !== sha256(accessToken)) {
    throw new Error('DPoP proof ath does not match the access token');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== 'number' || Math.abs(now - payload.iat) > MAX_AGE_SEC) {
    throw new Error('DPoP proof iat is too old or in the future');
  }

  // Each proof may be used only once (replay protection).
  for (const [jti, exp] of seenJti) if (exp < Date.now()) seenJti.delete(jti);
  if (typeof payload.jti !== 'string' || !payload.jti) throw new Error('DPoP proof has no jti');
  if (seenJti.has(payload.jti)) throw new Error('DPoP proof has already been used (jti replay)');
  seenJti.set(payload.jti, Date.now() + 2 * MAX_AGE_SEC * 1000);

  return jwkThumbprint(header.jwk);
}

module.exports = { SUPPORTED_ALGS, verifyDpopProof };
