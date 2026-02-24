const crypto = require('crypto');

function base64UrlEncode(data) {
  return Buffer.from(data).toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url').toString('utf8');
}

/**
 * Crée un JWT signé avec HMAC-SHA256.
 * Aucune librairie externe — uniquement le module crypto natif.
 */
function sign(payload, secret, expiresIn) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + parseDurationSec(expiresIn)
  };

  const segments = [
    base64UrlEncode(JSON.stringify(header)),
    base64UrlEncode(JSON.stringify(fullPayload))
  ];
  const signingInput = segments.join('.');

  const signature = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');

  return `${signingInput}.${signature}`;
}

/**
 * Vérifie la signature HMAC et l'expiration du token.
 * Utilise timingSafeEqual pour bloquer les attaques par timing.
 */
function verify(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Format JWT invalide');

  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');

  const sigBuf = Buffer.from(signatureB64);
  const expectedBuf = Buffer.from(expectedSig);

  if (sigBuf.length !== expectedBuf.length ||
      !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    throw new Error('Signature JWT invalide');
  }

  const payload = JSON.parse(base64UrlDecode(payloadB64));

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expiré');
  }

  return payload;
}

/**
 * Décode le payload sans vérifier la signature.
 * Utilisé uniquement pour extraire l'identité dans le rate limiter.
 */
function decode(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}

function parseDurationSec(str) {
  const match = str.match(/^(\d+)([smhd])$/);
  if (!match) return 900;
  const val = parseInt(match[1], 10);
  const mult = { s: 1, m: 60, h: 3600, d: 86400 };
  return val * (mult[match[2]] || 60);
}

module.exports = { sign, verify, decode };
