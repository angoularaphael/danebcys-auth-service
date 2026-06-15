// Création et vérification des jetons JWT (implémentation maison)
const crypto = require('crypto');

// Encode des données en texte base64url (format utilisé par les jetons JWT)
function base64UrlEncode(data) {
  return Buffer.from(data).toString('base64url');
}

// Décode du texte base64url en texte lisible
function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url').toString('utf8');
}

// Crée un jeton JWT signé (sans librairie externe)
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

// Vérifie la signature et la date d'expiration d'un jeton JWT
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

// Lit le contenu du jeton sans vérifier la signature (pour compter les requêtes)
function decode(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}

// Convertit une durée texte (ex. 15m, 7d) en secondes
function parseDurationSec(str) {
  const match = str.match(/^(\d+)([smhd])$/);
  if (!match) return 900;
  const val = parseInt(match[1], 10);
  const mult = { s: 1, m: 60, h: 3600, d: 86400 };
  return val * (mult[match[2]] || 60);
}

module.exports = { sign, verify, decode };
