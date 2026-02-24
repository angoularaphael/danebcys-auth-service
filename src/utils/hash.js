const crypto = require('crypto');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keyLength: 64 };

/**
 * Hash un mot de passe avec scrypt + salt + pepper.
 * Retourne { salt, hash } séparément (CDC : salt stocké en colonne dédiée).
 */
function hashPassword(password, pepper) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(32).toString('hex');
    const input = `${password}${pepper}`;

    crypto.scrypt(input, salt, SCRYPT_PARAMS.keyLength, {
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p
    }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({ salt, hash: derivedKey.toString('hex') });
    });
  });
}

/**
 * Vérifie un mot de passe contre un hash stocké, avec timing-safe compare.
 * Le salt est fourni séparément (colonne dédiée en DB).
 */
function verifyPassword(password, storedHash, salt, pepper) {
  return new Promise((resolve, reject) => {
    const input = `${password}${pepper}`;

    crypto.scrypt(input, salt, SCRYPT_PARAMS.keyLength, {
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p
    }, (err, derivedKey) => {
      if (err) return reject(err);
      const hashBuffer = Buffer.from(storedHash, 'hex');
      resolve(crypto.timingSafeEqual(hashBuffer, derivedKey));
    });
  });
}

/**
 * Comparaison timing-safe universelle (longueur variable).
 * On hash les deux valeurs en SHA-256 pour garantir des buffers de même taille.
 */
function safeCompare(a, b) {
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Crée un fingerprint à partir du User-Agent (CDC 4.2 : hash user-agent).
 */
function createFingerprint(userAgent) {
  if (!userAgent) return null;
  return crypto.createHash('sha256').update(userAgent).digest('hex');
}

module.exports = { hashPassword, verifyPassword, safeCompare, createFingerprint };
