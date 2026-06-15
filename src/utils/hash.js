// Hashage scrypt des mots de passe avec pepper et comparaison sécurisée
const crypto = require('crypto');

// Réglages pour chiffrer les mots de passe (algorithme scrypt)
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keyLength: 64 };

// Chiffre un mot de passe avec un sel et une clé secrète (pepper)
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

// Vérifie si un mot de passe correspond au hash stocké en base
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

// Compare deux textes secrets sans révéler leur contenu par le temps de réponse
function safeCompare(a, b) {
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// Crée une empreinte unique du navigateur à partir de son identifiant (User-Agent)
function createFingerprint(userAgent) {
  if (!userAgent) return null;
  return crypto.createHash('sha256').update(userAgent).digest('hex');
}

module.exports = { hashPassword, verifyPassword, safeCompare, createFingerprint };
