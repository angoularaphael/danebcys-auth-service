const crypto = require('crypto');
const env = require('../config/env');
const { BadRequestError } = require('../utils/errors');

/**
 * Crée un challenge PoW signé par HMAC (stateless, pas de stockage DB).
 * Le client doit trouver un nonce tel que SHA-256(challenge + nonce)
 * commence par `difficulty` zéros hexadécimaux.
 */
function createChallenge() {
  const timestamp = Date.now();
  const random = crypto.randomBytes(16).toString('hex');
  const challenge = `${timestamp}:${random}`;
  const signature = crypto
    .createHmac('sha256', env.POW_SECRET)
    .update(challenge)
    .digest('hex');

  return {
    challenge,
    difficulty: env.POW_DIFFICULTY,
    signature,
    expiresAt: new Date(timestamp + env.POW_EXPIRY_SECONDS * 1000).toISOString()
  };
}

/**
 * Middleware : vérifie le PoW via les headers
 * x-pow-challenge, x-pow-nonce, x-pow-signature
 */
function verifyPow(req, _res, next) {
  const challenge = req.headers['x-pow-challenge'];
  const nonce = req.headers['x-pow-nonce'];
  const signature = req.headers['x-pow-signature'];

  if (!challenge || !nonce || !signature) {
    return next(new BadRequestError(
      'Proof of Work requis (headers: x-pow-challenge, x-pow-nonce, x-pow-signature)'
    ));
  }

  const expectedSig = crypto
    .createHmac('sha256', env.POW_SECRET)
    .update(challenge)
    .digest('hex');

  if (
    signature.length !== expectedSig.length ||
    !crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'))
  ) {
    return next(new BadRequestError('Challenge PoW invalide'));
  }

  const timestamp = parseInt(challenge.split(':')[0], 10);
  if (Date.now() - timestamp > env.POW_EXPIRY_SECONDS * 1000) {
    return next(new BadRequestError('Challenge PoW expiré'));
  }

  const hash = crypto.createHash('sha256').update(challenge + nonce).digest('hex');
  const prefix = '0'.repeat(env.POW_DIFFICULTY);
  if (!hash.startsWith(prefix)) {
    return next(new BadRequestError('Proof of Work invalide'));
  }

  next();
}

module.exports = { createChallenge, verifyPow };
