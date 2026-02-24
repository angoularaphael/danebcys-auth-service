const jwt = require('../utils/jwt');
const env = require('../config/env');

/**
 * Rate limiter maison, basé sur le token (user ID) et non l'IP.
 * Stockage en mémoire avec nettoyage périodique.
 * Aucune librairie externe.
 */

const store = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now > entry.resetAt) store.delete(key);
  }
}, 60_000).unref();

function createLimiter({ windowMs, max, keyFn }) {
  return (req, res, next) => {
    const key = keyFn(req);
    if (!key) return next();

    const now = Date.now();
    let entry = store.get(key);

    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      store.set(key, entry);
    }

    entry.count++;

    const remaining = Math.max(0, max - entry.count);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > max) {
      return res.status(429).json({ error: 'Trop de requêtes, réessayez plus tard' });
    }

    next();
  };
}

function extractUserKey(req) {
  if (req.user && req.user.id) return `user:${req.user.id}`;
  return null;
}

function extractTokenKey(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  const payload = jwt.decode(header.split(' ')[1]);
  return payload ? `user:${payload.sub}` : null;
}

function extractIpKey(req) {
  return `ip:${req.clientIp || req.ip}`;
}

const tokenLimiter = createLimiter({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  keyFn: extractUserKey
});

const preAuthTokenLimiter = createLimiter({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  keyFn: extractTokenKey
});

const challengeLimiter = createLimiter({
  windowMs: 60_000,
  max: 30,
  keyFn: extractIpKey
});

module.exports = {
  createLimiter,
  tokenLimiter,
  preAuthTokenLimiter,
  challengeLimiter
};
