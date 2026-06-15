// Limite le nombre de requêtes par utilisateur ou par adresse IP (sans librairie externe)
const jwt = require('../utils/jwt');
const env = require('../config/env');

// Compteurs en mémoire : clé → nombre de requêtes dans la fenêtre
const store = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now > entry.resetAt) store.delete(key);
  }
}, 60_000).unref();

// Crée un limiteur : bloque après trop de requêtes dans une fenêtre de temps
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

// Identifie l'utilisateur connecté pour compter ses requêtes
function extractUserKey(req) {
  if (req.user && req.user.id) return `user:${req.user.id}`;
  return null;
}

// Lit l'identifiant dans le jeton sans vérification complète (routes avant connexion)
function extractTokenKey(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  const payload = jwt.decode(header.split(' ')[1]);
  return payload ? `user:${payload.sub}` : null;
}

// Utilise l'adresse IP pour compter les requêtes (routes publiques)
function extractIpKey(req) {
  return `ip:${req.clientIp || req.ip}`;
}

// Limite les requêtes des utilisateurs connectés
const tokenLimiter = createLimiter({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  keyFn: extractUserKey
});

// Limite les requêtes de renouvellement de jeton (/auth/refresh)
const preAuthTokenLimiter = createLimiter({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  keyFn: extractTokenKey
});

// Limite les demandes de défi anti-robot — 30 par minute par adresse IP
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
