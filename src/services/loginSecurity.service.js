// Compteur d'échecs de connexion par IP — blocage temporaire après N tentatives
const env = require('../config/env');

const MAX_ATTEMPTS = env.LOGIN_MAX_ATTEMPTS;
const WINDOW_MS = env.LOGIN_ATTEMPT_WINDOW_MS;
const BLOCK_MS = env.LOGIN_IP_BLOCK_MS;

// ip → { count, windowEnd, lastEmail }
const attempts = new Map();
// ip → timestamp fin de blocage
const blocked = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of attempts) {
    if (now > entry.windowEnd) attempts.delete(ip);
  }
  for (const [ip, until] of blocked) {
    if (now > until) blocked.delete(ip);
  }
}, 60_000).unref();

function isIpBlocked(ip) {
  if (!ip) return false;
  const until = blocked.get(ip);
  if (!until) return false;
  if (Date.now() > until) {
    blocked.delete(ip);
    return false;
  }
  return true;
}

function getBlockExpiresAt(ip) {
  return blocked.get(ip) || null;
}

function getRemainingAttempts(ip) {
  if (!ip || isIpBlocked(ip)) return 0;
  const entry = attempts.get(ip);
  if (!entry || Date.now() > entry.windowEnd) return MAX_ATTEMPTS;
  return Math.max(0, MAX_ATTEMPTS - entry.count);
}

// Incrémente les échecs ; bloque l'IP si le seuil est atteint
function recordFailedLogin(ip, email) {
  if (!ip) {
    return { blocked: false, attempts: 0, remaining: MAX_ATTEMPTS };
  }

  if (isIpBlocked(ip)) {
    return { blocked: true, attempts: MAX_ATTEMPTS, remaining: 0, lastEmail: email };
  }

  const now = Date.now();
  let entry = attempts.get(ip);

  if (!entry || now > entry.windowEnd) {
    entry = { count: 0, windowEnd: now + WINDOW_MS, lastEmail: email || null };
    attempts.set(ip, entry);
  }

  entry.count += 1;
  if (email) entry.lastEmail = email;

  if (entry.count >= MAX_ATTEMPTS) {
    blocked.set(ip, now + BLOCK_MS);
    attempts.delete(ip);
    return {
      blocked: true,
      attempts: entry.count,
      remaining: 0,
      lastEmail: entry.lastEmail,
      blockUntil: now + BLOCK_MS
    };
  }

  return {
    blocked: false,
    attempts: entry.count,
    remaining: MAX_ATTEMPTS - entry.count,
    lastEmail: entry.lastEmail
  };
}

// Réinitialise le compteur d'échecs après une connexion réussie (l'IP n'est pas débloquée si déjà bannie)
function recordSuccessfulLogin(ip) {
  if (ip) attempts.delete(ip);
}

module.exports = {
  isIpBlocked,
  getBlockExpiresAt,
  getRemainingAttempts,
  recordFailedLogin,
  recordSuccessfulLogin,
  MAX_ATTEMPTS,
  BLOCK_MS
};
