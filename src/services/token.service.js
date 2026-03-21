const crypto = require('crypto');
const jwt = require('../utils/jwt');
const { query } = require('../config/database');
const env = require('../config/env');

/** Durée de vie des tokens : identique pour tous les rôles (user, admin, vendeur, assistance). */

function generateAccessToken(user) {
  const tokenVersion = Number(user.tokenVersion ?? user.token_version ?? 0);
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      ver: tokenVersion,
      jti: crypto.randomUUID()
    },
    env.JWT_ACCESS_SECRET,
    env.JWT_ACCESS_EXPIRES_IN
  );
}

function generateRefreshToken() {
  return crypto.randomBytes(40).toString('hex');
}

function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_ACCESS_SECRET);
}

async function validateAccessToken(token) {
  const payload = verifyAccessToken(token);

  if (!payload.jti) {
    throw new Error('Token invalide: jti manquant');
  }

  if (await isAccessTokenRevoked(payload.jti)) {
    throw new Error('Token revoque');
  }

  const result = await query(
    `SELECT u.id, u.email, u.username, u.role_id, u.token_version, r.name AS role
     FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE u.id = $1 AND u.deleted = FALSE`,
    [payload.sub]
  );

  if (result.rows.length === 0) {
    throw new Error('Utilisateur non trouvé');
  }

  const user = result.rows[0];
  const tokenVersion = Number(payload.ver || 0);
  if (tokenVersion !== Number(user.token_version || 0)) {
    throw new Error('Token revoque');
  }

  return {
    payload,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      role_id: user.role_id,
      role: user.role
    }
  };
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function storeRefreshToken(userId, token, { fingerprintHash, ipAddress } = {}) {
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + parseDurationMs(env.JWT_REFRESH_EXPIRES_IN));

  await query(
    `INSERT INTO sessions (user_id, token_hash, fingerprint_hash, ip_address, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, tokenHash, fingerprintHash || null, ipAddress || null, expiresAt]
  );
}

/**
 * Rotation de token avec détection de réutilisation (CDC 4.2).
 *
 * Flux :
 *  1. Le token existe et n'est PAS invalidated → on le marque invalidated, on retourne le user
 *  2. Le token existe et EST invalidated → réutilisation détectée !
 *     → on supprime TOUS les tokens du user (toutes ses sessions)
 *     → on lance TOKEN_REUSE_DETECTED
 *  3. Le token n'existe pas ou est expiré → retourne null
 */
async function rotateRefreshToken(token) {
  const tokenHash = hashToken(token);

  const result = await query(
    `SELECT s.id, s.user_id, s.invalidated, s.expires_at, s.fingerprint_hash,
            u.id AS uid, u.email, u.role_id, u.token_version, r.name AS role_name, u.deleted
     FROM sessions s
     JOIN users u ON s.user_id = u.id
     JOIN roles r ON u.role_id = r.id
     WHERE s.token_hash = $1`,
    [tokenHash]
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0];

  if (row.invalidated) {
    await query('DELETE FROM sessions WHERE user_id = $1', [row.user_id]);
    await bumpUserTokenVersion(row.user_id);
    const err = new Error('TOKEN_REUSE_DETECTED');
    err.userId = row.user_id;
    throw err;
  }

  if (new Date(row.expires_at) < new Date()) return null;
  if (row.deleted) return null;

  await query(
    'UPDATE sessions SET invalidated = TRUE, last_used_at = NOW() WHERE id = $1',
    [row.id]
  );

  return {
    id: row.uid,
    email: row.email,
    role: row.role_name,
    tokenVersion: row.token_version
  };
}

async function revokeRefreshToken(token) {
  const tokenHash = hashToken(token);
  await query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
}

async function revokeAllUserTokens(userId) {
  await query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

async function revokeOtherUserSessions(userId, keepRefreshToken) {
  const keepHash = hashToken(keepRefreshToken);
  await query('DELETE FROM sessions WHERE user_id = $1 AND token_hash != $2', [userId, keepHash]);
}

async function isAccessTokenRevoked(tokenJti) {
  const result = await query(
    `SELECT 1
     FROM token_blacklist
     WHERE token_jti = $1 AND expires_at > NOW()
     LIMIT 1`,
    [tokenJti]
  );

  return result.rows.length > 0;
}

async function revokeAccessToken(token, reason = 'logout') {
  const payload = verifyAccessToken(token);

  if (!payload.jti || !payload.sub || !payload.exp) {
    return;
  }

  const expiresAt = new Date(payload.exp * 1000);
  if (expiresAt <= new Date()) {
    return;
  }

  await query(
    `INSERT INTO token_blacklist (token_jti, user_id, reason, expires_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (token_jti) DO UPDATE
       SET reason = EXCLUDED.reason,
           expires_at = EXCLUDED.expires_at,
           revoked_at = NOW()`,
    [payload.jti, payload.sub, reason, expiresAt]
  );
}

async function bumpUserTokenVersion(userId) {
  const result = await query(
    `UPDATE users
     SET token_version = token_version + 1
     WHERE id = $1
     RETURNING token_version`,
    [userId]
  );

  return result.rows[0]?.token_version ?? null;
}

function parseDurationMs(duration) {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000;
  const value = parseInt(match[1], 10);
  const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return value * (mult[match[2]] || 86_400_000);
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  validateAccessToken,
  hashToken,
  storeRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens,
  revokeOtherUserSessions,
  revokeAccessToken,
  isAccessTokenRevoked,
  bumpUserTokenVersion
};
