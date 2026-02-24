const crypto = require('crypto');
const { query } = require('../config/database');
const { hashPassword, verifyPassword, createFingerprint } = require('../utils/hash');
const { getPepper } = require('./pepper.service');
const tokenService = require('./token.service');
const mailService = require('./mail.service');
const { BadRequestError, UnauthorizedError, ConflictError } = require('../utils/errors');

function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

async function signup({ email, password, username, firstName, lastName, phone, country }, { userAgent, clientIp } = {}) {
  const existing = await query(
    'SELECT id FROM users WHERE email = $1 AND deleted = FALSE',
    [email]
  );
  if (existing.rows.length > 0) {
    throw new ConflictError('Un compte avec cet email existe déjà');
  }

  const existingUsername = await query(
    'SELECT id FROM users WHERE username = $1 AND deleted = FALSE',
    [username]
  );
  if (existingUsername.rows.length > 0) {
    throw new ConflictError('Ce nom d\'utilisateur est déjà pris');
  }

  const pepper = getPepper();
  const { salt, hash } = await hashPassword(password, pepper);

  const result = await query(
    `INSERT INTO users (username, email, phone, password_hash, salt, first_name, last_name, country)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, username, email, phone, first_name, last_name,
               email_verified, phone_verified, role_id, premium_level,
               country, created_at`,
    [username, email, phone || null, hash, salt, firstName || null, lastName || null, country || null]
  );

  const user = result.rows[0];
  user.role_name = 'user';

  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await query(
    'INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)',
    [user.id, code, expiresAt]
  );

  mailService.sendVerificationEmail(email, code).catch((err) => {
    console.error('[auth] Erreur envoi email de vérification:', err.message);
  });

  const fingerprintHash = createFingerprint(userAgent);
  const accessToken = tokenService.generateAccessToken({ id: user.id, email: user.email, role: 'user' });
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken, {
    fingerprintHash,
    ipAddress: clientIp
  });

  return { user: formatUser(user), accessToken, refreshToken };
}

async function login({ email, password }, { userAgent, clientIp } = {}) {
  const result = await query(
    `SELECT u.*, r.name AS role_name
     FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE u.email = $1 AND u.deleted = FALSE`,
    [email]
  );

  if (result.rows.length === 0) {
    throw new UnauthorizedError('Email ou mot de passe incorrect');
  }

  const user = result.rows[0];
  const pepper = getPepper();
  const valid = await verifyPassword(password, user.password_hash, user.salt, pepper);

  if (!valid) {
    throw new UnauthorizedError('Email ou mot de passe incorrect');
  }

  await query(
    'UPDATE users SET last_login_at = NOW() WHERE id = $1',
    [user.id]
  );

  const fingerprintHash = createFingerprint(userAgent);
  const accessToken = tokenService.generateAccessToken({ id: user.id, email: user.email, role: user.role_name });
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken, {
    fingerprintHash,
    ipAddress: clientIp
  });

  return { user: formatUser(user), accessToken, refreshToken };
}

async function refresh(oldRefreshToken, { userAgent, clientIp } = {}) {
  let user;
  try {
    user = await tokenService.rotateRefreshToken(oldRefreshToken);
  } catch (err) {
    if (err.message === 'TOKEN_REUSE_DETECTED') {
      throw new UnauthorizedError(
        'Réutilisation de token détectée — toutes les sessions ont été révoquées'
      );
    }
    throw err;
  }

  if (!user) {
    throw new UnauthorizedError('Refresh token invalide ou expiré');
  }

  const fingerprintHash = createFingerprint(userAgent);
  const accessToken = tokenService.generateAccessToken(user);
  const newRefreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, newRefreshToken, {
    fingerprintHash,
    ipAddress: clientIp
  });

  return { accessToken, refreshToken: newRefreshToken };
}

async function logout(refreshToken) {
  await tokenService.revokeRefreshToken(refreshToken);
}

async function getMe(userId) {
  const result = await query(
    `SELECT u.id, u.username, u.email, u.phone, u.first_name, u.last_name,
            u.email_verified, u.phone_verified, u.role_id, r.name AS role_name,
            u.premium_level, u.student_proof, u.country,
            u.created_at, u.updated_at, u.last_login_at
     FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE u.id = $1 AND u.deleted = FALSE`,
    [userId]
  );

  if (result.rows.length === 0) return null;
  return formatUser(result.rows[0]);
}

async function verifyEmail(userId, code) {
  const result = await query(
    `SELECT * FROM email_verifications
     WHERE user_id = $1 AND code = $2 AND used = FALSE AND expires_at > NOW()
     ORDER BY created_at DESC LIMIT 1`,
    [userId, code]
  );

  if (result.rows.length === 0) {
    throw new BadRequestError('Code invalide ou expiré');
  }

  await query('UPDATE email_verifications SET used = TRUE WHERE id = $1', [result.rows[0].id]);
  await query('UPDATE users SET email_verified = TRUE WHERE id = $1', [userId]);
}

function formatUser(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    phone: row.phone,
    firstName: row.first_name,
    lastName: row.last_name,
    emailVerified: row.email_verified,
    phoneVerified: row.phone_verified,
    role: row.role_name || 'user',
    premiumLevel: row.premium_level,
    country: row.country,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastLoginAt: row.last_login_at
  };
}

async function forgotPassword(email) {
  const result = await query(
    'SELECT id FROM users WHERE email = $1 AND deleted = FALSE',
    [email]
  );

  if (result.rows.length === 0) return;

  const user = result.rows[0];
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await query(
    'INSERT INTO password_resets (user_id, code, expires_at) VALUES ($1, $2, $3)',
    [user.id, code, expiresAt]
  );

  mailService.sendPasswordResetEmail(email, code).catch((err) => {
    console.error('[auth] Erreur envoi email de réinitialisation:', err.message);
  });
}

async function resetPassword(email, code, newPassword) {
  const result = await query(
    `SELECT pr.id AS reset_id, pr.user_id
     FROM password_resets pr
     JOIN users u ON pr.user_id = u.id
     WHERE u.email = $1 AND pr.code = $2 AND pr.used = FALSE
       AND pr.expires_at > NOW() AND u.deleted = FALSE
     ORDER BY pr.created_at DESC LIMIT 1`,
    [email, code]
  );

  if (result.rows.length === 0) {
    throw new BadRequestError('Code invalide ou expiré');
  }

  const { reset_id, user_id } = result.rows[0];
  const pepper = getPepper();
  const { salt, hash } = await hashPassword(newPassword, pepper);

  await query('UPDATE password_resets SET used = TRUE WHERE id = $1', [reset_id]);
  await query(
    'UPDATE users SET password_hash = $1, salt = $2 WHERE id = $3',
    [hash, salt, user_id]
  );

  await tokenService.revokeAllUserTokens(user_id);
}

module.exports = { signup, login, refresh, logout, getMe, verifyEmail, forgotPassword, resetPassword };
