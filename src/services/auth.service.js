const crypto = require('crypto');
const { query } = require('../config/database');
const { hashPassword, verifyPassword } = require('../utils/hash');
const { getPepper } = require('./pepper.service');
const tokenService = require('./token.service');
const mailService = require('./mail.service');
const { BadRequestError, UnauthorizedError, ConflictError } = require('../utils/errors');

function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

async function signup({ email, password, firstName, lastName, phone }) {
  const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    throw new ConflictError('Un compte avec cet email existe déjà');
  }

  const pepper = getPepper();
  const passwordHash = await hashPassword(password, pepper);

  const result = await query(
    `INSERT INTO users (email, phone, password_hash, first_name, last_name)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, email, phone, first_name, last_name, email_verified, role, created_at`,
    [email, phone || null, passwordHash, firstName, lastName]
  );

  const user = result.rows[0];

  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await query(
    'INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)',
    [user.id, code, expiresAt]
  );

  mailService.sendVerificationEmail(email, code).catch((err) => {
    console.error('[auth] Erreur envoi email de vérification:', err.message);
  });

  const accessToken = tokenService.generateAccessToken(user);
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken);

  return { user: formatUser(user), accessToken, refreshToken };
}

async function login({ email, password }) {
  const result = await query(
    'SELECT * FROM users WHERE email = $1 AND deleted = FALSE',
    [email]
  );

  if (result.rows.length === 0) {
    throw new UnauthorizedError('Email ou mot de passe incorrect');
  }

  const user = result.rows[0];
  const pepper = getPepper();
  const valid = await verifyPassword(password, user.password_hash, pepper);

  if (!valid) {
    throw new UnauthorizedError('Email ou mot de passe incorrect');
  }

  const accessToken = tokenService.generateAccessToken(user);
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken);

  return { user: formatUser(user), accessToken, refreshToken };
}

async function refresh(oldRefreshToken) {
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

  const accessToken = tokenService.generateAccessToken(user);
  const newRefreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, newRefreshToken);

  return { accessToken, refreshToken: newRefreshToken };
}

async function logout(refreshToken) {
  await tokenService.revokeRefreshToken(refreshToken);
}

async function getMe(userId) {
  const result = await query(
    `SELECT id, email, phone, first_name, last_name, email_verified,
            phone_verified, role, created_at, updated_at
     FROM users WHERE id = $1 AND deleted = FALSE`,
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
  await query('UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1', [userId]);
}

function formatUser(row) {
  return {
    id: row.id,
    email: row.email,
    phone: row.phone,
    firstName: row.first_name,
    lastName: row.last_name,
    emailVerified: row.email_verified,
    phoneVerified: row.phone_verified,
    role: row.role,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function forgotPassword(email) {
  const result = await query(
    'SELECT id FROM users WHERE email = $1 AND deleted = FALSE',
    [email]
  );

  // Ne pas révéler si l'email existe ou non
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
  const passwordHash = await hashPassword(newPassword, pepper);

  await query('UPDATE password_resets SET used = TRUE WHERE id = $1', [reset_id]);
  await query(
    'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
    [passwordHash, user_id]
  );

  await tokenService.revokeAllUserTokens(user_id);
}

module.exports = { signup, login, refresh, logout, getMe, verifyEmail, forgotPassword, resetPassword };
