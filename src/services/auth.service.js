// Logique métier : comptes, mots de passe, vérifications email/SMS
const crypto = require('crypto');
const { query } = require('../config/database');
const env = require('../config/env');
const { hashPassword, verifyPassword, createFingerprint } = require('../utils/hash');
const { getPepper } = require('./pepper.service');
const tokenService = require('./token.service');
const mailService = require('./mail.service');
const loginSecurity = require('./loginSecurity.service');
const { lookupIpLocation } = require('./geoip.service');
const { parseUserAgent } = require('../utils/browser');
const { BadRequestError, UnauthorizedError, ConflictError, ForbiddenError } = require('../utils/errors');

// Génère un code à 6 chiffres pour vérifier email ou téléphone
function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Crée un compte, envoie le code par email et renvoie les jetons de connexion
async function signup({ email, password, username, firstName, lastName, phone, country, role: roleName = 'user' }, { userAgent, clientIp } = {}) {
  const allowedRoles = ['user', 'vendeur'];
  const role = allowedRoles.includes(roleName) ? roleName : 'user';

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

  const roleResult = await query('SELECT id FROM roles WHERE name = $1', [role]);
  if (roleResult.rows.length === 0) {
    throw new Error(`Rôle "${role}" introuvable`);
  }
  const roleId = roleResult.rows[0].id;

  const pepper = getPepper();
  const { salt, hash } = await hashPassword(password, pepper);

  const result = await query(
    `INSERT INTO users (username, email, phone, password_hash, salt, first_name, last_name, country, role_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id, username, email, phone, first_name, last_name,
               email_verified, phone_verified, role_id, token_version, premium_level,
               country, created_at`,
    [username, email, phone || null, hash, salt, firstName || null, lastName || null, country || null, roleId]
  );

  const user = result.rows[0];
  user.role_name = role;

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
  const accessToken = tokenService.generateAccessToken({
    id: user.id,
    email: user.email,
    role,
    tokenVersion: user.token_version
  });
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken, {
    fingerprintHash,
    ipAddress: clientIp
  });

  return { user: formatUser(user), accessToken, refreshToken };
}

// Connecte un utilisateur et renvoie les jetons (même logique pour tous les rôles)
async function login({ email, password }, { userAgent, clientIp } = {}) {
  if (clientIp && loginSecurity.isIpBlocked(clientIp)) {
    throw new ForbiddenError(
      `Adresse IP temporairement bloquée après ${loginSecurity.MAX_ATTEMPTS} tentatives de connexion échouées.`
    );
  }

  const result = await query(
    `SELECT u.*, r.name AS role_name
     FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE u.email = $1`,
    [email]
  );

  const loginFailed = async () => {
    const fail = loginSecurity.recordFailedLogin(clientIp, email);
    if (fail.blocked && email) {
      const account = await query(
        'SELECT id FROM users WHERE email = $1 AND deleted = FALSE',
        [email]
      );
      if (account.rows.length > 0) {
        mailService.sendLoginBlockedEmail(email, {
          ip: clientIp,
          attempts: fail.attempts,
          blockMinutes: Math.ceil(loginSecurity.BLOCK_MS / 60_000)
        }).catch((err) => console.error('[auth] Alerte blocage IP:', err.message));
      }
    }
    const hint = fail.remaining > 0 && fail.remaining < loginSecurity.MAX_ATTEMPTS
      ? ` (${fail.remaining} tentative(s) restante(s) avant blocage de l'adresse IP)`
      : '';
    throw new UnauthorizedError(`Email ou mot de passe incorrect${hint}`);
  };

  if (result.rows.length === 0) {
    await loginFailed();
  }

  const user = result.rows[0];

  if (user.deleted) {
    const assistanceEmail = env.ASSISTANCE_EMAIL || 'angoularaphael05@gmail.com';
    throw new UnauthorizedError(
      `Votre compte a été banni. Pour contester cette décision, contactez l'assistance par email à ${assistanceEmail}`
    );
  }
  const pepper = getPepper();
  const valid = await verifyPassword(password, user.password_hash, user.salt, pepper);

  if (!valid) {
    await loginFailed();
  }

  loginSecurity.recordSuccessfulLogin(clientIp);

  if (!user.email_verified) {
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await query(
      'INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)',
      [user.id, code, expiresAt]
    );
    mailService.sendVerificationEmail(user.email, code).catch((err) => {
      console.error('[auth] Erreur envoi email de vérification:', err.message);
    });
  }

  await query(
    'UPDATE users SET last_login_at = NOW() WHERE id = $1',
    [user.id]
  );

  const fingerprintHash = createFingerprint(userAgent);
  const accessToken = tokenService.generateAccessToken({
    id: user.id,
    email: user.email,
    role: user.role_name,
    tokenVersion: user.token_version
  });
  const refreshToken = tokenService.generateRefreshToken();
  await tokenService.storeRefreshToken(user.id, refreshToken, {
    fingerprintHash,
    ipAddress: clientIp
  });

  const browser = parseUserAgent(userAgent);
  lookupIpLocation(clientIp).then((location) => {
    mailService.sendLoginAlertEmail(user.email, {
      browser,
      ip: clientIp,
      location,
      loginAt: new Date().toLocaleString('fr-FR', { timeZone: 'Europe/Paris' })
    });
  }).catch((err) => console.error('[auth] Alerte connexion:', err.message));

  return { user: formatUser(user), accessToken, refreshToken };
}

// Échange un refresh token contre une nouvelle paire de jetons
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

// Déconnecte l'utilisateur et invalide ses jetons
async function logout(refreshToken, accessToken) {
  await tokenService.revokeRefreshToken(refreshToken);
  if (accessToken) {
    await tokenService.revokeAccessToken(accessToken, 'logout');
  }
}

// Récupère le profil d'un utilisateur par son identifiant
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

// Valide le code email et marque l'adresse comme vérifiée
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

// Change le mot de passe après vérification de l'ancien
async function changePassword(userId, currentPassword, newPassword) {
  const result = await query(
    'SELECT id, password_hash, salt FROM users WHERE id = $1 AND deleted = FALSE',
    [userId]
  );
  if (result.rows.length === 0) {
    throw new BadRequestError('Utilisateur introuvable');
  }
  const user = result.rows[0];
  const pepper = getPepper();
  const valid = await verifyPassword(currentPassword, user.password_hash, user.salt, pepper);
  if (!valid) {
    throw new UnauthorizedError('Mot de passe actuel incorrect');
  }
  if (newPassword.length < 8) {
    throw new BadRequestError('Le nouveau mot de passe doit contenir au moins 8 caractères');
  }
  const { salt, hash } = await hashPassword(newPassword, pepper);
  await query('UPDATE users SET password_hash = $1, salt = $2 WHERE id = $3', [hash, salt, userId]);
}

// Ferme toutes les sessions sauf celle de l'appareil actuel
async function revokeOtherSessions(userId, keepRefreshToken) {
  await tokenService.revokeOtherUserSessions(userId, keepRefreshToken);
}

// Renvoie un code de vérification email si l'adresse n'est pas encore validée
async function resendEmailVerificationCode(userId) {
  const userResult = await query(
    'SELECT id, email, email_verified FROM users WHERE id = $1 AND deleted = FALSE',
    [userId]
  );

  if (userResult.rows.length === 0) {
    throw new BadRequestError('Utilisateur introuvable');
  }

  const user = userResult.rows[0];
  if (user.email_verified) {
    return { message: 'Adresse email deja verifiee' };
  }

  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await query(
    'INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)',
    [user.id, code, expiresAt]
  );

  mailService.sendVerificationEmail(user.email, code).catch((err) => {
    console.error('[auth] Erreur envoi email de verification:', err.message);
  });

  return { message: 'Code de verification renvoye' };
}

// Transforme une ligne de base de données en objet lisible pour l'API
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

// Envoie un code par email pour réinitialiser le mot de passe (sans révéler si le compte existe)
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

// Change le mot de passe avec le code reçu et ferme toutes les sessions
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
  await tokenService.bumpUserTokenVersion(user_id);
}

// Envoie un code SMS pour vérifier le numéro de téléphone
async function requestPhoneVerification(userId) {
  const userResult = await query(
    'SELECT phone FROM users WHERE id = $1 AND deleted = FALSE',
    [userId]
  );
  if (userResult.rows.length === 0) throw new BadRequestError('Utilisateur introuvable');
  const { phone } = userResult.rows[0];
  if (!phone) throw new BadRequestError('Aucun numéro de téléphone associé au compte');

  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await query(
    'INSERT INTO phone_verifications (user_id, phone, code, expires_at) VALUES ($1, $2, $3, $4)',
    [userId, phone, code, expiresAt]
  );

  mailService.sendPhoneVerificationSms(phone, code).catch((err) => {
    console.error('[auth] Erreur envoi SMS de vérification:', err.message);
  });
}

// Valide le code SMS et marque le téléphone comme vérifié
async function verifyPhone(userId, code) {
  const result = await query(
    `SELECT * FROM phone_verifications
     WHERE user_id = $1 AND code = $2 AND used = FALSE AND expires_at > NOW()
     ORDER BY created_at DESC LIMIT 1`,
    [userId, code]
  );

  if (result.rows.length === 0) {
    throw new BadRequestError('Code invalide ou expiré');
  }

  await query('UPDATE phone_verifications SET used = TRUE WHERE id = $1', [result.rows[0].id]);
  await query('UPDATE users SET phone_verified = TRUE WHERE id = $1', [userId]);
}

module.exports = {
  signup,
  login,
  refresh,
  logout,
  getMe,
  verifyEmail,
  resendEmailVerificationCode,
  verifyPhone,
  requestPhoneVerification,
  forgotPassword,
  resetPassword,
  changePassword,
  revokeOtherSessions
};
