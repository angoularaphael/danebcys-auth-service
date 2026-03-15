/**
 * Détection d'activité frauduleuse : trop de requêtes par minute.
 * - Seuil : FRAUD_REQUESTS_PER_MIN (défaut 20)
 * - À chaque dépassement : notification "activité_frauduleuse" aux admins
 * - Après FRAUD_BAN_AFTER_NOTIF (défaut 5) notifications : bannissement auto (soft delete)
 */
const env = require('../config/env');
const { query } = require('../config/database');
const notificationsClient = require('../services/notificationsClient');

const FRAUD_REQUESTS_PER_MIN = env.FRAUD_REQUESTS_PER_MIN || 20;
const FRAUD_BAN_AFTER_NOTIF = env.FRAUD_BAN_AFTER_NOTIF || 5;
const WINDOW_MS = 60_000;

const requestCounts = new Map();
const fraudCounts = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of requestCounts) {
    if (now > entry.windowEnd) requestCounts.delete(key);
  }
  for (const [key, entry] of fraudCounts) {
    if (now > entry.resetAt) fraudCounts.delete(key);
  }
}, 60_000).unref();

async function softDeleteUser(userId) {
  await query('UPDATE users SET deleted = TRUE WHERE id = $1 AND deleted = FALSE', [userId]);
}

async function handleFraud(userId, userEmail, username) {
  let entry = fraudCounts.get(userId);
  if (!entry) {
    entry = { count: 0, resetAt: Date.now() + 300_000 };
    fraudCounts.set(userId, entry);
  }
  entry.count++;
  entry.resetAt = Date.now() + 300_000;

  const message = `Activité frauduleuse détectée : ${userEmail || username || userId} (${entry.count}/${FRAUD_BAN_AFTER_NOTIF})`;
  await notificationsClient.sendToAdmins('activité_frauduleuse', message);

  if (entry.count >= FRAUD_BAN_AFTER_NOTIF) {
    try {
      await softDeleteUser(userId);
      console.warn('[fraud] Utilisateur banni automatiquement:', userId, userEmail);
      fraudCounts.delete(userId);
    } catch (err) {
      console.error('[fraud] Échec bannissement:', err.message);
    }
  }
}

function fraudDetector(req, res, next) {
  const user = req.user;
  if (!user || !user.id) return next();

  const userId = user.id;
  const now = Date.now();
  let entry = requestCounts.get(userId);

  if (!entry || now > entry.windowEnd) {
    entry = { count: 0, windowEnd: now + WINDOW_MS, fraudNotified: false };
    requestCounts.set(userId, entry);
  }
  entry.count++;

  if (entry.count > FRAUD_REQUESTS_PER_MIN && !entry.fraudNotified) {
    entry.fraudNotified = true;
    handleFraud(userId, user.email, user.username).catch((err) =>
      console.error('[fraud] Erreur:', err.message)
    );
  }

  next();
}

module.exports = { fraudDetector };
