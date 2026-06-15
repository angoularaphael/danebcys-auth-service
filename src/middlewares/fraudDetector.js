// Surveille les utilisateurs qui font trop de modifications en peu de temps
const env = require('../config/env');
const { query } = require('../config/database');
const { sendToAdmins } = require('../services/notificationsClient');

// Nombre max de modifications par minute avant alerte
const FRAUD_REQUESTS_PER_MIN = env.FRAUD_REQUESTS_PER_MIN || 80;
// Nombre d'alertes avant bannissement automatique du compte
const FRAUD_BAN_AFTER_NOTIF = env.FRAUD_BAN_AFTER_NOTIF || 5;
// Durée de la fenêtre de comptage (1 minute)
const WINDOW_MS = 60_000;

// Compte les modifications récentes par utilisateur (en mémoire)
const requestCounts = new Map();
// Compte les alertes fraude par utilisateur (en mémoire)
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

// Marque le compte comme supprimé dans PostgreSQL (sans effacer les données)
async function softDeleteUser(userId) {
  await query('UPDATE users SET deleted = TRUE WHERE id = $1 AND deleted = FALSE', [userId]);
}

// Prévient les admins puis bannit le compte si trop d'alertes — appelle Communication-service port 3006
async function handleFraud(userId, userEmail, username) {
  let entry = fraudCounts.get(userId);
  if (!entry) {
    entry = { count: 0, resetAt: Date.now() + 300_000 };
    fraudCounts.set(userId, entry);
  }
  entry.count++;
  entry.resetAt = Date.now() + 300_000;

  const message = `Activité suspecte détectée : ${userEmail || username || userId} (${entry.count}/${FRAUD_BAN_AFTER_NOTIF})`;
  await sendToAdmins('activité_frauduleuse', message).catch((err) =>
    console.error('[fraud] Échec notification admins:', err.message)
  );

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

// Compte les modifications (pas les lectures) et déclenche une alerte si seuil dépassé
function fraudDetector(req, res, next) {
  const user = req.user;
  if (!user || !user.id) return next();
  // Les lectures simples (GET) ne comptent pas — évite les faux positifs
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

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
