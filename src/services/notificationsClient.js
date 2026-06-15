// Client HTTP vers Communication-service pour les notifications
const http = require('http');
const https = require('https');
const env = require('../config/env');

// Appelle Communication-service (port 3006) pour créer une notification
function callNotifications(userId, type, message) {
  return new Promise((resolve, reject) => {
    const baseUrl = env.NOTIFICATIONS_SERVICE_URL || 'http://localhost:3006';
    const url = new URL(baseUrl + '/internal/notifications');
    const transport = url.protocol === 'https:' ? https : http;

    const body = JSON.stringify({ userId, type, message });

    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Service-Key': env.INTER_SERVICE_KEY || ''
      }
    };

    const req = transport.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          try {
            const parsed = JSON.parse(data);
            return reject(new Error(parsed.error || 'Notifications Service error'));
          } catch (_e) {
            return reject(new Error('Notifications Service error'));
          }
        }
        resolve({ created: true });
      });
    });

    req.on('error', (e) => reject(new Error(`Notifications: ${e.message}`)));
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

// Envoie une notification à tous les administrateurs — appelle Communication-service port 3006
async function sendToAdmins(type, message) {
  const { query } = require('../config/database');
  try {
    const result = await query(
      `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'admin' AND u.deleted = FALSE`
    );
    const adminIds = result.rows.map((r) => r.id);
    for (const adminId of adminIds) {
      await callNotifications(adminId, type, message).catch((err) =>
        console.error('[notificationsClient] Échec envoi admin', adminId, err.message)
      );
    }
  } catch (err) {
    console.error('[notificationsClient] Échec récupération admins:', err.message);
  }
}

module.exports = { callNotifications, sendToAdmins };
