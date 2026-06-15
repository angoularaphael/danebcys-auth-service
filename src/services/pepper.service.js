// Récupère et conserve le pepper primaire depuis pepper-primary pour le hashage des mots de passe
const crypto = require('crypto');
const http = require('http');
const env = require('../config/env');

// Secret pepper en mémoire uniquement (jamais écrit sur disque par Auth-service)
let pepper = null;

// Récupère le pepper depuis pepper-primary au démarrage
async function initPepper() {
  if (!env.PEPPER_PRIMARY_URL) {
    if (env.NODE_ENV === 'development') {
      console.warn('[pepper] Aucun pepper service configuré — fallback dev');
      pepper = crypto.createHash('sha256').update('dev-fallback-pepper').digest('hex');
      return;
    }
    throw new Error('PEPPER_PRIMARY_URL requis en production');
  }

  try {
    pepper = await fetchPepper(env.PEPPER_PRIMARY_URL, env.PEPPER_PRIMARY_KEY, 'Primary');
    console.log('[pepper] Pepper externe initialisé');
  } catch (err) {
    if (env.NODE_ENV === 'development') {
      console.error('[pepper] Erreur:', err.message);
      console.warn('[pepper] Fallback dev activé');
      pepper = crypto.createHash('sha256').update('dev-fallback-pepper').digest('hex');
    } else {
      throw err;
    }
  }
}

function getPepper() {
  if (!pepper) {
    throw new Error('Pepper non initialisé — appelez initPepper() au démarrage');
  }
  return pepper;
}

function fetchPepper(baseUrl, serviceKey, label) {
  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl);

    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: '/pepper',
      method: 'GET',
      headers: {
        'X-Service-Key': serviceKey,
        Accept: 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`Pepper ${label} HTTP ${res.statusCode}: ${data}`));
        }
        try {
          const body = JSON.parse(data);
          resolve(body.pepper);
        } catch (e) {
          reject(new Error(`Pepper ${label} réponse invalide`));
        }
      });
    });

    req.on('error', (err) => reject(new Error(`Pepper ${label}: ${err.message}`)));
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error(`Pepper ${label} timeout (5s)`));
    });
    req.end();
  });
}

module.exports = { initPepper, getPepper };
