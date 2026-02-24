const crypto = require('crypto');
const http = require('http');
const env = require('../config/env');

let combinedPepper = null;

/**
 * Double pepper entièrement externe :
 *  - Pepper primaire : récupéré depuis pepper-primary (microservice)
 *  - Pepper secondaire : récupéré depuis pepper-service (microservice)
 *  - Combinaison : HMAC-SHA256(primary, secondary)
 *
 * Le Auth Service ne stocke AUCUN pepper.
 * En dev, si les services sont indisponibles, fallback sur un hash déterministe.
 */
async function initPepper() {
  const hasPrimary = !!env.PEPPER_PRIMARY_URL;
  const hasSecondary = !!env.PEPPER_SECONDARY_URL;

  if (!hasPrimary && !hasSecondary) {
    if (env.NODE_ENV === 'development') {
      console.warn('[pepper] Aucun Pepper Service configuré — fallback dev');
      combinedPepper = crypto.createHash('sha256').update('dev-fallback-pepper').digest('hex');
      return;
    }
    throw new Error('PEPPER_PRIMARY_URL et PEPPER_SECONDARY_URL requis en production');
  }

  try {
    const results = await Promise.all([
      hasPrimary
        ? fetchPepper(env.PEPPER_PRIMARY_URL, env.PEPPER_PRIMARY_KEY, 'Primary')
        : null,
      hasSecondary
        ? fetchPepper(env.PEPPER_SECONDARY_URL, env.PEPPER_SECONDARY_KEY, 'Secondary')
        : null
    ]);

    const primary = results[0];
    const secondary = results[1];

    if (primary && secondary) {
      combinedPepper = crypto
        .createHmac('sha256', primary)
        .update(secondary)
        .digest('hex');
      console.log('[pepper] Double pepper initialisé (primary + secondary)');
    } else if (primary) {
      combinedPepper = crypto.createHash('sha256').update(primary).digest('hex');
      console.warn('[pepper] Seul le pepper primaire est disponible');
    } else {
      combinedPepper = crypto.createHash('sha256').update(secondary).digest('hex');
      console.warn('[pepper] Seul le pepper secondaire est disponible');
    }
  } catch (err) {
    if (env.NODE_ENV === 'development') {
      console.error('[pepper] Erreur:', err.message);
      console.warn('[pepper] Fallback dev activé');
      combinedPepper = crypto.createHash('sha256').update('dev-fallback-pepper').digest('hex');
    } else {
      throw err;
    }
  }
}

function getPepper() {
  if (!combinedPepper) {
    throw new Error('Pepper non initialisé — appelez initPepper() au démarrage');
  }
  return combinedPepper;
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
        'Accept': 'application/json'
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
