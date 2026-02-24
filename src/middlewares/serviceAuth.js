const { safeCompare } = require('../utils/hash');
const env = require('../config/env');

/**
 * Authentification inter-microservices.
 * Les services internes s'authentifient via le header X-Service-Key.
 * La comparaison utilise SHA-256 + timingSafeEqual (pas de timing leak).
 */
function serviceAuth(req, res, next) {
  const key = req.headers['x-service-key'];

  if (!key) {
    return res.status(401).json({ error: 'Header X-Service-Key manquant' });
  }

  if (!safeCompare(key, env.INTER_SERVICE_KEY)) {
    return res.status(403).json({ error: 'Clé de service invalide' });
  }

  req.isService = true;
  next();
}

module.exports = { serviceAuth };
