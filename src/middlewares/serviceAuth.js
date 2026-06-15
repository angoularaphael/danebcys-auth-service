// Vérifie la clé X-Service-Key pour protéger les routes /internal
const { safeCompare } = require('../utils/hash');
const env = require('../config/env');

// Vérifie la clé secrète X-Service-Key — protège les routes /internal
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
