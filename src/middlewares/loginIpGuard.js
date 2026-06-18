// Refuse la connexion si l'adresse IP est bloquée (trop d'échecs de mot de passe)
const loginSecurity = require('../services/loginSecurity.service');

function loginIpGuard(req, res, next) {
  const ip = req.clientIp || req.ip;
  if (!loginSecurity.isIpBlocked(ip)) {
    return next();
  }

  const expiresAt = loginSecurity.getBlockExpiresAt(ip);
  const retryAfterSec = expiresAt
    ? Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000))
    : 1800;

  res.setHeader('Retry-After', String(retryAfterSec));
  return res.status(403).json({
    error: `Adresse IP temporairement bloquée après ${loginSecurity.MAX_ATTEMPTS} tentatives de connexion échouées. Réessayez dans ${Math.ceil(retryAfterSec / 60)} minute(s).`
  });
}

module.exports = { loginIpGuard };
