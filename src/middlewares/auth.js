const tokenService = require('../services/token.service');
const { UnauthorizedError } = require('../utils/errors');

function authenticate(req, _res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedError('Token manquant');
    }

    const token = header.split(' ')[1];
    const payload = tokenService.verifyAccessToken(token);
    req.user = { id: payload.sub, email: payload.email, role: payload.role };
    next();
  } catch (_err) {
    next(new UnauthorizedError('Token invalide ou expiré'));
  }
}

module.exports = { authenticate };
