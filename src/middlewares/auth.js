const tokenService = require('../services/token.service');
const { UnauthorizedError } = require('../utils/errors');

async function authenticate(req, _res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedError('Token manquant');
    }

    const token = header.split(' ')[1];
    const validated = await tokenService.validateAccessToken(token);
    req.accessToken = token;
    req.user = validated.user;
    next();
  } catch (_err) {
    next(new UnauthorizedError('Token invalide ou expiré'));
  }
}

module.exports = { authenticate };
