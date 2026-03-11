const tokenService = require('../services/token.service');

function extractBearerToken(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return null;
  }
  return header.slice('Bearer '.length).trim();
}

async function validateAndAttachUser(req) {
  if (req.authValidated) {
    return req.user || null;
  }

  const token = extractBearerToken(req);
  req.authValidated = true;

  if (!token) {
    return null;
  }

  try {
    const result = await tokenService.validateAccessToken(token);
    req.accessToken = token;
    req.user = result.user;
    return result.user;
  } catch (err) {
    const error = new Error(err.message || 'Token invalide');
    error.statusCode = 401;
    throw error;
  }
}

async function authenticateRequired(req, _res, next) {
  try {
    const token = extractBearerToken(req);
    if (!token) {
      const err = new Error('Token manquant');
      err.statusCode = 401;
      throw err;
    }

    await validateAndAttachUser(req);
    next();
  } catch (err) {
    next(err);
  }
}

async function authenticateOptional(req, _res, next) {
  try {
    await validateAndAttachUser(req);
    next();
  } catch (_err) {
    next();
  }
}

module.exports = {
  authenticateRequired,
  authenticateOptional
};
