const authService = require('../services/auth.service');
const { createChallenge } = require('../middlewares/pow');
const { BadRequestError } = require('../utils/errors');

function extractContext(req) {
  return {
    userAgent: req.headers['user-agent'] || '',
    clientIp: req.clientIp || req.ip
  };
}

async function signup(req, res, next) {
  try {
    const { email, password, username, firstName, lastName, phone, country } = req.body;

    if (!email || !password || !username) {
      throw new BadRequestError('email, password et username sont requis');
    }
    if (password.length < 8) {
      throw new BadRequestError('Le mot de passe doit contenir au moins 8 caractères');
    }

    const result = await authService.signup(
      { email, password, username, firstName, lastName, phone, country },
      extractContext(req)
    );
    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new BadRequestError('email et password sont requis');
    }

    const result = await authService.login(
      { email, password },
      extractContext(req)
    );
    res.json(result);
  } catch (err) {
    next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new BadRequestError('refreshToken est requis');
    }

    const result = await authService.refresh(refreshToken, extractContext(req));
    res.json(result);
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new BadRequestError('refreshToken est requis');
    }

    await authService.logout(refreshToken, req.accessToken);
    res.json({ message: 'Déconnexion réussie' });
  } catch (err) {
    next(err);
  }
}

async function getMe(req, res, next) {
  try {
    const user = await authService.getMe(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json({ user });
  } catch (err) {
    next(err);
  }
}

async function verifyEmail(req, res, next) {
  try {
    const { code } = req.body;

    if (!code) {
      throw new BadRequestError('code est requis');
    }

    await authService.verifyEmail(req.user.id, code);
    res.json({ message: 'Email vérifié avec succès' });
  } catch (err) {
    next(err);
  }
}

async function resendEmailCode(req, res, next) {
  try {
    const result = await authService.resendEmailVerificationCode(req.user.id);
    res.json(result);
  } catch (err) {
    next(err);
  }
}

function getChallenge(_req, res) {
  const challenge = createChallenge();
  res.json(challenge);
}

async function forgotPassword(req, res, next) {
  try {
    const { email } = req.body;

    if (!email) {
      throw new BadRequestError('email est requis');
    }

    await authService.forgotPassword(email);
    res.json({ message: 'Si un compte existe avec cet email, un code de réinitialisation a été envoyé' });
  } catch (err) {
    next(err);
  }
}

async function resetPassword(req, res, next) {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      throw new BadRequestError('email, code et newPassword sont requis');
    }
    if (newPassword.length < 8) {
      throw new BadRequestError('Le nouveau mot de passe doit contenir au moins 8 caractères');
    }

    await authService.resetPassword(email, code, newPassword);
    res.json({ message: 'Mot de passe réinitialisé avec succès' });
  } catch (err) {
    next(err);
  }
}

async function sendPhoneCode(req, res, next) {
  try {
    await authService.requestPhoneVerification(req.user.id);
    res.json({ message: 'Code de vérification envoyé par SMS' });
  } catch (err) {
    next(err);
  }
}

async function verifyPhone(req, res, next) {
  try {
    const { code } = req.body;
    if (!code) throw new BadRequestError('code est requis');

    await authService.verifyPhone(req.user.id, code);
    res.json({ message: 'Téléphone vérifié avec succès' });
  } catch (err) {
    next(err);
  }
}

async function changePassword(req, res, next) {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      throw new BadRequestError('currentPassword et newPassword sont requis');
    }

    await authService.changePassword(req.user.id, currentPassword, newPassword);
    res.json({ message: 'Mot de passe modifié avec succès' });
  } catch (err) {
    next(err);
  }
}

async function revokeOtherSessions(req, res, next) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new BadRequestError('refreshToken est requis');
    }

    await authService.revokeOtherSessions(req.user.id, refreshToken);
    res.json({ message: 'Toutes les autres sessions ont été fermées' });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  signup,
  login,
  refresh,
  logout,
  getMe,
  verifyEmail,
  resendEmailCode,
  verifyPhone,
  sendPhoneCode,
  getChallenge,
  forgotPassword,
  resetPassword,
  changePassword,
  revokeOtherSessions
};
