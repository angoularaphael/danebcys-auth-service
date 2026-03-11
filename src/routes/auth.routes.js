const { Router } = require('express');
const controller = require('../controllers/auth.controller');
const { authenticate } = require('../middlewares/auth');
const { verifyPow } = require('../middlewares/pow');
const { tokenLimiter, preAuthTokenLimiter, challengeLimiter } = require('../middlewares/rateLimiter');

const router = Router();

router.get('/pow-challenge', challengeLimiter, controller.getChallenge);

router.post('/signup', verifyPow, controller.signup);
router.post('/login', verifyPow, controller.login);
router.post('/forgot-password', verifyPow, controller.forgotPassword);
router.post('/reset-password', verifyPow, controller.resetPassword);

router.post('/refresh', preAuthTokenLimiter, controller.refresh);

router.post('/logout', authenticate, tokenLimiter, controller.logout);
router.get('/me', authenticate, tokenLimiter, controller.getMe);
router.put('/me/password', authenticate, tokenLimiter, controller.changePassword);
router.post('/me/revoke-sessions', authenticate, tokenLimiter, controller.revokeOtherSessions);
router.post('/verify-email', authenticate, tokenLimiter, controller.verifyEmail);
router.post('/resend-email-code', authenticate, tokenLimiter, controller.resendEmailCode);
router.post('/send-phone-code', authenticate, tokenLimiter, controller.sendPhoneCode);
router.post('/verify-phone', authenticate, tokenLimiter, controller.verifyPhone);

module.exports = router;
