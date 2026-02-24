const { Router } = require('express');
const { serviceAuth } = require('../middlewares/serviceAuth');
const jwt = require('../utils/jwt');
const env = require('../config/env');
const { query } = require('../config/database');

const router = Router();

/**
 * POST /internal/validate-token
 * Permet aux autres microservices de valider un access token
 * sans connaître le secret JWT.
 * Protégé par X-Service-Key.
 */
router.post('/validate-token', serviceAuth, async (req, res) => {
  try {
    const { accessToken } = req.body;
    if (!accessToken) {
      return res.status(400).json({ valid: false, error: 'accessToken requis' });
    }

    const payload = jwt.verify(accessToken, env.JWT_ACCESS_SECRET);

    const result = await query(
      'SELECT id, email, role FROM users WHERE id = $1 AND deleted = FALSE',
      [payload.sub]
    );

    if (result.rows.length === 0) {
      return res.json({ valid: false, error: 'Utilisateur non trouvé' });
    }

    res.json({ valid: true, user: result.rows[0] });
  } catch (err) {
    res.json({ valid: false, error: err.message });
  }
});

module.exports = router;
