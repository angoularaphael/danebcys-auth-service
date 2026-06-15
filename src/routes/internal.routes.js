// Routes réservées aux autres microservices — montées sur /internal
const { Router } = require('express');
const { serviceAuth } = require('../middlewares/serviceAuth');
const tokenService = require('../services/token.service');
const { query } = require('../config/database');

const router = Router();

router.use(serviceAuth);

// Liste les identifiants des administrateurs — GET /internal/admins
router.get('/admins', async (_req, res) => {
  try {
    const result = await query(
      `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'admin' AND u.deleted = FALSE`
    );
    res.json({ adminIds: result.rows.map((r) => r.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Vérifie un jeton de connexion et renvoie l'utilisateur — POST /internal/validate-token
router.post('/validate-token', async (req, res) => {
  try {
    const { accessToken } = req.body;
    if (!accessToken) {
      return res.status(400).json({ valid: false, error: 'accessToken requis' });
    }

    const validated = await tokenService.validateAccessToken(accessToken);
    res.json({ valid: true, user: validated.user });
  } catch (err) {
    res.json({ valid: false, error: err.message });
  }
});

// Liste les utilisateurs avec recherche et pagination — GET /internal/users
router.get('/users', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;
    const { search, role, deleted } = req.query;

    let where = [];
    let params = [];
    let idx = 1;

    if (deleted === 'true') {
      where.push(`u.deleted = TRUE`);
    } else if (deleted === 'all') {
      // Pas de filtre sur les comptes supprimés
    } else {
      where.push(`u.deleted = FALSE`);
    }

    if (search) {
      where.push(`(u.email ILIKE $${idx} OR u.username ILIKE $${idx} OR u.first_name ILIKE $${idx} OR u.last_name ILIKE $${idx})`);
      params.push(`%${search}%`);
      idx++;
    }

    if (role) {
      where.push(`r.name = $${idx}`);
      params.push(role);
      idx++;
    }

    const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

    const countResult = await query(
      `SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id = r.id ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0].count, 10);

    const result = await query(
      `SELECT u.id, u.username, u.email, u.phone, u.first_name, u.last_name,
              u.email_verified, u.phone_verified, u.role_id, r.name AS role,
              u.premium_level, u.student_proof, u.country, u.deleted,
              u.created_at, u.updated_at, u.last_login_at
       FROM users u
       JOIN roles r ON u.role_id = r.id
       ${whereClause}
       ORDER BY u.created_at DESC
       LIMIT $${idx} OFFSET $${idx + 1}`,
      [...params, limit, offset]
    );

    res.json({
      users: result.rows,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupère un utilisateur par identifiant — GET /internal/users/:id
router.get('/users/:id', async (req, res) => {
  try {
    const result = await query(
      `SELECT u.id, u.username, u.email, u.phone, u.first_name, u.last_name,
              u.email_verified, u.phone_verified, u.role_id, r.name AS role,
              u.premium_level, u.student_proof, u.country, u.deleted,
              u.created_at, u.updated_at, u.last_login_at
       FROM users u
       JOIN roles r ON u.role_id = r.id
       WHERE u.id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Met à jour le profil d'un utilisateur — PUT /internal/users/:id
router.put('/users/:id', async (req, res) => {
  try {
    const { username, firstName, lastName, phone, country } = req.body;

    const fields = [];
    const params = [];
    let idx = 1;

    if (username !== undefined) { fields.push(`username = $${idx++}`); params.push(username); }
    if (firstName !== undefined) { fields.push(`first_name = $${idx++}`); params.push(firstName); }
    if (lastName !== undefined) { fields.push(`last_name = $${idx++}`); params.push(lastName); }
    if (phone !== undefined) { fields.push(`phone = $${idx++}`); params.push(phone || null); }
    if (country !== undefined) { fields.push(`country = $${idx++}`); params.push(country || null); }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'Aucun champ à mettre à jour' });
    }

    params.push(req.params.id);

    const result = await query(
      `UPDATE users SET ${fields.join(', ')}
       WHERE id = $${idx} AND deleted = FALSE
       RETURNING id, username, email, phone, first_name, last_name,
                 email_verified, phone_verified, role_id, premium_level,
                 student_proof, country, created_at, updated_at, last_login_at`,
      params
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username, email ou téléphone déjà utilisé' });
    }
    res.status(500).json({ error: err.message });
  }
});

// Change le rôle d'un utilisateur — PUT /internal/users/:id/role
router.put('/users/:id/role', async (req, res) => {
  try {
    const { roleId } = req.body;
    if (!roleId) return res.status(400).json({ error: 'roleId requis' });

    const result = await query(
      `UPDATE users u SET role_id = $1
       FROM roles r
       WHERE u.id = $2 AND u.deleted = FALSE AND r.id = $1
       RETURNING u.id, u.username, u.email, u.role_id, r.name AS role`,
      [roleId, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23503') {
      return res.status(400).json({ error: 'Rôle invalide' });
    }
    res.status(500).json({ error: err.message });
  }
});

// Met à jour le niveau premium d'un utilisateur — PUT /internal/users/:id/premium
router.put('/users/:id/premium', async (req, res) => {
  try {
    const { premiumLevel, studentProof } = req.body;
    if (!premiumLevel) return res.status(400).json({ error: 'premiumLevel requis' });

    const fields = ['premium_level = $1'];
    const params = [premiumLevel];
    let idx = 2;

    if (studentProof !== undefined) {
      fields.push(`student_proof = $${idx++}`);
      params.push(studentProof);
    }

    params.push(req.params.id);

    const result = await query(
      `UPDATE users SET ${fields.join(', ')}
       WHERE id = $${idx} AND deleted = FALSE
       RETURNING id, username, email, premium_level, student_proof`,
      params
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.message.includes('premium_level_enum')) {
      return res.status(400).json({ error: 'Niveau premium invalide (none, premium, premium_avancee, etudiant)' });
    }
    res.status(500).json({ error: err.message });
  }
});

// Désactive un compte sans effacer les données — DELETE /internal/users/:id
router.delete('/users/:id', async (req, res) => {
  try {
    const result = await query(
      `UPDATE users SET deleted = TRUE WHERE id = $1 AND deleted = FALSE RETURNING id`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ message: 'Utilisateur supprimé (soft delete)' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Réactive un compte précédemment désactivé — PUT /internal/users/:id/restore
router.put('/users/:id/restore', async (req, res) => {
  try {
    const result = await query(
      `UPDATE users u SET deleted = FALSE
       FROM roles r
       WHERE u.id = $1 AND u.deleted = TRUE AND u.role_id = r.id
       RETURNING u.id, u.username, u.email, u.role_id, r.name AS role`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé ou non supprimé' });
    }

    res.json({ message: 'Utilisateur restauré', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Conflit : un utilisateur actif a déjà cet email ou username' });
    }
    res.status(500).json({ error: err.message });
  }
});

// Liste tous les rôles disponibles — GET /internal/roles
router.get('/roles', async (_req, res) => {
  try {
    const result = await query('SELECT id, name, description FROM roles ORDER BY id');
    res.json({ roles: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
