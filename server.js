require('dotenv').config();

const app = require('./src/app');
const { pool, initDB, query } = require('./src/config/database');
const { initPepper, getPepper } = require('./src/services/pepper.service');
const { hashPassword } = require('./src/utils/hash');
const env = require('./src/config/env');

async function seedAdmin() {
  const adminRole = await query("SELECT id FROM roles WHERE name = 'admin'");
  if (adminRole.rows.length === 0) {
    console.error('[seed] Rôle admin introuvable');
    return;
  }

  const pepper = getPepper();
  const { salt, hash } = await hashPassword('#Fareno12', pepper);

  const existing = await query(
    "SELECT id FROM users WHERE email = 'giffareno05@gmail.com'"
  );

  if (existing.rows.length > 0) {
    await query(
      'UPDATE users SET password_hash = $1, salt = $2, role_id = $3, deleted = FALSE WHERE email = $4',
      [hash, salt, adminRole.rows[0].id, 'giffareno05@gmail.com']
    );
    console.log('[seed] Super admin mis à jour avec le pepper actuel');
    return;
  }

  await query(
    `INSERT INTO users (username, email, password_hash, salt, role_id, email_verified)
     VALUES ($1, $2, $3, $4, $5, TRUE)`,
    ['giffareno', 'giffareno05@gmail.com', hash, salt, adminRole.rows[0].id]
  );

  console.log('[seed] Super admin créé : giffareno (giffareno05@gmail.com)');
}

async function start() {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('[Auth Service] PostgreSQL connecté');

    await initDB();

    await initPepper();

    await seedAdmin();

    app.listen(env.PORT, () => {
      console.log(`[Auth Service] Démarré sur le port ${env.PORT}`);
    });
  } catch (err) {
    console.error('[Auth Service] Erreur au démarrage:', err.message);
    process.exit(1);
  }
}

start();
