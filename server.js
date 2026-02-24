require('dotenv').config();

const app = require('./src/app');
const { pool, initDB } = require('./src/config/database');
const { initPepper } = require('./src/services/pepper.service');
const env = require('./src/config/env');

async function start() {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('[Auth Service] PostgreSQL connecté');

    await initDB();

    await initPepper();

    app.listen(env.PORT, () => {
      console.log(`[Auth Service] Démarré sur le port ${env.PORT}`);
    });
  } catch (err) {
    console.error('[Auth Service] Erreur au démarrage:', err.message);
    process.exit(1);
  }
}

start();
