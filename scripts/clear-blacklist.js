/**
 * Vide la table token_blacklist (tokens révoqués).
 * Utile pour retester sans être bloqué par des tokens blacklistés.
 *
 * Exécuter :
 *   npm run clear-blacklist
 *   ou : node scripts/clear-blacklist.js
 *
 * Avec Docker :
 *   docker compose exec auth-service npm run clear-blacklist
 */
require('dotenv').config();
const { pool } = require('../src/config/database');

async function run() {
  const client = await pool.connect();
  try {
    const result = await client.query('DELETE FROM token_blacklist');
    console.log('Blacklist vidée :', result.rowCount, 'entrée(s) supprimée(s).');
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch((e) => {
  console.error('Erreur:', e.message);
  process.exit(1);
});
