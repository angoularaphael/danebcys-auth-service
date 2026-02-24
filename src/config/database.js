const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const env = require('./env');

const pool = new Pool({
  host: env.PG_HOST,
  port: env.PG_PORT,
  database: env.PG_DATABASE,
  user: env.PG_USER,
  password: env.PG_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

pool.on('error', (err) => {
  console.error('[database] Erreur inattendue du pool:', err.message);
});

async function query(text, params) {
  const start = Date.now();
  const result = await pool.query(text, params);
  if (env.NODE_ENV === 'development') {
    const duration = Date.now() - start;
    console.log('[query]', { text: text.substring(0, 80), duration: `${duration}ms`, rows: result.rowCount });
  }
  return result;
}

async function getClient() {
  return pool.connect();
}

async function initDB() {
  const sqlPath = path.join(__dirname, '..', '..', 'init.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');
  try {
    await pool.query(sql);
    console.log('[database] Schema initialisé avec succès');
  } catch (err) {
    console.error('[database] Erreur initialisation:', err.message);
    throw err;
  }
}

module.exports = { pool, query, getClient, initDB };
