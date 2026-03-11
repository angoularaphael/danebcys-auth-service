require('dotenv').config();

const { pool, initDB } = require('../src/config/database');
const { initPepper, getPepper } = require('../src/services/pepper.service');
const { seedSuperAdmin } = require('../src/services/adminSeed.service');

async function run() {
  try {
    await initDB();
    await initPepper();
    const result = await seedSuperAdmin(getPepper());
    console.log(
      result.created
        ? `[seed] Super admin créé: ${result.email}`
        : `[seed] Super admin mis à jour: ${result.email}`
    );
    await pool.end();
    process.exit(0);
  } catch (error) {
    console.error('[seed] Erreur super admin:', error.message);
    await pool.end();
    process.exit(1);
  }
}

run();
