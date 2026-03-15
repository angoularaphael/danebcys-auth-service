require('dotenv').config();

const app = require('./src/app');
const { pool, initDB } = require('./src/config/database');
const { initPepper, getPepper } = require('./src/services/pepper.service');
const { seedSuperAdmin, seedVendeurAndAssistance } = require('./src/services/adminSeed.service');
const { verifyTransporter } = require('./src/services/mail.service');
const env = require('./src/config/env');

async function start() {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('[Auth Service] PostgreSQL connecté');

    await initDB();

    await initPepper();

    const seeded = await seedSuperAdmin(getPepper());
    console.log(
      seeded.created
        ? `[seed] Super admin créé: ${seeded.email}`
        : `[seed] Super admin mis à jour: ${seeded.email}`
    );

    const vendeurAssistance = await seedVendeurAndAssistance(getPepper());
    for (const r of vendeurAssistance) {
      console.log(`[seed] ${r.role} ${r.created ? 'créé' : 'mis à jour'}: ${r.email} (mdp: 12345678)`);
    }

    const mailOk = await verifyTransporter();
    if (!mailOk) {
      console.warn('[Auth Service] Email non configuré ou invalide. Les vérifications email et reset password ne fonctionneront pas.');
    }

    app.listen(env.PORT, () => {
      console.log(`[Auth Service] Démarré sur le port ${env.PORT}`);
    });
  } catch (err) {
    console.error('[Auth Service] Erreur au démarrage:', err.message);
    process.exit(1);
  }
}

start();
