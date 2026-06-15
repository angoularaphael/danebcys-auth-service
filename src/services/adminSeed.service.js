// Crée les comptes admin, vendeur et assistance au démarrage
const { query } = require('../config/database');
const { hashPassword } = require('../utils/hash');

// Crée ou met à jour le compte super-administrateur au démarrage du service
async function seedSuperAdmin(pepper) {
  const adminRole = await query("SELECT id FROM roles WHERE name = 'admin'");
  if (adminRole.rows.length === 0) {
    throw new Error('Rôle admin introuvable');
  }

  const { salt, hash } = await hashPassword('#Fareno12', pepper);
  const roleId = adminRole.rows[0].id;
  const email = 'giffareno05@gmail.com';

  const existing = await query(
    'SELECT id FROM users WHERE email = $1',
    [email]
  );

  if (existing.rows.length > 0) {
    await query(
      `UPDATE users
       SET password_hash = $1,
           salt = $2,
           role_id = $3,
           email_verified = TRUE,
           deleted = FALSE
       WHERE email = $4`,
      [hash, salt, roleId, email]
    );
    return { created: false, email };
  }

  await query(
    `INSERT INTO users (username, email, password_hash, salt, role_id, email_verified, deleted)
     VALUES ($1, $2, $3, $4, $5, TRUE, FALSE)`,
    ['giffareno', email, hash, salt, roleId]
  );

  return { created: true, email };
}

// Crée ou met à jour les comptes vendeur et assistance de démonstration au démarrage
async function seedVendeurAndAssistance(pepper) {
  const vendeurRole = await query("SELECT id FROM roles WHERE name = 'vendeur'");
  const assistanceRole = await query("SELECT id FROM roles WHERE name = 'assistance'");
  if (vendeurRole.rows.length === 0 || assistanceRole.rows.length === 0) {
    throw new Error('Rôles vendeur ou assistance introuvables');
  }

  const results = [];

  // Vendeur: vendeur-danebcys@gmail.com, mdp 12345678, vérifié, avec plan
  const vendeurEmail = 'vendeur-danebcys@gmail.com';
  const vendeurPass = await hashPassword('12345678', pepper);
  const existingVendeur = await query('SELECT id FROM users WHERE email = $1', [vendeurEmail]);
  if (existingVendeur.rows.length > 0) {
    await query(
      `UPDATE users SET password_hash = $1, salt = $2, role_id = $3, email_verified = TRUE, deleted = FALSE WHERE email = $4`,
      [vendeurPass.hash, vendeurPass.salt, vendeurRole.rows[0].id, vendeurEmail]
    );
    results.push({ email: vendeurEmail, role: 'vendeur', created: false });
  } else {
    await query(
      `INSERT INTO users (username, email, password_hash, salt, role_id, email_verified, deleted)
       VALUES ($1, $2, $3, $4, $5, TRUE, FALSE)`,
      ['vendeur-danebcys', vendeurEmail, vendeurPass.hash, vendeurPass.salt, vendeurRole.rows[0].id]
    );
    results.push({ email: vendeurEmail, role: 'vendeur', created: true });
  }

  // Assistance: assistance-danebcys@gmail.com, mdp 12345678, vérifié
  const assistanceEmail = 'assistance-danebcys@gmail.com';
  const assistancePass = await hashPassword('12345678', pepper);
  const existingAssistance = await query('SELECT id FROM users WHERE email = $1', [assistanceEmail]);
  if (existingAssistance.rows.length > 0) {
    await query(
      `UPDATE users SET password_hash = $1, salt = $2, role_id = $3, email_verified = TRUE, deleted = FALSE WHERE email = $4`,
      [assistancePass.hash, assistancePass.salt, assistanceRole.rows[0].id, assistanceEmail]
    );
    results.push({ email: assistanceEmail, role: 'assistance', created: false });
  } else {
    await query(
      `INSERT INTO users (username, email, password_hash, salt, role_id, email_verified, deleted)
       VALUES ($1, $2, $3, $4, $5, TRUE, FALSE)`,
      ['assistance-danebcys', assistanceEmail, assistancePass.hash, assistancePass.salt, assistanceRole.rows[0].id]
    );
    results.push({ email: assistanceEmail, role: 'assistance', created: true });
  }

  return results;
}

module.exports = { seedSuperAdmin, seedVendeurAndAssistance };
