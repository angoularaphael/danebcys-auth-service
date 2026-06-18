// Envoi d'emails via Gmail (vérification, réinitialisation mot de passe)
const nodemailer = require('nodemailer');
const env = require('../config/env');

// Connexion Gmail pour envoyer les emails (créée à la première utilisation)
let transporter = null;
// Indique si la connexion Gmail a été testée avec succès
let verified = false;

// Prépare l'envoi d'emails via Gmail
function getTransporter() {
  if (!transporter) {
    if (!env.EMAIL_USER || !env.EMAIL_PASS) {
      console.error('[mail] EMAIL_USER et EMAIL_PASS doivent être définis. Pour Gmail, utilisez un mot de passe d\'application (https://myaccount.google.com/apppasswords).');
      throw new Error('Configuration email manquante (EMAIL_USER, EMAIL_PASS)');
    }
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: env.EMAIL_USER,
        pass: env.EMAIL_PASS
      }
    });
  }
  return transporter;
}

// Teste la connexion Gmail au démarrage
async function verifyTransporter() {
  if (verified) return true;
  try {
    const t = getTransporter();
    await t.verify();
    verified = true;
    console.log('[mail] Connexion SMTP vérifiée avec succès');
    return true;
  } catch (err) {
    console.error('[mail] Échec vérification SMTP:', err.message);
    console.error('[mail] Vérifiez EMAIL_USER, EMAIL_PASS (mot de passe d\'application Gmail) et que "Accès aux applications moins sécurisées" est activé si nécessaire.');
    return false;
  }
}

// Envoie un email avec le code de vérification d'adresse (6 chiffres)
async function sendVerificationEmail(to, code) {
  const mailOptions = {
    from: `"DANEBCYS" <${env.EMAIL_USER}>`,
    to,
    subject: 'Vérification de votre adresse email',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px;">
        <h2 style="color: #333;">Vérification email</h2>
        <p>Votre code de vérification est :</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center;
                    padding: 16px; background: #f4f4f4; border-radius: 8px; margin: 16px 0;">
          ${code}
        </div>
        <p>Ce code expire dans <strong>15 minutes</strong>.</p>
        <p style="color: #888; font-size: 12px;">Si vous n'avez pas demandé ce code, ignorez cet email.</p>
      </div>
    `
  };

  try {
    return await getTransporter().sendMail(mailOptions);
  } catch (err) {
    console.error('[mail] Échec envoi email de vérification à', to, ':', err.message);
    throw err;
  }
}

// Envoie un email avec le code de réinitialisation de mot de passe
async function sendPasswordResetEmail(to, code) {
  const mailOptions = {
    from: `"DANEBCYS" <${env.EMAIL_USER}>`,
    to,
    subject: 'Réinitialisation de votre mot de passe',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px;">
        <h2 style="color: #333;">Réinitialisation du mot de passe</h2>
        <p>Vous avez demandé une réinitialisation de mot de passe. Votre code est :</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center;
                    padding: 16px; background: #f4f4f4; border-radius: 8px; margin: 16px 0;">
          ${code}
        </div>
        <p>Ce code expire dans <strong>15 minutes</strong>.</p>
        <p style="color: #888; font-size: 12px;">Si vous n'avez pas fait cette demande, ignorez cet email. Votre mot de passe restera inchangé.</p>
      </div>
    `
  };

  return getTransporter().sendMail(mailOptions);
}

// Envoie un SMS de vérification — en développement, le code s'affiche dans la console
async function sendPhoneVerificationSms(phone, code) {
  if (env.NODE_ENV === 'development') {
    console.log(`[SMS STUB] Code de vérification pour ${phone} : ${code}`);
    return;
  }

  // TODO: Intégrer Twilio en production
  // const twilio = require('twilio')(env.TWILIO_SID, env.TWILIO_AUTH_TOKEN);
  // await twilio.messages.create({
  //   body: `Votre code de vérification : ${code}`,
  //   from: env.TWILIO_PHONE,
  //   to: phone
  // });
  console.warn('[SMS] Twilio non configuré, code non envoyé:', code);
}

function formatSecurityEmailHtml({ title, intro, rows }) {
  const rowsHtml = rows
    .map(
      ({ label, value }) =>
        `<tr><td style="padding:8px 12px;color:#666;vertical-align:top;">${label}</td>`
        + `<td style="padding:8px 12px;font-weight:600;">${value}</td></tr>`
    )
    .join('');

  return `
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; padding: 24px;">
      <h2 style="color: #333;">${title}</h2>
      <p>${intro}</p>
      <table style="width:100%;border-collapse:collapse;background:#f9f9f9;border-radius:8px;margin:16px 0;">
        ${rowsHtml}
      </table>
      <p style="color: #888; font-size: 12px;">Si vous n'êtes pas à l'origine de cette activité, changez votre mot de passe et contactez l'assistance.</p>
    </div>
  `;
}

// Alerte : nouvelle connexion réussie (navigateur, IP, position approximative)
async function sendLoginAlertEmail(to, { browser, ip, location, loginAt }) {
  const mailOptions = {
    from: `"DANEBCYS Sécurité" <${env.EMAIL_USER}>`,
    to,
    subject: 'Nouvelle connexion à votre compte DANEBCYS',
    html: formatSecurityEmailHtml({
      title: 'Connexion détectée',
      intro: 'Une connexion vient d\'être effectuée sur votre compte :',
      rows: [
        { label: 'Date', value: loginAt },
        { label: 'Navigateur', value: browser || 'Inconnu' },
        { label: 'Adresse IP', value: ip || 'Inconnue' },
        { label: 'Position approx.', value: location || 'Non disponible' }
      ]
    })
  };

  try {
    return await getTransporter().sendMail(mailOptions);
  } catch (err) {
    console.error('[mail] Échec alerte connexion à', to, ':', err.message);
  }
}

// Alerte : 5 échecs de mot de passe — IP bloquée
async function sendLoginBlockedEmail(to, { ip, attempts, blockMinutes }) {
  const mailOptions = {
    from: `"DANEBCYS Sécurité" <${env.EMAIL_USER}>`,
    to,
    subject: 'Alerte sécurité : tentatives de connexion échouées',
    html: formatSecurityEmailHtml({
      title: 'Adresse IP bloquée',
      intro: `${attempts} tentatives de connexion avec un mot de passe incorrect ont été détectées. L'adresse IP a été temporairement bloquée.`,
      rows: [
        { label: 'Adresse IP', value: ip || 'Inconnue' },
        { label: 'Durée du blocage', value: `Environ ${blockMinutes} minute(s)` },
        { label: 'Compte concerné', value: to }
      ]
    })
  };

  try {
    return await getTransporter().sendMail(mailOptions);
  } catch (err) {
    console.error('[mail] Échec alerte blocage IP à', to, ':', err.message);
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendPhoneVerificationSms,
  sendLoginAlertEmail,
  sendLoginBlockedEmail,
  verifyTransporter
};
