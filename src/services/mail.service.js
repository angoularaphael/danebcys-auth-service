const nodemailer = require('nodemailer');
const env = require('../config/env');

let transporter = null;

function getTransporter() {
  if (!transporter) {
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

  return getTransporter().sendMail(mailOptions);
}

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

/**
 * Stub SMS : en développement le code est loggé en console.
 * En production, remplacer par Twilio (CDC 2.4 / 6.1).
 */
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

module.exports = { sendVerificationEmail, sendPasswordResetEmail, sendPhoneVerificationSms };
