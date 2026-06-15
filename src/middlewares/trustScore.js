// Calcule un score de confiance du navigateur et journalise les IP suspectes
const crypto = require('crypto');

// Indique si l'avertissement « secret IP manquant » a déjà été affiché
let warnedMissingSecret = false;

// Retourne la clé secrète pour masquer les adresses IP dans les journaux
function getIpLogSecret() {
  const secret = process.env.IP_LOG_SECRET || process.env.INTER_SERVICE_KEY;
  if (!secret && !warnedMissingSecret) {
    warnedMissingSecret = true;
    console.warn('------------------------------------------------');
    console.warn('ERREUR : IP_LOG_SECRET manquant (fallback insecure)');
    console.warn('------------------------------------------------');
  }
  return secret || 'dev-insecure-ip-log-secret';
}

// Transforme une adresse IP en code anonyme (impossible de retrouver l'IP d'origine)
function hmacIp(ip) {
  const secret = getIpLogSecret();
  return crypto.createHmac('sha256', secret).update(String(ip || '')).digest('hex');
}

// Retourne le début de la tranche de 5 minutes contenant cette date
function debutBucket5Min(date = new Date()) {
  const ms = date.getTime();
  const bucketMs = 5 * 60 * 1000;
  return new Date(Math.floor(ms / bucketMs) * bucketMs);
}

// Enregistre une adresse IP suspecte dans MongoDB (collection logsSuspects)
async function enregistrerIpSuspecteMongo(collection, ipBrute, trust, req) {
  const maintenant = new Date();
  const bucketStart = debutBucket5Min(maintenant);
  const ipHash = hmacIp(ipBrute);
  const expireAt = new Date(maintenant.getTime() + (7 * 24 * 60 * 60 * 1000));

  const exemple = {
    ts: maintenant,
    methode: req.method,
    chemin: req.originalUrl,
    score: trust.score,
    niveau: trust.niveau
  };

  const incNiveaux = {};
  incNiveaux[`niveaux.${trust.niveau}`] = 1;

  await collection.updateOne(
    { ipHash, bucketStart },
    {
      $setOnInsert: { ipHash, bucketStart, createdAt: maintenant },
      $set: { lastSeenAt: maintenant, expireAt },
      $inc: { compteur: 1, ...incNiveaux },
      $addToSet: { raisons: { $each: trust.raisons || [] } },
      $push: {
        derniersExemples: {
          $each: [exemple],
          $slice: -5
        }
      }
    },
    { upsert: true }
  );
}

// Décode une chaîne encodée en JSON
function base64UrlDecodeToJson(valeur) {
  try {
    const b64 = String(valeur).replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const json = Buffer.from(b64 + pad, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch (_e) {
    return null;
  }
}

// Nettoie une chaîne (supprime les espaces autour)
function normaliser(str) {
  return String(str || '').trim();
}

// Vérifie si une chaîne contient un morceau de texte (sans tenir compte des majuscules)
function contient(str, morceau) {
  return normaliser(str).toLowerCase().includes(String(morceau).toLowerCase());
}

// Extrait la langue principale demandée par le navigateur
function extraireLanguePrincipale(acceptLanguage) {
  const brut = normaliser(acceptLanguage);
  if (!brut) return null;
  return brut.split(',')[0].trim() || null;
}

// Détecte si le navigateur ressemble à un outil automatique (curl, Postman, etc.)
function estUserAgentSuspect(ua) {
  const x = normaliser(ua).toLowerCase();
  if (!x) return true;

  const marqueurs = [
    'curl/', 'wget/', 'python-requests', 'httpclient', 'okhttp', 'postmanruntime',
    'axios', 'node-fetch', 'undici', 'java/', 'go-http-client'
  ];

  return marqueurs.some((m) => x.includes(m));
}

// Détecte si le visiteur utilise un téléphone, iOS ou Android
function analyserUaMobile(ua) {
  const x = normaliser(ua).toLowerCase();
  const estMobile = x.includes('mobile') || x.includes('android') || x.includes('iphone') || x.includes('ipad');
  const estIos = x.includes('iphone') || x.includes('ipad') || x.includes('ios');
  const estAndroid = x.includes('android');
  return { estMobile, estIos, estAndroid };
}

// Calcule un score de confiance (0–100) à partir des infos du navigateur
function scoreConfianceDepuisRequete(req) {
  let score = 50;
  const raisons = [];

  const ua = normaliser(req.headers['user-agent']);
  const accept = normaliser(req.headers['accept']);
  const acceptLanguage = normaliser(req.headers['accept-language']);
  const secFetchSite = normaliser(req.headers['sec-fetch-site']);
  const secFetchMode = normaliser(req.headers['sec-fetch-mode']);
  const secFetchDest = normaliser(req.headers['sec-fetch-dest']);

  const chUa = normaliser(req.headers['sec-ch-ua']);
  const chMobile = normaliser(req.headers['sec-ch-ua-mobile']);
  const chPlatform = normaliser(req.headers['sec-ch-ua-platform']);

  if (estUserAgentSuspect(ua)) {
    score -= 35;
    raisons.push('UA ressemble a un client non-navigateur (curl/lib).');
  } else {
    score += 5;
  }

  const secFetchCount = [secFetchSite, secFetchMode, secFetchDest].filter(Boolean).length;
  if (secFetchCount >= 2) {
    score += 10;
  } else if (secFetchCount === 0) {
    score -= 5;
    raisons.push('Sec-Fetch-* absent (signal faible).');
  }

  if (chUa) score += 5;
  if (chMobile) score += 3;
  if (chPlatform) score += 3;

  const uaMobile = analyserUaMobile(ua);
  if (chMobile) {
    const indiqueMobile = contient(chMobile, '?1') || contient(chMobile, '1');
    if (indiqueMobile !== uaMobile.estMobile) {
      score -= 15;
      raisons.push('Incoherence UA vs Sec-CH-UA-Mobile.');
    } else {
      score += 3;
    }
  }

  if (accept && accept.includes(',')) score += 3;
  if (acceptLanguage) score += 3;

  const signalsB64 = req.headers['x-client-signals'];
  const versionSignals = normaliser(req.headers['x-client-signals-v']);
  let signaux = null;

  if (signalsB64 && versionSignals === '1') {
    signaux = base64UrlDecodeToJson(signalsB64);
    if (!signaux) {
      score -= 10;
      raisons.push('X-Client-Signals illisible.');
    } else {
      score += 5;
    }
  }

  if (signaux) {
    if (signaux.webdriver === true) {
      score -= 40;
      raisons.push('navigator.webdriver=true (automation probable).');
    }

    const langueReq = extraireLanguePrincipale(acceptLanguage);
    if (langueReq && signaux.lang) {
      const a = langueReq.slice(0, 2).toLowerCase();
      const b = String(signaux.lang).slice(0, 2).toLowerCase();
      if (a && b && a !== b) {
        score -= 8;
        raisons.push('Langue incoherente (Accept-Language vs navigator.language).');
      }
    }

    if (signaux.ua && ua && signaux.ua !== ua) {
      score -= 12;
      raisons.push('UA incoherent entre header et signaux front.');
    }

    if (typeof signaux.touchPoints === 'number') {
      if (uaMobile.estMobile && signaux.touchPoints === 0) {
        score -= 10;
        raisons.push('Mobile declare mais 0 touch points.');
      }
      if (!uaMobile.estMobile && signaux.touchPoints > 0) {
        score += 2;
      }
    }

    if (signaux.ecran && signaux.ecran.w && signaux.ecran.h) {
      if (signaux.ecran.w < 200 || signaux.ecran.h < 200) {
        score -= 8;
        raisons.push('Dimensions ecran anormales.');
      } else {
        score += 2;
      }
    }

    if (typeof signaux.ts === 'number') {
      const ageMs = Math.abs(Date.now() - signaux.ts);
      if (ageMs > 10 * 60 * 1000) {
        score -= 10;
        raisons.push('Signaux front trop anciens (replay possible).');
      }
    }
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  let niveau = 'OK';
  if (score < 35) niveau = 'DANGER';
  else if (score < 60) niveau = 'SUSPECT';

  if (score < 60) {
    const collection = global.logsSuspectsCollection;
    if (collection) {
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
      enregistrerIpSuspecteMongo(collection, ip, { score, niveau, raisons }, req).catch(() => {});
    }
  }

  return { score, niveau, raisons };
}

// Ajoute le score de confiance dans les en-têtes de réponse (x-trust-score, x-trust-level)
function middlewareScoreConfiance(options = {}) {
  const {
    headerScore = 'x-trust-score',
    headerNiveau = 'x-trust-level'
  } = options;

  return function trustMiddleware(req, res, next) {
    const resultat = scoreConfianceDepuisRequete(req);
    res.setHeader(headerScore, String(resultat.score));
    res.setHeader(headerNiveau, resultat.niveau);
    req.trust = resultat;
    next();
  };
}

module.exports = { middlewareScoreConfiance, scoreConfianceDepuisRequete };
