// Liste des réglages obligatoires — un avertissement s'affiche s'ils manquent
const requiredVars = [
  'PG_HOST', 'PG_PORT', 'PG_DATABASE', 'PG_USER', 'PG_PASSWORD',
  'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET',
  'POW_SECRET',
  'INTER_SERVICE_KEY'
];

for (const key of requiredVars) {
  if (!process.env[key]) {
    console.warn(`[env] Variable manquante: ${key}`);
  }
}

// Transforme une liste séparée par des virgules en tableau (ex. sites autorisés)
function parseList(value, fallback = '') {
  const source = value || fallback;
  return source
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

module.exports = {
  // Port d'écoute du Auth-service (défaut 3001)
  PORT: parseInt(process.env.PORT, 10) || 3001,
  // Mode d'exécution : développement ou production
  NODE_ENV: process.env.NODE_ENV || 'development',

  // Adresse du serveur PostgreSQL
  PG_HOST: process.env.PG_HOST || 'localhost',
  // Port PostgreSQL (défaut 5432)
  PG_PORT: parseInt(process.env.PG_PORT, 10) || 5432,
  // Nom de la base de données
  PG_DATABASE: process.env.PG_DATABASE || 'auth_service',
  // Identifiant de connexion PostgreSQL
  PG_USER: process.env.PG_USER || 'postgres',
  // Mot de passe PostgreSQL
  PG_PASSWORD: process.env.PG_PASSWORD || 'postgres',

  // Clé secrète pour signer les jetons de connexion courts (access token)
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  // Clé secrète pour les jetons de renouvellement (refresh token)
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
  // Durée de vie du jeton de connexion court (ex. 15 minutes)
  JWT_ACCESS_EXPIRES_IN: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  // Durée de vie de la session (défaut 7 jours)
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d', // Session (tous rôles) : 7 jours

  // Microservice pepper-primary — GET /pepper (secret hors base Auth)
  PEPPER_PRIMARY_URL: process.env.PEPPER_PRIMARY_URL || '',
  PEPPER_PRIMARY_KEY: process.env.PEPPER_PRIMARY_KEY || '',

  // Adresse email Gmail utilisée pour envoyer les mails
  EMAIL_USER: process.env.EMAIL_USER,
  // Mot de passe d'application Gmail
  EMAIL_PASS: process.env.EMAIL_PASS,
  // Clé secrète pour masquer les adresses IP dans les journaux
  IP_LOG_SECRET: process.env.IP_LOG_SECRET || '',

  // Nombre de zéros requis pour valider le défi anti-robot (PoW)
  POW_DIFFICULTY: parseInt(process.env.POW_DIFFICULTY, 10) || 4,
  // Clé secrète pour signer les défis anti-robot
  POW_SECRET: process.env.POW_SECRET,
  // Durée de validité d'un défi anti-robot en secondes
  POW_EXPIRY_SECONDS: parseInt(process.env.POW_EXPIRY_SECONDS, 10) || 300,

  // Clé partagée entre les microservices (en-tête X-Service-Key)
  INTER_SERVICE_KEY: process.env.INTER_SERVICE_KEY,

  // Email d'assistance affiché aux utilisateurs bannis
  ASSISTANCE_EMAIL: process.env.ASSISTANCE_EMAIL || 'angoularaphael05@gmail.com',

  // Adresse du Users-service (défaut port 3002)
  USERS_SERVICE_URL: process.env.USERS_SERVICE_URL || 'http://localhost:3002',
  // Recherche : gérée par Products-service via /api/v1/search
  // Adresse du Products-service (défaut port 3004)
  PRODUCTS_SERVICE_URL: process.env.PRODUCTS_SERVICE_URL || 'http://localhost:3004',
  // Adresse du Orders-service (défaut port 3005)
  ORDERS_SERVICE_URL: process.env.ORDERS_SERVICE_URL || 'http://localhost:3005',
  // Communication-service : messages et notifications sur le même port
  // Adresse pour les messages (défaut port 3006)
  MESSAGING_SERVICE_URL: process.env.MESSAGING_SERVICE_URL || 'http://localhost:3006',
  // Adresse pour créer des notifications — POST /internal/notifications (défaut port 3006)
  NOTIFICATIONS_SERVICE_URL: process.env.NOTIFICATIONS_SERVICE_URL || 'http://localhost:3006',
  // Adresse du Assistance-service (défaut port 3007)
  ASSISTANCE_SERVICE_URL: process.env.ASSISTANCE_SERVICE_URL || 'http://localhost:3007',
  // Abonnements : gérés par Users-service via /api/v1/subscriptions
  // Favoris : gérés par Users-service via /api/v1/favorites

  // Sites frontend autorisés à appeler l'API (Angular)
  CORS_ORIGINS: parseList(
    process.env.CORS_ORIGINS,
    'http://localhost:4200,http://127.0.0.1:4200,http://localhost:3001,http://127.0.0.1:3001'
  ),
  // Taille maximale du corps JSON d'une requête
  JSON_LIMIT: process.env.JSON_LIMIT || '1mb',
  // Délai max avant abandon quand on transfère une requête vers un autre service (60 s)
  PROXY_TIMEOUT_MS: parseInt(process.env.PROXY_TIMEOUT_MS, 10) || 60000,

  // Fenêtre de temps pour limiter le nombre de requêtes (15 minutes)
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
  // Nombre max de requêtes autorisées par fenêtre
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,

  // Nombre max de modifications par minute avant alerte fraude
  FRAUD_REQUESTS_PER_MIN: parseInt(process.env.FRAUD_REQUESTS_PER_MIN, 10) || 80,
  // Nombre d'alertes avant bannissement automatique
  FRAUD_BAN_AFTER_NOTIF: parseInt(process.env.FRAUD_BAN_AFTER_NOTIF, 10) || 5,
  // Fenêtre pour limiter les routes de connexion (5 minutes)
  AUTH_RATE_LIMIT_WINDOW_MS: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 10) || 300000,
  // Nombre max de tentatives de connexion par fenêtre
  AUTH_RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS, 10) || 40
};
