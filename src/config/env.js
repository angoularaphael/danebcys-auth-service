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

function parseList(value, fallback = '') {
  const source = value || fallback;
  return source
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

module.exports = {
  PORT: parseInt(process.env.PORT, 10) || 3001,
  NODE_ENV: process.env.NODE_ENV || 'development',

  PG_HOST: process.env.PG_HOST || 'localhost',
  PG_PORT: parseInt(process.env.PG_PORT, 10) || 5432,
  PG_DATABASE: process.env.PG_DATABASE || 'auth_service',
  PG_USER: process.env.PG_USER || 'postgres',
  PG_PASSWORD: process.env.PG_PASSWORD || 'postgres',

  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
  JWT_ACCESS_EXPIRES_IN: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d', // Session (tous rôles) : 7 jours

  PEPPER_PRIMARY_URL: process.env.PEPPER_PRIMARY_URL || '',
  PEPPER_PRIMARY_KEY: process.env.PEPPER_PRIMARY_KEY || '',
  PEPPER_SECONDARY_URL: process.env.PEPPER_SECONDARY_URL || '',
  PEPPER_SECONDARY_KEY: process.env.PEPPER_SECONDARY_KEY || '',

  EMAIL_USER: process.env.EMAIL_USER,
  EMAIL_PASS: process.env.EMAIL_PASS,
  IP_LOG_SECRET: process.env.IP_LOG_SECRET || '',

  POW_DIFFICULTY: parseInt(process.env.POW_DIFFICULTY, 10) || 4,
  POW_SECRET: process.env.POW_SECRET,
  POW_EXPIRY_SECONDS: parseInt(process.env.POW_EXPIRY_SECONDS, 10) || 300,

  INTER_SERVICE_KEY: process.env.INTER_SERVICE_KEY,

  ASSISTANCE_EMAIL: process.env.ASSISTANCE_EMAIL || 'angoularaphael05@gmail.com',

  USERS_SERVICE_URL: process.env.USERS_SERVICE_URL || 'http://localhost:3002',
  SEARCH_SERVICE_URL: process.env.SEARCH_SERVICE_URL || 'http://localhost:3003',
  PRODUCTS_SERVICE_URL: process.env.PRODUCTS_SERVICE_URL || 'http://localhost:3004',
  ORDERS_SERVICE_URL: process.env.ORDERS_SERVICE_URL || 'http://localhost:3005',
  MESSAGING_SERVICE_URL: process.env.MESSAGING_SERVICE_URL || 'http://localhost:3006',
  ASSISTANCE_SERVICE_URL: process.env.ASSISTANCE_SERVICE_URL || 'http://localhost:3007',
  SUBSCRIPTIONS_SERVICE_URL: process.env.SUBSCRIPTIONS_SERVICE_URL || 'http://localhost:3008',
  FAVORITES_SERVICE_URL: process.env.FAVORITES_SERVICE_URL || 'http://localhost:3009',
  NOTIFICATIONS_SERVICE_URL: process.env.NOTIFICATIONS_SERVICE_URL || 'http://localhost:3010',

  CORS_ORIGINS: parseList(
    process.env.CORS_ORIGINS,
    'http://localhost:4200,http://127.0.0.1:4200,http://localhost:3001,http://127.0.0.1:3001'
  ),
  JSON_LIMIT: process.env.JSON_LIMIT || '1mb',
  PROXY_TIMEOUT_MS: parseInt(process.env.PROXY_TIMEOUT_MS, 10) || 8000,

  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,

  FRAUD_REQUESTS_PER_MIN: parseInt(process.env.FRAUD_REQUESTS_PER_MIN, 10) || 20,
  FRAUD_BAN_AFTER_NOTIF: parseInt(process.env.FRAUD_BAN_AFTER_NOTIF, 10) || 5,
  AUTH_RATE_LIMIT_WINDOW_MS: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 10) || 300000,
  AUTH_RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS, 10) || 40
};
