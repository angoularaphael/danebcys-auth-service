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
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',

  PEPPER_PRIMARY_URL: process.env.PEPPER_PRIMARY_URL || '',
  PEPPER_PRIMARY_KEY: process.env.PEPPER_PRIMARY_KEY || '',
  PEPPER_SECONDARY_URL: process.env.PEPPER_SECONDARY_URL || '',
  PEPPER_SECONDARY_KEY: process.env.PEPPER_SECONDARY_KEY || '',

  EMAIL_USER: process.env.EMAIL_USER,
  EMAIL_PASS: process.env.EMAIL_PASS,

  POW_DIFFICULTY: parseInt(process.env.POW_DIFFICULTY, 10) || 4,
  POW_SECRET: process.env.POW_SECRET,
  POW_EXPIRY_SECONDS: parseInt(process.env.POW_EXPIRY_SECONDS, 10) || 300,

  INTER_SERVICE_KEY: process.env.INTER_SERVICE_KEY,

  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100
};
