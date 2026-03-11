const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const env = require('./config/env');
const publicRoutes = require('./routes/public.routes');
const internalRoutes = require('./routes/internal.routes');
const { middlewareScoreConfiance } = require('./middlewares/trustScore');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', true);

app.use(helmet({ contentSecurityPolicy: false }));
const localTestOrigins = new Set([
  'http://localhost:3001',
  'http://127.0.0.1:3001'
]);
app.use(cors({
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    if (origin === 'null' && env.NODE_ENV !== 'production') {
      return callback(null, true);
    }

    if (
      env.CORS_ORIGINS.length === 0 ||
      env.CORS_ORIGINS.includes(origin) ||
      localTestOrigins.has(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error('Origine non autorisee'));
  }
}));
app.use(express.json({ limit: env.JSON_LIMIT }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.clientIp = req.headers['x-client-ip'] || req.headers['x-forwarded-for'] || req.ip;
  res.setHeader('x-request-id', req.requestId);
  next();
});

app.use(middlewareScoreConfiance());
app.use('/api/v1', publicRoutes);
app.use('/internal', internalRoutes);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'auth-service' });
});

app.use((err, _req, res, _next) => {
  const status = err.statusCode || (err.message === 'Origine non autorisee' ? 403 : 500);
  res.status(status).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

module.exports = app;
