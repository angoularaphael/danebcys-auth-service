// Application Express principale : point d'entrée du site, connexions et proxy vers les microservices (port 3001)
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
// Adresses locales autorisées en développement pour tester le frontend
const localTestOrigins = new Set([
  'http://localhost:3001',
  'http://127.0.0.1:3001'
]);
app.use(cors({
  // Vérifie si l'origine de la requête est autorisée (site frontend autorisé)
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

// Ajoute un numéro de requête et l'adresse IP du visiteur à chaque appel
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.clientIp = req.headers['x-client-ip'] || req.headers['x-forwarded-for'] || req.ip;
  res.setHeader('x-request-id', req.requestId);
  next();
});

app.use(middlewareScoreConfiance());
// Routes visibles par le frontend — préfixe /api/v1
app.use('/api/v1', publicRoutes);
// Routes réservées aux autres services — préfixe /internal (clé secrète requise)
app.use('/internal', internalRoutes);

// Vérifie que le service fonctionne — GET /health
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'auth-service' });
});

// Affiche un message d'erreur clair quand quelque chose plante
app.use((err, _req, res, _next) => {
  const status = err.statusCode || (err.message === 'Origine non autorisee' ? 403 : 500);
  res.status(status).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

module.exports = app;
