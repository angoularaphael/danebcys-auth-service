// Routes API publiques et proxy vers Users, Products, Orders, etc.
const { Router } = require('express');
const env = require('../config/env');
const authRoutes = require('./auth.routes');
const { authenticateRequired, authenticateOptional } = require('../middlewares/proxyAuth');
const { fraudDetector } = require('../middlewares/fraudDetector');
const { proxyTo } = require('../services/proxy');

// Ajoute le chemin API à l'adresse d'un microservice (ex. /api/v1/users)
function withApiPath(baseUrl, apiPath) {
  const normalizedBase = (baseUrl || '').replace(/\/+$/, '');
  const normalizedApiPath = apiPath.startsWith('/') ? apiPath : `/${apiPath}`;

  if (normalizedBase.endsWith(normalizedApiPath)) {
    return normalizedBase;
  }

  return `${normalizedBase}${normalizedApiPath}`;
}

// Applique la connexion obligatoire, optionnelle ou aucune avant de transférer la requête
function withResolvedAuth(resolveMode, handler) {
  return async function authResolver(req, res, next) {
    try {
      const mode = resolveMode(req);
      if (mode === 'required') {
        return authenticateRequired(req, res, () => handler(req, res, next));
      }
      if (mode === 'optional') {
        return authenticateOptional(req, res, () => handler(req, res, next));
      }
      return handler(req, res, next);
    } catch (err) {
      next(err);
    }
  };
}

// Reçoit les requêtes du frontend et les transfère vers un autre microservice
function createProxyRouter(targetBaseUrl, resolveMode = () => 'none') {
  const router = Router();
  const proxyHandler = proxyTo(targetBaseUrl);
  const handler = (req, res, next) => fraudDetector(req, res, () => proxyHandler(req, res, next));
  router.use(withResolvedAuth(resolveMode, handler));
  return router;
}

// Vérifie si l'URL pointe vers un seul identifiant (ex. /abc-123)
function isSingleIdPath(pathname) {
  return /^\/[^/]+$/.test(pathname) && pathname !== '/me';
}

// Règles de connexion pour Users-service (port 3002) : profil public en lecture seule
function resolveUsersRouteMode(req) {
  if (req.method === 'GET' && isSingleIdPath(req.path)) {
    return 'none';
  }
  return 'required';
}

// Règles de connexion pour Products-service (port 3004) : catalogue public, écriture réservée
function resolveProductsRouteMode(req) {
  if (req.method === 'GET') {
    if (req.path === '/categories') return 'optional';
    if (req.path === '/top-sellers') return 'optional';
    if (req.path === '/flash-sales') return 'optional';
    if (/^\/seller\/[^/]+$/.test(req.path)) return 'optional';
    if (/^\/[^/]+\/reviews$/.test(req.path)) return 'optional';
    if (isSingleIdPath(req.path)) return 'optional';
  }
  return 'required';
}

// Règles de connexion pour Assistance-service (port 3007) : démarrage du chat sans connexion
function resolveAssistanceRouteMode(req) {
  if ((req.method === 'GET' && req.path === '/chat/start') || (req.method === 'POST' && req.path === '/chat')) {
    return 'none';
  }
  return 'required';
}

// Routes API publiques du site — montées sur /api/v1
const router = Router();

router.use('/auth', authRoutes);
router.use('/users', createProxyRouter(withApiPath(env.USERS_SERVICE_URL, '/api/v1/users'), resolveUsersRouteMode));
router.use('/products', createProxyRouter(withApiPath(env.PRODUCTS_SERVICE_URL, '/api/v1/products'), resolveProductsRouteMode));
// Recherche : renvoie vers Products-service (port 3004) /api/v1/search
router.use('/search', createProxyRouter(withApiPath(env.PRODUCTS_SERVICE_URL, '/api/v1/search'), () => 'optional'));
router.use('/cart', createProxyRouter(withApiPath(env.ORDERS_SERVICE_URL, '/api/v1/cart'), () => 'required'));
router.use('/orders', createProxyRouter(withApiPath(env.ORDERS_SERVICE_URL, '/api/v1/orders'), () => 'required'));
router.use('/messages', createProxyRouter(withApiPath(env.MESSAGING_SERVICE_URL, '/api/v1/messages'), () => 'required'));
router.use('/assistance', createProxyRouter(withApiPath(env.ASSISTANCE_SERVICE_URL, '/api/v1/assistance'), resolveAssistanceRouteMode));
// Abonnements : renvoie vers Users-service (port 3002) /api/v1/subscriptions
router.use('/subscriptions', createProxyRouter(withApiPath(env.USERS_SERVICE_URL, '/api/v1/subscriptions'), () => 'required'));
// Favoris : renvoie vers Users-service (port 3002) /api/v1/favorites
router.use('/favorites', createProxyRouter(withApiPath(env.USERS_SERVICE_URL, '/api/v1/favorites'), () => 'required'));
router.use('/notifications', createProxyRouter(withApiPath(env.NOTIFICATIONS_SERVICE_URL, '/api/v1/notifications'), () => 'required'));

module.exports = router;
