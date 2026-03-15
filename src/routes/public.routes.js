const { Router } = require('express');
const env = require('../config/env');
const authRoutes = require('./auth.routes');
const { authenticateRequired, authenticateOptional } = require('../middlewares/proxyAuth');
const { fraudDetector } = require('../middlewares/fraudDetector');
const { proxyTo } = require('../services/proxy');

function withApiPath(baseUrl, apiPath) {
  const normalizedBase = (baseUrl || '').replace(/\/+$/, '');
  const normalizedApiPath = apiPath.startsWith('/') ? apiPath : `/${apiPath}`;

  if (normalizedBase.endsWith(normalizedApiPath)) {
    return normalizedBase;
  }

  return `${normalizedBase}${normalizedApiPath}`;
}

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

function createProxyRouter(targetBaseUrl, resolveMode = () => 'none') {
  const router = Router();
  const proxyHandler = proxyTo(targetBaseUrl);
  const handler = (req, res, next) => fraudDetector(req, res, () => proxyHandler(req, res, next));
  router.use(withResolvedAuth(resolveMode, handler));
  return router;
}

function isSingleIdPath(pathname) {
  return /^\/[^/]+$/.test(pathname) && pathname !== '/me';
}

function resolveUsersRouteMode(req) {
  if (req.method === 'GET' && isSingleIdPath(req.path)) {
    return 'none';
  }
  return 'required';
}

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

function resolveAssistanceRouteMode(req) {
  if ((req.method === 'GET' && req.path === '/chat/start') || (req.method === 'POST' && req.path === '/chat')) {
    return 'none';
  }
  return 'required';
}

const router = Router();

router.use('/auth', authRoutes);
router.use('/users', createProxyRouter(withApiPath(env.USERS_SERVICE_URL, '/api/v1/users'), resolveUsersRouteMode));
router.use('/products', createProxyRouter(withApiPath(env.PRODUCTS_SERVICE_URL, '/api/v1/products'), resolveProductsRouteMode));
router.use('/search', createProxyRouter(withApiPath(env.SEARCH_SERVICE_URL, '/api/v1/search'), () => 'optional'));
router.use('/cart', createProxyRouter(withApiPath(env.ORDERS_SERVICE_URL, '/api/v1/cart'), () => 'required'));
router.use('/orders', createProxyRouter(withApiPath(env.ORDERS_SERVICE_URL, '/api/v1/orders'), () => 'required'));
router.use('/messages', createProxyRouter(withApiPath(env.MESSAGING_SERVICE_URL, '/api/v1/messages'), () => 'required'));
router.use('/assistance', createProxyRouter(withApiPath(env.ASSISTANCE_SERVICE_URL, '/api/v1/assistance'), resolveAssistanceRouteMode));
router.use('/subscriptions', createProxyRouter(withApiPath(env.SUBSCRIPTIONS_SERVICE_URL, '/api/v1/subscriptions'), () => 'required'));
router.use('/favorites', createProxyRouter(withApiPath(env.FAVORITES_SERVICE_URL, '/api/v1/favorites'), () => 'required'));
router.use('/notifications', createProxyRouter(withApiPath(env.NOTIFICATIONS_SERVICE_URL, '/api/v1/notifications'), () => 'required'));

module.exports = router;
