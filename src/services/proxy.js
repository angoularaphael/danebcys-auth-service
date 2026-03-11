const http = require('http');
const https = require('https');
const env = require('../config/env');

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length'
]);

const STRIPPED_CLIENT_HEADERS = new Set([
  'x-service-key',
  'x-user-id',
  'x-user-email',
  'x-user-role',
  'x-user-username',
  'x-gateway-authenticated'
]);

function buildForwardHeaders(req, payload) {
  const headers = {};

  for (const [name, value] of Object.entries(req.headers)) {
    const normalized = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(normalized) || STRIPPED_CLIENT_HEADERS.has(normalized)) {
      continue;
    }
    headers[name] = value;
  }

  headers['x-request-id'] = req.requestId;
  headers['x-client-ip'] = req.clientIp;
  headers['x-forwarded-for'] = req.clientIp;
  headers['x-forwarded-proto'] = req.protocol;

  if (req.user) {
    headers['x-user-id'] = req.user.id;
    headers['x-user-email'] = req.user.email;
    headers['x-user-role'] = req.user.role;
    headers['x-user-username'] = req.user.username;
    headers['x-gateway-authenticated'] = 'true';
  }

  if (payload) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload);
  }

  return headers;
}

function copyResponseHeaders(upstream, res) {
  for (const [name, value] of Object.entries(upstream.headers)) {
    if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
      continue;
    }
    if (value !== undefined) {
      res.setHeader(name, value);
    }
  }
}

function createPayload(req) {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return null;
  }

  if (!req.body || Object.keys(req.body).length === 0) {
    return null;
  }

  return JSON.stringify(req.body);
}

function proxyTo(targetBaseUrl) {
  return async function proxyHandler(req, res, next) {
    try {
      const url = new URL(targetBaseUrl);
      const transport = url.protocol === 'https:' ? https : http;
      const payload = createPayload(req);
      const targetPath = `${url.pathname.replace(/\/$/, '')}${req.url}`;

      const upstreamReq = transport.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          method: req.method,
          path: targetPath,
          headers: buildForwardHeaders(req, payload)
        },
        (upstreamRes) => {
          copyResponseHeaders(upstreamRes, res);
          res.status(upstreamRes.statusCode || 502);
          upstreamRes.pipe(res);
        }
      );

      upstreamReq.on('error', (err) => {
        const error = new Error(`Service proxy injoignable: ${err.message}`);
        error.statusCode = 502;
        next(error);
      });

      upstreamReq.setTimeout(env.PROXY_TIMEOUT_MS, () => {
        upstreamReq.destroy();
        const error = new Error(`Timeout proxy (${env.PROXY_TIMEOUT_MS}ms)`);
        error.statusCode = 504;
        next(error);
      });

      if (payload) {
        upstreamReq.write(payload);
      }

      upstreamReq.end();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = {
  proxyTo
};
