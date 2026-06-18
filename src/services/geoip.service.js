// Géolocalisation approximative par IP (service gratuit ip-api.com, sans clé API)
const http = require('http');

const PRIVATE_IP =
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|localhost$)/i;

// Retourne une description lisible ou null si IP locale / échec
function lookupIpLocation(ip) {
  return new Promise((resolve) => {
    if (!ip || PRIVATE_IP.test(ip) || ip === '::1') {
      resolve('Local / réseau privé (géolocalisation indisponible)');
      return;
    }

    const options = {
      hostname: 'ip-api.com',
      port: 80,
      path: `/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city`,
      method: 'GET',
      timeout: 3000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const body = JSON.parse(data);
          if (body.status !== 'success') {
            resolve(null);
            return;
          }
          const parts = [body.city, body.regionName, body.country].filter(Boolean);
          resolve(parts.length ? parts.join(', ') : null);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

module.exports = { lookupIpLocation };
