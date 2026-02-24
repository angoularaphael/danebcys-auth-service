const API = '/api/v1/auth';

let accessToken = null;
let refreshToken = null;

const $ = (sel) => document.querySelector(sel);
const logEl = $('#log-output');

function log(msg, type = 'info') {
  const time = new Date().toLocaleTimeString('fr-FR');
  const div = document.createElement('div');
  div.className = 'log-entry';
  div.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-${type}">${msg}</span>`;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}

function updateTokenDisplay() {
  const accEl = $('#display-access');
  const refEl = $('#display-refresh');
  accEl.textContent = accessToken || 'Aucun';
  refEl.textContent = refreshToken || 'Aucun';
  accEl.className = 'token-box' + (accessToken ? ' has-value' : '');
  refEl.className = 'token-box' + (refreshToken ? ' has-value' : '');
}

async function sha256(message) {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function solvePoW(statusEl) {
  statusEl.textContent = 'PoW : récupération du challenge...';
  log('Récupération du challenge PoW...', 'pow');

  const res = await fetch(`${API}/pow-challenge`);
  const { challenge, difficulty, signature } = await res.json();

  statusEl.textContent = `PoW : résolution (difficulté ${difficulty})...`;
  log(`Challenge reçu — difficulté ${difficulty}, résolution en cours...`, 'pow');

  const prefix = '0'.repeat(difficulty);
  let nonce = 0;
  const start = performance.now();

  while (true) {
    const hash = await sha256(challenge + nonce);
    if (hash.startsWith(prefix)) {
      const ms = Math.round(performance.now() - start);
      log(`PoW résolu en ${ms}ms — nonce: ${nonce}`, 'ok');
      statusEl.textContent = `PoW : résolu en ${ms}ms (nonce: ${nonce})`;
      return { challenge, nonce: String(nonce), signature };
    }
    nonce++;
    if (nonce % 5000 === 0) {
      statusEl.textContent = `PoW : ${nonce} tentatives...`;
      await new Promise(r => setTimeout(r, 0));
    }
  }
}

async function apiCall(method, path, body = null, extraHeaders = {}) {
  const headers = { 'Content-Type': 'application/json', ...extraHeaders };
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(path, opts);
  const data = await res.json();

  if (!res.ok) {
    log(`${method} ${path} → ${res.status} : ${data.error}`, 'err');
    throw data;
  }
  log(`${method} ${path} → ${res.status}`, 'ok');
  return data;
}

// Health check
(async function checkHealth() {
  try {
    const data = await apiCall('GET', '/health');
    $('#health-status').innerHTML =
      '<span class="status-dot ok"></span><span style="font-size:13px">Connecté</span>';
    log(`Health: ${data.status} — ${data.service}`, 'ok');
  } catch {
    $('#health-status').innerHTML =
      '<span class="status-dot err"></span><span style="font-size:13px">Hors ligne</span>';
    log('Auth Service inaccessible', 'err');
  }
})();

// SIGNUP
$('#btn-signup').addEventListener('click', async () => {
  const btn = $('#btn-signup');
  btn.disabled = true;
  try {
    const pow = await solvePoW($('#signup-pow-status'));

    const data = await apiCall('POST', `${API}/signup`, {
      email: $('#signup-email').value,
      password: $('#signup-password').value,
      firstName: $('#signup-firstname').value,
      lastName: $('#signup-lastname').value,
      phone: $('#signup-phone').value || undefined
    }, {
      'x-pow-challenge': pow.challenge,
      'x-pow-nonce': pow.nonce,
      'x-pow-signature': pow.signature
    });

    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
    updateTokenDisplay();
    log(`Inscrit : ${data.user.email} (${data.user.id})`, 'ok');
  } catch (e) {
    /* already logged */
  }
  btn.disabled = false;
});

// LOGIN
$('#btn-login').addEventListener('click', async () => {
  const btn = $('#btn-login');
  btn.disabled = true;
  try {
    const pow = await solvePoW($('#login-pow-status'));

    const data = await apiCall('POST', `${API}/login`, {
      email: $('#login-email').value,
      password: $('#login-password').value
    }, {
      'x-pow-challenge': pow.challenge,
      'x-pow-nonce': pow.nonce,
      'x-pow-signature': pow.signature
    });

    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
    updateTokenDisplay();
    log(`Connecté : ${data.user.email}`, 'ok');
  } catch (e) {
    /* already logged */
  }
  btn.disabled = false;
});

// REFRESH
$('#btn-refresh').addEventListener('click', async () => {
  if (!refreshToken) return log('Pas de refresh token', 'warn');
  try {
    const data = await apiCall('POST', `${API}/refresh`, { refreshToken });
    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
    updateTokenDisplay();
    log('Tokens rafraîchis (rotation effectuée)', 'ok');
  } catch (e) {
    /* already logged */
  }
});

// LOGOUT
$('#btn-logout').addEventListener('click', async () => {
  if (!accessToken) return log('Pas connecté', 'warn');
  try {
    await apiCall('POST', `${API}/logout`, { refreshToken });
    accessToken = null;
    refreshToken = null;
    updateTokenDisplay();
    log('Déconnecté', 'ok');
  } catch (e) {
    /* already logged */
  }
});

// ME
$('#btn-me').addEventListener('click', async () => {
  if (!accessToken) return log('Pas connecté', 'warn');
  try {
    const data = await apiCall('GET', `${API}/me`);
    $('#user-info').style.display = 'block';
    $('#user-json').textContent = JSON.stringify(data.user, null, 2);
    log('Profil chargé', 'ok');
  } catch (e) {
    /* already logged */
  }
});

// VERIFY EMAIL
$('#btn-verify').addEventListener('click', async () => {
  if (!accessToken) return log('Pas connecté', 'warn');
  const code = $('#verify-code').value.trim();
  if (!code) return log('Entrez le code reçu par email', 'warn');
  try {
    const data = await apiCall('POST', `${API}/verify-email`, { code });
    log(data.message, 'ok');
  } catch (e) {
    /* already logged */
  }
});

// FORGOT PASSWORD
$('#btn-forgot').addEventListener('click', async () => {
  const btn = $('#btn-forgot');
  btn.disabled = true;
  try {
    const email = $('#forgot-email').value.trim();
    if (!email) { log('Entrez une adresse email', 'warn'); btn.disabled = false; return; }

    const pow = await solvePoW($('#forgot-pow-status'));

    const data = await apiCall('POST', `${API}/forgot-password`, { email }, {
      'x-pow-challenge': pow.challenge,
      'x-pow-nonce': pow.nonce,
      'x-pow-signature': pow.signature
    });

    log(data.message, 'ok');
    $('#reset-email').value = email;
  } catch (e) {
    /* already logged */
  }
  btn.disabled = false;
});

// RESET PASSWORD
$('#btn-reset').addEventListener('click', async () => {
  const btn = $('#btn-reset');
  btn.disabled = true;
  try {
    const email = $('#reset-email').value.trim();
    const code = $('#reset-code').value.trim();
    const newPassword = $('#reset-password').value;

    if (!email || !code || !newPassword) {
      log('Remplissez tous les champs', 'warn'); btn.disabled = false; return;
    }

    const pow = await solvePoW($('#reset-pow-status'));

    const data = await apiCall('POST', `${API}/reset-password`,
      { email, code, newPassword },
      {
        'x-pow-challenge': pow.challenge,
        'x-pow-nonce': pow.nonce,
        'x-pow-signature': pow.signature
      }
    );

    log(data.message, 'ok');
  } catch (e) {
    /* already logged */
  }
  btn.disabled = false;
});

// INTERNAL VALIDATE
$('#btn-validate').addEventListener('click', async () => {
  const key = $('#service-key').value.trim();
  if (!key) return log('Collez la clé INTER_SERVICE_KEY depuis votre .env', 'warn');
  if (!accessToken) return log('Pas de token à valider — connectez-vous d\'abord', 'warn');
  try {
    const data = await apiCall('POST', '/internal/validate-token',
      { accessToken },
      { 'x-service-key': key }
    );
    if (data.valid) {
      log(`Token valide — user: ${data.user.email} (${data.user.role})`, 'ok');
    } else {
      log(`Token invalide : ${data.error}`, 'err');
    }
  } catch (e) {
    /* already logged */
  }
});
