try { require('dotenv').config(); } catch (e) { /* dotenv is a dev-only convenience; envs come from Render in production */ }

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const { DATABASE_URL, APP_PASSWORD, SESSION_SECRET, PORT } = process.env;

if (!DATABASE_URL) throw new Error('Falta la variable de entorno DATABASE_URL');
if (!APP_PASSWORD) throw new Error('Falta la variable de entorno APP_PASSWORD');
if (!SESSION_SECRET) throw new Error('Falta la variable de entorno SESSION_SECRET');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// Render está detrás de un proxy; necesario para que express-rate-limit y
// las cookies "secure" identifiquen correctamente IP/HTTPS.
app.set('trust proxy', 1);

// El frontend es un único HTML con <script> y onclick="" inline (sin build step),
// así que se mantiene el resto de cabeceras por defecto de helmet pero se permite
// script inline en la CSP; de lo contrario el navegador bloquearía toda la app.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'unsafe-inline'"],
      },
    },
  })
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

const SESSION_COOKIE = 'damasco_session';
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function timingSafeEqualStrings(a, b) {
  const ah = sha256(a);
  const bh = sha256(b);
  return crypto.timingSafeEqual(ah, bh);
}

function signSession(issuedAt) {
  const payload = String(issuedAt);
  const hmac = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${hmac}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return false;
  const idx = token.lastIndexOf('.');
  if (idx === -1) return false;
  const payload = token.slice(0, idx);
  const hmac = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const givenBuf = Buffer.from(hmac, 'hex');
  if (expectedBuf.length !== givenBuf.length) return false;
  if (!crypto.timingSafeEqual(expectedBuf, givenBuf)) return false;
  const issuedAt = Number(payload);
  if (!Number.isFinite(issuedAt)) return false;
  if (Date.now() - issuedAt > SESSION_MAX_AGE_MS) return false;
  return true;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const eq = pair.indexOf('=');
    if (eq === -1) return;
    const key = pair.slice(0, eq).trim();
    const val = pair.slice(eq + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

function setSessionCookie(res) {
  const token = signSession(Date.now());
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    `Max-Age=${Math.floor(SESSION_MAX_AGE_MS / 1000)}`,
  ];
  // "Secure" solo tiene sentido bajo HTTPS real (Render en producción);
  // en local (http://localhost) el navegador descartaria la cookie.
  if (isProduction) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
  const parts = [`${SESSION_COOKIE}=`, 'HttpOnly', 'Path=/', 'SameSite=Strict', 'Max-Age=0'];
  if (isProduction) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function hasValidSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifySession(cookies[SESSION_COOKIE]);
}

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

const stateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

function renderLoginPage(errorMessage) {
  const errorHtml = errorMessage
    ? `<p class="error">${errorMessage}</p>`
    : '';
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Damasco - Acceso</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#1b1b1f; color:#fff; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  form { background:#26262b; padding:32px 28px; border-radius:14px; width:280px; box-shadow:0 10px 30px rgba(0,0,0,.4); }
  h1 { font-size:18px; margin:0 0 18px; text-align:center; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:8px; border:1px solid #444; background:#1b1b1f; color:#fff; font-size:15px; margin-bottom:12px; }
  button { width:100%; padding:10px; border:none; border-radius:8px; background:#3a9d6b; color:#fff; font-weight:700; font-size:15px; cursor:pointer; }
  .error { color:#ff6b6b; font-size:13px; margin:-4px 0 12px; text-align:center; }
</style>
</head>
<body>
  <form method="POST" action="/api/login">
    <h1>Acceso Damasco</h1>
    ${errorHtml}
    <input type="password" name="password" placeholder="Contraseña" autofocus required>
    <button type="submit">Entrar</button>
  </form>
</body>
</html>`;
}

app.post('/api/login', loginLimiter, (req, res) => {
  const password = req.body && req.body.password;
  if (typeof password !== 'string' || !password) {
    return res.status(400).send(renderLoginPage('Introduce la contraseña.'));
  }
  if (!timingSafeEqualStrings(password, APP_PASSWORD)) {
    return res.status(401).send(renderLoginPage('Contraseña incorrecta.'));
  }
  setSessionCookie(res);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (wantsJson) return res.json({ ok: true });
  res.redirect('/');
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.redirect('/');
});

function requireAuth(req, res, next) {
  if (hasValidSession(req)) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  res.status(401).send(renderLoginPage());
}

app.use(requireAuth);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/state', stateLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT data FROM app_state WHERE id = $1', [1]);
    if (result.rows.length === 0) {
      return res.json({ value: null });
    }
    res.json({ value: JSON.stringify(result.rows[0].data) });
  } catch (err) {
    console.error('Error en GET /api/state:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/state', stateLimiter, async (req, res) => {
  const body = req.body;
  const keys = body ? Object.keys(body) : [];
  if (!body || keys.length !== 1 || keys[0] !== 'value' || typeof body.value !== 'string') {
    return res.status(400).json({ error: 'Cuerpo inválido: se espera { value: string }' });
  }
  let parsed;
  try {
    parsed = JSON.parse(body.value);
  } catch (e) {
    return res.status(400).json({ error: 'El campo value no contiene JSON válido' });
  }
  try {
    await pool.query(
      `INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()`,
      [parsed]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Error en POST /api/state:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'No encontrado' });
});

app.use((err, req, res, next) => {
  console.error('Error no controlado:', err);
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Cuerpo de la petición inválido' });
  }
  if (err && err.status === 413) {
    return res.status(413).json({ error: 'Payload demasiado grande' });
  }
  res.status(500).json({ error: 'Error interno del servidor' });
});

const port = PORT || 3000;

ensureSchema()
  .then(() => {
    app.listen(port, () => {
      console.log(`Damasco app escuchando en el puerto ${port}`);
    });
  })
  .catch((err) => {
    console.error('No se pudo inicializar el esquema de la base de datos:', err);
    process.exit(1);
  });
