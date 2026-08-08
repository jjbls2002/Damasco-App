try { require('dotenv').config(); } catch (e) { /* dotenv is a dev-only convenience; envs come from Render in production */ }

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const { DATABASE_URL, SESSION_SECRET, PORT } = process.env;

if (!DATABASE_URL) throw new Error('Falta la variable de entorno DATABASE_URL');
if (!SESSION_SECRET) throw new Error('Falta la variable de entorno SESSION_SECRET');

// Cuentas válidas para el PIN de acceso. Viven solo en el servidor: el
// frontend nunca recibe esta lista, solo el resultado de validar un PIN.
// Para añadir más camareros/encargados, añade otro objeto aquí.
const ACCOUNTS = [
  { id: 'u1', pin: '789', name: 'Usuario 1', initials: 'U1' },
];

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

function signSession(accountId) {
  const payload = Buffer.from(JSON.stringify({ id: accountId, ts: Date.now() })).toString('base64url');
  const hmac = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${hmac}`;
}

// Devuelve el accountId si la cookie es válida y no ha caducado, o null.
function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const idx = token.lastIndexOf('.');
  if (idx === -1) return null;
  const payload = token.slice(0, idx);
  const hmac = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const givenBuf = Buffer.from(hmac, 'hex');
  if (expectedBuf.length !== givenBuf.length) return null;
  if (!crypto.timingSafeEqual(expectedBuf, givenBuf)) return null;
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!data || typeof data.id !== 'string' || !Number.isFinite(data.ts)) return null;
  if (Date.now() - data.ts > SESSION_MAX_AGE_MS) return null;
  return data.id;
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

function setSessionCookie(res, accountId) {
  const token = signSession(accountId);
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

function getSessionAccountId(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifySessionToken(cookies[SESSION_COOKIE]);
}

// El PIN son solo 3 dígitos (1000 combinaciones): límite estricto y propio
// para el intento de PIN, aparte del límite general de /api/state.
const pinLoginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const stateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

function requireAuth(req, res, next) {
  const accountId = getSessionAccountId(req);
  if (!accountId) return res.status(401).json({ error: 'No autorizado' });
  req.accountId = accountId;
  next();
}

app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/pin-login', pinLoginLimiter, (req, res) => {
  const pin = req.body && req.body.pin;
  if (typeof pin !== 'string' || !pin) {
    return res.status(400).json({ error: 'PIN inválido' });
  }
  const matched = ACCOUNTS.find((account) => timingSafeEqualStrings(pin, account.pin));
  if (!matched) {
    return res.status(401).json({ error: 'PIN incorrecto' });
  }
  setSessionCookie(res, matched.id);
  res.json({ account: { id: matched.id, name: matched.name, initials: matched.initials } });
});

app.get('/api/me', (req, res) => {
  const accountId = getSessionAccountId(req);
  const account = accountId && ACCOUNTS.find((a) => a.id === accountId);
  if (!account) return res.status(401).json({ error: 'No autorizado' });
  res.json({ account: { id: account.id, name: account.name, initials: account.initials } });
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/state', stateLimiter, requireAuth, async (req, res) => {
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

app.post('/api/state', stateLimiter, requireAuth, async (req, res) => {
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
