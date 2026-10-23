'use strict';

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const { authenticate } = require('ldap-authentication');

const {
  SAP_URL,
  SAP_COMPANY_DB,
  SAP_USER,
  SAP_PASSWORD,
  PORT = 3000,
  HTTPS_PORT,
  HTTP_PORT,
  SSL_PFX_PATH,
  SSL_PFX_PASSPHRASE,
  AD_URL,
  AD_DOMAIN,
  AD_TLS_REJECT_UNAUTHORIZED,
  SESSION_SECRET,
  SESSION_MAX_AGE,
} = process.env;

if (!SAP_URL || !SAP_COMPANY_DB || !SAP_USER || !SAP_PASSWORD) {
  console.error(
    'Faltan variables de entorno. Verifique SAP_URL, SAP_COMPANY_DB, SAP_USER y SAP_PASSWORD en el archivo .env'
  );
  process.exit(1);
}

if (!AD_URL || !AD_DOMAIN) {
  console.error(
    'Faltan variables de entorno de Active Directory. Verifique AD_URL y AD_DOMAIN en el archivo .env'
  );
  process.exit(1);
}

if (!SESSION_SECRET) {
  console.error(
    'Falta SESSION_SECRET en el archivo .env (usar una cadena larga y aleatoria).'
  );
  process.exit(1);
}

// Autenticación contra Active Directory usando ldap-authentication
async function authenticateAD(username, password) {
  const userDn = username.includes('@')
    ? username
    : `${AD_DOMAIN}\\${username}`;

  const rejectUnauthorized = String(AD_TLS_REJECT_UNAUTHORIZED || 'true')
    .toLowerCase() !== 'false';

  try {
    const user = await authenticate({
      ldapOpts: {
        url: AD_URL,
        tlsOptions: { rejectUnauthorized },
      },
      userDn,
      userPassword: password,
    });
    return user || true;
  } catch (err) {
    // Credenciales inválidas o error de conexión: se propaga para manejarlo arriba
    throw err;
  }
}

// Cliente HTTP que ignora certificados autofirmados
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

const sapClient = axios.create({
  baseURL: SAP_URL.replace(/\/+$/, ''),
  httpsAgent,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// Sesión SAP B1 en memoria
let sapSession = {
  b1session: null,
  routeid: null,
};

function buildCookieHeader() {
  const parts = [];
  if (sapSession.b1session) parts.push(`B1SESSION=${sapSession.b1session}`);
  if (sapSession.routeid) parts.push(`ROUTEID=${sapSession.routeid}`);
  return parts.join('; ');
}

async function login() {
  const response = await sapClient.post('/b1s/v1/Login', {
    CompanyDB: SAP_COMPANY_DB,
    UserName: SAP_USER,
    Password: SAP_PASSWORD,
  });

  const setCookie = response.headers['set-cookie'] || [];
  let b1session = null;
  let routeid = null;

  for (const cookie of setCookie) {
    const [pair] = cookie.split(';');
    const [name, value] = pair.split('=');
    if (name === 'B1SESSION') b1session = value;
    if (name === 'ROUTEID') routeid = value;
  }

  if (!b1session) {
    throw new Error('No se recibió la cookie B1SESSION en el login');
  }

  sapSession = { b1session, routeid };
  console.log('Sesión SAP B1 iniciada correctamente');
  return sapSession;
}

async function ensureSession() {
  if (!sapSession.b1session) {
    await login();
  }
  return sapSession;
}

const app = express();
app.use(express.json());

// Cabeceras de seguridad (HSTS solo aplica cuando se sirve por HTTPS)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Sesiones
const sessionMaxAge = parsePositiveInt(SESSION_MAX_AGE, 8 * 60 * 60 * 1000);
app.set('trust proxy', 1);
app.use(
  session({
    name: 'sapb1.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: 'auto',
      maxAge: sessionMaxAge,
    },
  })
);

// Middleware de autenticación
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();

  const isApi = req.path.startsWith('/api/');
  if (isApi) {
    return res.status(401).json({ error: { message: 'No autenticado' } });
  }

  const redirect = encodeURIComponent(req.originalUrl || '/');
  return res.redirect(`/login.html?redirect=${redirect}`);
}

// Endpoints de autenticación (públicos)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: { message: 'Usuario y contraseña son obligatorios' } });
  }

  // Construir el identificador de autenticación
  let authUser = String(username).trim();
  if (!authUser.includes('\\') && !authUser.includes('@')) {
    authUser = `${AD_DOMAIN}\\${authUser}`;
  }

  try {
    const adUser = await authenticateAD(authUser, password);

    req.session.user = {
      username: authUser,
      displayName:
        (adUser && (adUser.displayName || adUser.cn)) || authUser,
      email: (adUser && (adUser.mail || adUser.userPrincipalName)) || null,
      loginAt: new Date().toISOString(),
    };

    return res.json({ ok: true, user: req.session.user });
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    // ldap-authentication lanza errores con "InvalidCredentialsError" cuando la clave es incorrecta
    if (/InvalidCredentials|invalid credentials|49/i.test(msg)) {
      return res
        .status(401)
        .json({ error: { message: 'Credenciales inválidas' } });
    }
    console.error('Error autenticando contra AD:', msg);
    return res
      .status(500)
      .json({ error: { message: 'Error al autenticar contra Active Directory' } });
  }
});

app.post('/api/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(() => {
    res.clearCookie('sapb1.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ user: req.session.user });
  }
  return res.status(401).json({ error: { message: 'No autenticado' } });
});

// Archivos estáticos públicos (login, logout, manifest, sw, icons)
app.use(
  express.static(path.join(__dirname, 'public'), {
    index: false,
    setHeaders: (res, filePath) => {
      // no-cache para HTML para evitar servir vistas protegidas cacheadas
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store');
      }
    },
  })
);

// Redirigir la raíz a la página de clientes
app.get('/', (req, res) => {
  res.redirect('/clientes.html');
});

// Proteger vistas HTML (excepto login/logout)
app.get(['/clientes.html', '/articulos.html'], requireAuth, (req, res, next) => {
  next();
});

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    await ensureSession();

    const response = await sapClient.get('/b1s/v1/Orders?$top=5', {
      headers: { Cookie: buildCookieHeader() },
    });

    res.json(response.data);
  } catch (error) {
    // Si la sesión expiró, reintentar una vez
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.get('/b1s/v1/Orders?$top=5', {
          headers: { Cookie: buildCookieHeader() },
        });
        return res.json(retry.data);
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

function parsePositiveInt(value, fallback, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return max ? Math.min(n, max) : n;
}

function escapeODataString(value) {
  return String(value).replace(/'/g, "''");
}

function buildClientesQuery({ page, limit, search }) {
  const filters = ["CardType eq 'cCustomer'"];

  if (search) {
    const safe = escapeODataString(search);
    filters.push(
      `(contains(CardCode,'${safe}') or contains(CardName,'${safe}') or contains(City,'${safe}') or contains(Country,'${safe}'))`
    );
  }

  const skip = (page - 1) * limit;
  const top = limit;

  const params = new URLSearchParams();
  params.set('$filter', filters.join(' and '));
  params.set(
    '$select',
    'CardCode,CardName,Phone1,Cellular,EmailAddress,Address,City,Country,CurrentAccountBalance,Currency'
  );
  params.set('$orderby', 'CardCode');
  params.set('$top', String(top));
  params.set('$skip', String(skip));
  params.set('$inlinecount', 'allpages');

  return `/b1s/v1/BusinessPartners?${params.toString()}`;
}

app.get('/api/clientes', requireAuth, async (req, res) => {
  const page = parsePositiveInt(req.query.page, 1);
  const limit = parsePositiveInt(req.query.limit, 20, 200);
  const search = (req.query.search || '').trim();

  const query = buildClientesQuery({ page, limit, search });

  try {
    await ensureSession();

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    return sendClientesResponse(res, response.data, { page, limit });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        return sendClientesResponse(res, retry.data, { page, limit });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

function buildArticulosQuery({ page, limit, search }) {
  const filters = ["ItemType eq 'itItems'"];

  if (search) {
    const safe = escapeODataString(search);
    filters.push(
      `(contains(ItemCode,'${safe}') or contains(ItemName,'${safe}'))`
    );
  }

  const skip = (page - 1) * limit;
  const top = limit;

  const params = new URLSearchParams();
  params.set('$filter', filters.join(' and '));
  params.set(
    '$select',
    'ItemCode,ItemName,QuantityOnStock,SalesUnit,ItemWarehouseInfoCollection'
  );
  params.set('$orderby', 'ItemCode');
  params.set('$top', String(top));
  params.set('$skip', String(skip));
  params.set('$inlinecount', 'allpages');

  return `/b1s/v1/Items?${params.toString()}`;
}

app.get('/api/articulos', requireAuth, async (req, res) => {
  const page = parsePositiveInt(req.query.page, 1);
  const limit = parsePositiveInt(req.query.limit, 20, 200);
  const search = (req.query.search || '').trim();

  const query = buildArticulosQuery({ page, limit, search });

  try {
    await ensureSession();

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    return sendArticulosResponse(res, response.data, { page, limit });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        return sendArticulosResponse(res, retry.data, { page, limit });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

function sendArticulosResponse(res, sapData, { page, limit }) {
  const raw = Array.isArray(sapData.value) ? sapData.value : [];
  const total = Number(sapData['odata.count'] ?? sapData['@odata.count'] ?? 0) || 0;
  const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;

  const data = raw.map((item) => {
    const warehouses = Array.isArray(item.ItemWarehouseInfoCollection)
      ? item.ItemWarehouseInfoCollection
          .filter((w) => Number(w.InStock) > 0)
          .map((w) => ({
            WarehouseCode: w.WarehouseCode,
            InStock: Number(w.InStock) || 0,
          }))
      : [];

    return {
      ItemCode: item.ItemCode,
      ItemName: item.ItemName,
      QuantityOnStock: Number(item.QuantityOnStock) || 0,
      SalesUnit: item.SalesUnit,
      Warehouses: warehouses,
    };
  });

  res.json({
    data,
    total,
    page: Number(page),
    totalPages,
  });
}

function sendClientesResponse(res, sapData, { page, limit }) {
  const data = Array.isArray(sapData.value) ? sapData.value : [];
  const total = Number(sapData['odata.count'] ?? sapData['@odata.count'] ?? 0) || 0;
  const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;

  res.json({
    data,
    total,
    page: Number(page),
    totalPages,
  });
}

function handleError(res, error) {
  const status = error.response ? error.response.status : 500;
  const data = error.response ? error.response.data : { message: error.message };
  console.error('Error SAP B1:', status, data);
  res.status(status).json({ error: data });
}

function startHttpsServer(appInstance) {
  if (!SSL_PFX_PATH) {
    console.error(
      'HTTPS habilitado pero falta SSL_PFX_PATH. Defina la ruta al archivo .pfx en el .env'
    );
    process.exit(1);
  }

  const pfxPath = path.isAbsolute(SSL_PFX_PATH)
    ? SSL_PFX_PATH
    : path.join(__dirname, SSL_PFX_PATH);

  if (!fs.existsSync(pfxPath)) {
    console.error(`No se encontró el archivo .pfx en: ${pfxPath}`);
    process.exit(1);
  }

  // Limpiar comillas y espacios accidentales en la passphrase
  const rawPass = (SSL_PFX_PASSPHRASE || '').trim().replace(/^["']|["']$/g, '');
  console.log(
    `Passphrase leída: longitud=${rawPass.length}, tiene comillas=${/^["']|["']$/.test(SSL_PFX_PASSPHRASE || '')}, tiene espacios al inicio/fin=${(SSL_PFX_PASSPHRASE || '') !== (SSL_PFX_PASSPHRASE || '').trim()}`
  );

  const options = {
    pfx: fs.readFileSync(pfxPath),
    passphrase: rawPass ? rawPass : undefined,
  };

  const httpsPort = parsePositiveInt(HTTPS_PORT, 443);

  let httpsServer;
  try {
    httpsServer = https.createServer(options, appInstance);
  } catch (err) {
    if (err && err.message && err.message.includes('mac verify failure')) {
      console.error(
        'No se pudo abrir el archivo .pfx: la passphrase (SSL_PFX_PASSPHRASE) es incorrecta o el .pfx no tiene passphrase.'
      );
      console.error(
        'Verifique la contraseña del certificado con: openssl pkcs12 -info -in "' +
          pfxPath +
          '" -noout'
      );
    } else {
      console.error('Error al crear el servidor HTTPS:', err.message);
    }
    process.exit(1);
  }

  httpsServer.listen(httpsPort, () => {
    console.log(`Servidor HTTPS escuchando en https://localhost:${httpsPort}`);
    console.log(`Certificado cargado desde: ${pfxPath}`);
  });

  // Servidor HTTP opcional que redirige a HTTPS
  if (HTTP_PORT) {
    const httpPort = parsePositiveInt(HTTP_PORT, 80);
    const redirectApp = express();
    redirectApp.use((req, res) => {
      const host = (req.headers.host || '').split(':')[0];
      const portSuffix = httpsPort === 443 ? '' : `:${httpsPort}`;
      const target = `https://${host}${portSuffix}${req.originalUrl}`;
      res.redirect(301, target);
    });
    http.createServer(redirectApp).listen(httpPort, () => {
      console.log(`Servidor HTTP (redirección) escuchando en http://localhost:${httpPort}`);
    });
  }

  return httpsServer;
}

if (SSL_PFX_PATH) {
  startHttpsServer(app);
} else {
  app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
    console.log(
      'Para habilitar HTTPS configure SSL_PFX_PATH (y opcionalmente SSL_PFX_PASSPHRASE) en el .env'
    );
  });
}
