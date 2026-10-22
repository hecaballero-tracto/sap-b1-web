'use strict';

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

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
} = process.env;

if (!SAP_URL || !SAP_COMPANY_DB || !SAP_USER || !SAP_PASSWORD) {
  console.error(
    'Faltan variables de entorno. Verifique SAP_URL, SAP_COMPANY_DB, SAP_USER y SAP_PASSWORD en el archivo .env'
  );
  process.exit(1);
}

// Cliente HTTP que ignora certificados autofirmados
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

const sapClient = axios.create({
  baseURL: SAP_URL.replace(/\/+$/, ''),
  httpsAgent,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// Sesión en memoria
let session = {
  b1session: null,
  routeid: null,
};

function buildCookieHeader() {
  const parts = [];
  if (session.b1session) parts.push(`B1SESSION=${session.b1session}`);
  if (session.routeid) parts.push(`ROUTEID=${session.routeid}`);
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

  session = { b1session, routeid };
  console.log('Sesión SAP B1 iniciada correctamente');
  return session;
}

async function ensureSession() {
  if (!session.b1session) {
    await login();
  }
  return session;
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/orders', async (req, res) => {
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
        session = { b1session: null, routeid: null };
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

app.get('/api/clientes', async (req, res) => {
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
        session = { b1session: null, routeid: null };
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

  const options = {
    pfx: fs.readFileSync(pfxPath),
    passphrase: SSL_PFX_PASSPHRASE || undefined,
  };

  const httpsPort = parsePositiveInt(HTTPS_PORT, 443);
  const httpsServer = https.createServer(options, appInstance);

  httpsServer.listen(httpsPort, () => {
    console.log(`Servidor HTTPS escuchando en https://localhost:${httpsPort}`);
  });

  // Servidor HTTP opcional que redirige a HTTPS
  if (HTTP_PORT) {
    const httpPort = parsePositiveInt(HTTP_PORT, 80);
    const redirectApp = express();
    redirectApp.use((req, res) => {
      const host = (req.headers.host || '').split(':')[0];
      const target = `https://${host}${req.originalUrl}`;
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
  });
}
