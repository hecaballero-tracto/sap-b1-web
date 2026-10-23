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

// Caché en memoria de almacenes: Map<WarehouseCode, WarehouseName>
let warehousesCache = null;
let warehousesCachePromise = null;

// Caché en memoria de grupos de artículos: Map<ItemsGroupCode, GroupName>
let itemGroupsCache = null;
let itemGroupsCachePromise = null;

// Caché en memoria de fabricantes: Map<ManufacturerCode, ManufacturerName>
let manufacturersCache = null;
let manufacturersCachePromise = null;

// Caché en memoria de marcas activas (tabla de usuario @MARCAS): Array<string>
let marcasCache = null;
let marcasCachePromise = null;

async function loadWarehouses() {
  if (warehousesCache) return warehousesCache;
  if (warehousesCachePromise) return warehousesCachePromise;

  warehousesCachePromise = (async () => {
    try {
      await ensureSession();
      const response = await sapClient.get(
        "/b1s/v1/Warehouses?$select=WarehouseCode,WarehouseName",
        { headers: { Cookie: buildCookieHeader() } }
      );
      const list = Array.isArray(response.data && response.data.value)
        ? response.data.value
        : [];
      const map = new Map();
      for (const w of list) {
        if (w && w.WarehouseCode) {
          map.set(w.WarehouseCode, w.WarehouseName || w.WarehouseCode);
        }
      }
      warehousesCache = map;
      return map;
    } catch (err) {
      // No cachear fallos: permitir reintento en la próxima llamada
      warehousesCachePromise = null;
      throw err;
    }
  })();

  return warehousesCachePromise;
}

async function loadItemGroups() {
  if (itemGroupsCache) return itemGroupsCache;
  if (itemGroupsCachePromise) return itemGroupsCachePromise;

  itemGroupsCachePromise = (async () => {
    try {
      await ensureSession();
      const response = await sapClient.get(
        "/b1s/v1/ItemGroups?$select=Number,GroupName",
        { headers: { Cookie: buildCookieHeader() } }
      );
      const list = Array.isArray(response.data && response.data.value)
        ? response.data.value
        : [];
      const map = new Map();
      for (const g of list) {
        if (g && g.Number !== undefined && g.Number !== null) {
          map.set(String(g.Number), g.GroupName || String(g.Number));
        }
      }
      itemGroupsCache = map;
      return map;
    } catch (err) {
      itemGroupsCachePromise = null;
      throw err;
    }
  })();

  return itemGroupsCachePromise;
}

async function loadManufacturers() {
  if (manufacturersCache) return manufacturersCache;
  if (manufacturersCachePromise) return manufacturersCachePromise;

  manufacturersCachePromise = (async () => {
    try {
      await ensureSession();
      const response = await sapClient.get(
        "/b1s/v1/Manufacturers?$select=Code,ManufacturerName",
        { headers: { Cookie: buildCookieHeader() } }
      );
      const list = Array.isArray(response.data && response.data.value)
        ? response.data.value
        : [];
      const map = new Map();
      for (const m of list) {
        if (m && m.Code !== undefined && m.Code !== null) {
          map.set(String(m.Code), m.ManufacturerName || String(m.Code));
        }
      }
      manufacturersCache = map;
      return map;
    } catch (err) {
      manufacturersCachePromise = null;
      throw err;
    }
  })();

  return manufacturersCachePromise;
}

async function loadMarcas() {
  if (marcasCache) return marcasCache;
  if (marcasCachePromise) return marcasCachePromise;

  marcasCachePromise = (async () => {
    try {
      await ensureSession();

      const fetchMarcas = async (filter) => {
        const params = new URLSearchParams();
        params.set('$filter', filter);
        params.set('$select', 'Code,U_Activo');
        const response = await sapClient.get(
          `/b1s/v1/Marcas?${params.toString()}`,
          { headers: { Cookie: buildCookieHeader() } }
        );
        return Array.isArray(response.data && response.data.value)
          ? response.data.value
          : [];
      };

      // Intento principal con 'Si'
      let list = await fetchMarcas("U_Activo eq 'Si'");

      // Fallback por variaciones de mayúsculas en el UDF
      if (!list.length) {
        list = await fetchMarcas("U_Activo eq 'SI'");
      }

      // Fallback final: filtrar en memoria por 'si' (case-insensitive)
      if (!list.length) {
        const all = await fetchMarcas("Code ne ''");
        list = all.filter(
          (item) =>
            item &&
            String(item.U_Activo || '').toLowerCase() === 'si'
        );
      }

      const codes = list
        .map((m) => (m && m.Code !== undefined && m.Code !== null ? String(m.Code) : null))
        .filter((c) => c !== null && c !== '')
        .sort((a, b) => a.localeCompare(b));

      marcasCache = codes;
      return codes;
    } catch (err) {
      marcasCachePromise = null;
      throw err;
    }
  })();

  return marcasCachePromise;
}

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
const sessionMaxAge = parsePositiveInt(SESSION_MAX_AGE, 10 * 60 * 60 * 1000);
app.set('trust proxy', 1);
const sessionMiddleware = session({
  name: 'sapb1.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: sessionMaxAge,
  },
});
app.use(sessionMiddleware);

// Control de sesiones concurrentes por usuario (FIFO, máximo 2)
const MAX_SESSIONS_PER_USER = 2;
// Map<username, Array<{ sid, createdAt }>>  (orden: más antigua primero)
const userSessions = new Map();

function registerUserSession(username, sid) {
  const list = userSessions.get(username) || [];
  // Evitar duplicados del mismo sid
  const filtered = list.filter((entry) => entry.sid !== sid);
  filtered.push({ sid, createdAt: Date.now() });

  // Si excede el máximo, destruir las más antiguas (FIFO)
  while (filtered.length > MAX_SESSIONS_PER_USER) {
    const oldest = filtered.shift();
    if (oldest && oldest.sid) {
      destroySessionById(oldest.sid);
    }
  }

  userSessions.set(username, filtered);
}

function unregisterUserSession(username, sid) {
  if (!username) return;
  const list = userSessions.get(username);
  if (!list) return;
  const filtered = list.filter((entry) => entry.sid !== sid);
  if (filtered.length) {
    userSessions.set(username, filtered);
  } else {
    userSessions.delete(username);
  }
}

// Referencia al store de sesiones (se asigna tras inicializar el middleware)
let sessionStoreRef = null;
app.use((req, res, next) => {
  if (!sessionStoreRef && req.sessionStore) {
    sessionStoreRef = req.sessionStore;
  }
  next();
});

function destroySessionById(sid) {
  if (!sid) return;
  const store = sessionStoreRef;
  if (store && typeof store.destroy === 'function') {
    store.destroy(sid, (err) => {
      if (err) console.warn('No se pudo destruir sesión previa:', err.message);
    });
  }
}

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

    // Registrar la sesión y aplicar límite FIFO por usuario
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Error guardando sesión:', saveErr.message);
        return res
          .status(500)
          .json({ error: { message: 'Error al crear la sesión' } });
      }
      registerUserSession(authUser, req.sessionID);
      return res.json({ ok: true, user: req.session.user });
    });
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
  const username = req.session.user && req.session.user.username;
  const sid = req.sessionID;
  req.session.destroy(() => {
    unregisterUserSession(username, sid);
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

// Redirigir la raíz a la página de clientes
app.get('/', (req, res) => {
  res.redirect('/clientes.html');
});

// Proteger vistas HTML ANTES de servir estáticos
app.get(['/clientes.html', '/articulos.html'], requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', req.path));
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

function buildArticulosQuery({ page, limit, search, rubro, fabricante, marca }) {
  const filters = ["ItemType eq 'itItems'"];

  if (search) {
    const safe = escapeODataString(search);
    filters.push(
      `(contains(ItemCode,'${safe}') or contains(ItemName,'${safe}'))`
    );
  }

  if (rubro !== undefined && rubro !== null && rubro !== '') {
    const n = parseInt(rubro, 10);
    if (Number.isFinite(n)) {
      filters.push(`ItemsGroupCode eq ${n}`);
    }
  }

  if (fabricante !== undefined && fabricante !== null && fabricante !== '') {
    const n = parseInt(fabricante, 10);
    if (Number.isFinite(n)) {
      filters.push(`Manufacturer eq ${n}`);
    }
  }

  if (marca !== undefined && marca !== null && marca !== '') {
    const safe = escapeODataString(marca);
    filters.push(`U_Marca eq '${safe}'`);
  }

  const skip = (page - 1) * limit;
  const top = limit;

  const params = new URLSearchParams();
  params.set('$filter', filters.join(' and '));
  params.set(
    '$select',
    'ItemCode,ItemName,ForeignName,QuantityOnStock,SalesUnit,SWW,ItemsGroupCode,Manufacturer,CreateDate,U_Marca,U_Modelo,QuantityOrderedByCustomers,QuantityOrderedFromVendors,ItemWarehouseInfoCollection'
  );
  params.set('$orderby', 'ItemCode');
  params.set('$top', String(top));
  params.set('$skip', String(skip));
  params.set('$inlinecount', 'allpages');

  return `/b1s/v1/Items?${params.toString()}`;
}

app.get('/api/articulos/catalogos', requireAuth, async (req, res) => {
  try {
    await ensureSession();

    const [itemGroups, manufacturers] = await Promise.all([
      loadItemGroups().catch((err) => {
        console.warn('No se pudo cargar el catálogo de grupos:', err.message);
        return new Map();
      }),
      loadManufacturers().catch((err) => {
        console.warn('No se pudo cargar el catálogo de fabricantes:', err.message);
        return new Map();
      }),
    ]);

    // Marcas activas desde la tabla de usuario @MARCAS
    let marcas = [];
    try {
      const codes = await loadMarcas();
      marcas = codes.map((code) => ({ code, name: code }));
    } catch (err) {
      console.warn('No se pudieron cargar las marcas:', err.message);
    }

    const rubros = Array.from(itemGroups.entries())
      .map(([code, name]) => ({ code: Number(code), name }))
      .sort((a, b) => a.name.localeCompare(b.name));

    const fabricantes = Array.from(manufacturers.entries())
      .map(([code, name]) => ({ code: Number(code), name }))
      .sort((a, b) => a.name.localeCompare(b.name));

    return res.json({ rubros, fabricantes, marcas });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/articulos', requireAuth, async (req, res) => {
  const page = parsePositiveInt(req.query.page, 1);
  const limit = parsePositiveInt(req.query.limit, 20, 200);
  const search = (req.query.search || '').trim();
  const rubro = (req.query.rubro || '').trim();
  const fabricante = (req.query.fabricante || '').trim();
  const marca = (req.query.marca || '').trim();

  const query = buildArticulosQuery({
    page,
    limit,
    search,
    rubro,
    fabricante,
    marca,
  });

  try {
    await ensureSession();

    // Cargar catálogos auxiliares en paralelo (si fallan, se responde sin nombres)
    const warehousesPromise = loadWarehouses().catch((err) => {
      console.warn('No se pudo cargar el catálogo de almacenes:', err.message);
      return new Map();
    });
    const itemGroupsPromise = loadItemGroups().catch((err) => {
      console.warn('No se pudo cargar el catálogo de grupos:', err.message);
      return new Map();
    });
    const manufacturersPromise = loadManufacturers().catch((err) => {
      console.warn('No se pudo cargar el catálogo de fabricantes:', err.message);
      return new Map();
    });

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    const [warehouses, itemGroups, manufacturers] = await Promise.all([
      warehousesPromise,
      itemGroupsPromise,
      manufacturersPromise,
    ]);
    return sendArticulosResponse(res, response.data, {
      page,
      limit,
      warehouses,
      itemGroups,
      manufacturers,
    });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const [warehouses, itemGroups, manufacturers] = await Promise.all([
          loadWarehouses().catch(() => new Map()),
          loadItemGroups().catch(() => new Map()),
          loadManufacturers().catch(() => new Map()),
        ]);
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        return sendArticulosResponse(res, retry.data, {
          page,
          limit,
          warehouses,
          itemGroups,
          manufacturers,
        });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

function sendArticulosResponse(
  res,
  sapData,
  { page, limit, warehouses, itemGroups, manufacturers }
) {
  const raw = Array.isArray(sapData.value) ? sapData.value : [];
  const total = Number(sapData['odata.count'] ?? sapData['@odata.count'] ?? 0) || 0;
  const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;
  const whMap = warehouses instanceof Map ? warehouses : new Map();
  const groupMap = itemGroups instanceof Map ? itemGroups : new Map();
  const manufMap = manufacturers instanceof Map ? manufacturers : new Map();

  const data = raw.map((item) => {
    const warehouses = Array.isArray(item.ItemWarehouseInfoCollection)
      ? item.ItemWarehouseInfoCollection
          .map((w) => {
            const inStock = Number(w.InStock) || 0;
            const committed = Number(w.Committed) || 0;
            const ordered = Number(w.Ordered) || 0;
            const available = inStock - committed + ordered;
            return {
              WarehouseCode: w.WarehouseCode,
              WarehouseName: whMap.get(w.WarehouseCode) || w.WarehouseCode,
              InStock: inStock,
              Committed: committed,
              Ordered: ordered,
              Available: available,
            };
          })
          .filter((w) => w.InStock > 0 || w.Available > 0)
      : [];

    const groupCode =
      item.ItemsGroupCode !== undefined && item.ItemsGroupCode !== null
        ? Number(item.ItemsGroupCode)
        : null;
    const manufCode =
      item.Manufacturer !== undefined && item.Manufacturer !== null
        ? Number(item.Manufacturer)
        : null;

    return {
      ItemCode: item.ItemCode,
      ItemName: item.ItemName,
      FrgnName: item.ForeignName || '',
      QuantityOnStock: Number(item.QuantityOnStock) || 0,
      SalesUnit: item.SalesUnit,
      SWW: item.SWW || '',
      ItemsGroupCode: groupCode,
      rubro:
        item.ItemsGroupCode !== undefined && item.ItemsGroupCode !== null
          ? groupMap.get(String(item.ItemsGroupCode)) || ''
          : '',
      Manufacturer: manufCode,
      fabricante:
        item.Manufacturer !== undefined && item.Manufacturer !== null
          ? manufMap.get(String(item.Manufacturer)) || ''
          : '',
      LstSalDate: null,
      CreateDate: item.CreateDate || null,
      U_Marca: item.U_Marca || '',
      U_Modelo: item.U_Modelo || '',
      IsCommited: Number(item.QuantityOrderedByCustomers) || 0,
      OnOrder: Number(item.QuantityOrderedFromVendors) || 0,
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
