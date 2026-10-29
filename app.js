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
const ldap = require('ldapjs');

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

// Grupos de AD con permiso para configurar listas de precios (en minúsculas)
const PRICE_LIST_ADMIN_GROUPS = ['informatica', 'directorio', 'directorio_rw'];

function extractGroupNames(memberOf) {
  if (!memberOf) return [];
  const list = Array.isArray(memberOf) ? memberOf : [memberOf];
  const names = [];
  for (const dn of list) {
    if (!dn) continue;
    const text = String(dn);
    // Extraer el CN del DN: "CN=Informatica,OU=...,DC=..."
    const m = /CN=([^,]+)/i.exec(text);
    if (m) {
      names.push(m[1].trim().toLowerCase());
    } else {
      names.push(text.trim().toLowerCase());
    }
  }
  return names;
}

function canConfigurePriceListsFromGroups(groups, rawMemberOf) {
  if (Array.isArray(groups)) {
    const lower = groups.map((g) => String(g).toLowerCase());
    if (PRICE_LIST_ADMIN_GROUPS.some((g) => lower.includes(g))) {
      return true;
    }
  }

  // Fallback: revisar el DN completo por si el CN no se extrajo correctamente
  if (rawMemberOf) {
    const list = Array.isArray(rawMemberOf) ? rawMemberOf : [rawMemberOf];
    for (const dn of list) {
      if (!dn) continue;
      const text = String(dn).toLowerCase();
      if (PRICE_LIST_ADMIN_GROUPS.some((g) => text.includes(`cn=${g}`))) {
        return true;
      }
    }
  }

  return false;
}

// Atributos que se solicitan explícitamente al AD
const AD_ATTRIBUTES = [
  'sAMAccountName',
  'displayName',
  'mail',
  'userPrincipalName',
  'memberOf',
];

// BaseDN fijo del dominio (puede sobreescribirse con AD_BASE_DN)
const AD_BASE_DN = process.env.AD_BASE_DN || 'DC=tractoagrovial,DC=com,DC=py';

// Búsqueda directa con ldapjs para obtener memberOf cuando ldap-authentication
// no lo devuelve (por ejemplo, cuando el bind es con DOMINIO\\usuario).
function searchMemberOf(username, password) {
  return new Promise((resolve) => {
    const rejectUnauthorized = String(AD_TLS_REJECT_UNAUTHORIZED || 'true')
      .toLowerCase() !== 'false';

    const client = ldap.createClient({
      url: AD_URL,
      tlsOptions: { rejectUnauthorized },
    });

    const done = (result) => {
      try {
        client.unbind(() => {});
      } catch (_) {
        /* ignorar */
      }
      resolve(result);
    };

    client.on('error', (err) => {
      console.warn('[AUTH AD] Error de conexión LDAP en búsqueda memberOf:', err.message);
      done(null);
    });

    const bindDn = username.includes('@')
      ? username
      : `${AD_DOMAIN}\\${username}`;

    client.bind(bindDn, password, (bindErr) => {
      if (bindErr) {
        console.warn('[AUTH AD] Bind fallido en búsqueda memberOf:', bindErr.message);
        return done(null);
      }

      // Buscar por sAMAccountName en el baseDN fijo del dominio
      const baseDN = AD_BASE_DN;
      const samAccount = username.split('@')[0].split('\\\\').pop();
      const filter = `(&(objectClass=user)(sAMAccountName=${samAccount}))`;
      const opts = {
        filter,
        scope: 'sub',
        paged: false,
        attributes: ['sAMAccountName', 'displayName', 'mail', 'userPrincipalName', 'memberOf'],
      };
      console.log('[AUTH AD] Buscando memberOf en baseDN:', baseDN, 'filtro:', filter);

      client.search(baseDN, opts, (searchErr, res) => {
        if (searchErr) {
          console.warn('[AUTH AD] Error en búsqueda memberOf:', searchErr.message);
          return done(null);
        }

        let found = null;
        res.on('searchEntry', (entry) => {
          if (!found) {
            const attrs = {};

            // 1) Intentar con entry.pojo.attributes
            const pojoAttrs =
              (entry.pojo && entry.pojo.attributes) || null;
            if (Array.isArray(pojoAttrs)) {
              for (const a of pojoAttrs) {
                if (!a || !a.type) continue;
                attrs[a.type] =
                  a.values && a.values.length === 1 ? a.values[0] : a.values;
              }
            }

            // 2) Fallback con entry.attributes (ldapjs >= 3)
            if (!Object.keys(attrs).length && Array.isArray(entry.attributes)) {
              for (const a of entry.attributes) {
                if (!a || !a.type) continue;
                attrs[a.type] =
                  a.values && a.values.length === 1 ? a.values[0] : a.values;
              }
            }

            // 3) Fallback con entry.raw
            if (!attrs.memberOf && Array.isArray(entry.raw)) {
              const rawMemberOf = entry.raw
                .filter((a) => a && a.type === 'memberOf')
                .map((a) => a.values);
              if (rawMemberOf.length) {
                attrs.memberOf = rawMemberOf[0];
              }
            }

            console.log('[AUTH AD SEARCH ENCONTRADO]:', attrs.memberOf);
            found = attrs;
          }
        });
        res.on('searchReference', () => {
          /* ignorar referencias (referrals) sin emitir error */
        });
        res.on('error', (err) => {
          // Los referrals de AD no deben abortar la búsqueda
          if (err && /referral/i.test(String(err.message || ''))) {
            console.warn('[AUTH AD] Referral ignorado:', err.message);
            return;
          }
          console.warn('[AUTH AD] Error en respuesta de búsqueda:', err.message);
          done(null);
        });
        res.on('end', () => done(found));
      });
    });
  });
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
      attributes: AD_ATTRIBUTES,
    });

    // Si no vino memberOf, intentar búsqueda directa como fallback
    const hasMemberOf =
      user &&
      ((Array.isArray(user.memberOf) && user.memberOf.length) ||
        (typeof user.memberOf === 'string' && user.memberOf.length));

    if (!hasMemberOf) {
      const extra = await searchMemberOf(username, password);
      if (extra) {
        return { ...(user || {}), ...extra };
      }
    }

    return user || true;
  } catch (err) {
    // Credenciales inválidas o error de conexión: se propaga para manejarlo arriba
    throw err;
  }
}

// Endpoint de DeepSeek para interpretación de consultas en lenguaje natural
const DEEPSEEK_ENDPOINT = 'https' + '://api.deepseek.com/chat/completions';

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

// Caché en memoria de marcas únicas (para el filtro del cliente): Array<string>
// TTL de 12 horas
const MARCAS_UNICAS_TTL_MS = 12 * 60 * 60 * 1000;
let marcasUnicasCache = null; // { data: string[], expiresAt: number }
let marcasUnicasCachePromise = null;

// Caché en memoria de listas de precios: Map<PriceListNo, PriceListName>
let priceListsCache = null;
let priceListsCachePromise = null;

// Configuración global persistente de listas de precios visibles
const PRICE_LISTS_CONFIG_DIR = path.join(__dirname, 'config');
const PRICE_LISTS_CONFIG_FILE = path.join(
  PRICE_LISTS_CONFIG_DIR,
  'price_lists_config.json'
);

function readPriceListsConfig() {
  try {
    if (!fs.existsSync(PRICE_LISTS_CONFIG_FILE)) {
      return { visibleLists: [] };
    }
    const raw = fs.readFileSync(PRICE_LISTS_CONFIG_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const visibleLists = Array.isArray(parsed && parsed.visibleLists)
      ? parsed.visibleLists.map(Number).filter((n) => Number.isFinite(n))
      : [];
    return { visibleLists };
  } catch (err) {
    console.warn('No se pudo leer la configuración de listas de precios:', err.message);
    return { visibleLists: [] };
  }
}

function writePriceListsConfig(config) {
  try {
    if (!fs.existsSync(PRICE_LISTS_CONFIG_DIR)) {
      fs.mkdirSync(PRICE_LISTS_CONFIG_DIR, { recursive: true });
    }
    fs.writeFileSync(
      PRICE_LISTS_CONFIG_FILE,
      JSON.stringify(config, null, 2),
      'utf8'
    );
    return true;
  } catch (err) {
    console.error('No se pudo guardar la configuración de listas de precios:', err.message);
    return false;
  }
}

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

async function loadMarcasUnicas() {
  const now = Date.now();
  if (marcasUnicasCache && marcasUnicasCache.expiresAt > now) {
    return marcasUnicasCache.data;
  }
  if (marcasUnicasCachePromise) return marcasUnicasCachePromise;

  marcasUnicasCachePromise = (async () => {
    try {
      await ensureSession();

      const set = new Set();

      // 1) Intentar con la tabla de usuario @MARCAS (si existe)
      try {
        const params = new URLSearchParams();
        params.set('$select', 'Code');
        params.set('$top', '5000');
        const resp = await sapClient.get(
          `/b1s/v1/Marcas?${params.toString()}`,
          { headers: { Cookie: buildCookieHeader() } }
        );
        const list = Array.isArray(resp.data && resp.data.value)
          ? resp.data.value
          : [];
        for (const m of list) {
          if (m && m.Code !== undefined && m.Code !== null) {
            const code = String(m.Code).trim();
            if (code) set.add(code);
          }
        }
      } catch (err) {
        console.warn(
          'No se pudo consultar @MARCAS, se usará fallback desde Items:',
          err.message
        );
      }

      // 2) Fallback: extraer marcas únicas desde Items
      if (set.size === 0) {
        const params = new URLSearchParams();
        params.set('$select', 'U_Marca');
        params.set('$filter', "U_Marca ne null and U_Marca ne ''");
        params.set('$top', '5000');
        const resp = await sapClient.get(
          `/b1s/v1/Items?${params.toString()}`,
          { headers: { Cookie: buildCookieHeader() } }
        );
        const list = Array.isArray(resp.data && resp.data.value)
          ? resp.data.value
          : [];
        for (const item of list) {
          if (item && item.U_Marca !== undefined && item.U_Marca !== null) {
            const marca = String(item.U_Marca).trim();
            if (marca) set.add(marca);
          }
        }
      }

      const data = Array.from(set).sort((a, b) =>
        a.localeCompare(b, 'es', { sensitivity: 'base' })
      );

      marcasUnicasCache = {
        data,
        expiresAt: Date.now() + MARCAS_UNICAS_TTL_MS,
      };
      return data;
    } catch (err) {
      marcasUnicasCachePromise = null;
      throw err;
    } finally {
      marcasUnicasCachePromise = null;
    }
  })();

  return marcasUnicasCachePromise;
}

async function loadPriceLists() {
  if (priceListsCache) return priceListsCache;
  if (priceListsCachePromise) return priceListsCachePromise;

  priceListsCachePromise = (async () => {
    try {
      await ensureSession();
      const response = await sapClient.get(
        "/b1s/v1/PriceLists?$select=PriceListNo,PriceListName",
        { headers: { Cookie: buildCookieHeader() } }
      );
      const list = Array.isArray(response.data && response.data.value)
        ? response.data.value
        : [];
      const map = new Map();
      for (const p of list) {
        if (p && p.PriceListNo !== undefined && p.PriceListNo !== null) {
          map.set(
            Number(p.PriceListNo),
            p.PriceListName || String(p.PriceListNo)
          );
        }
      }
      priceListsCache = map;
      return map;
    } catch (err) {
      priceListsCachePromise = null;
      throw err;
    }
  })();

  return priceListsCachePromise;
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

    console.log(
      '[AUTH AD RAW USER KEYS]:',
      Object.keys(adUser || {}),
      'memberOf:',
      adUser && (adUser.memberOf || (adUser._raw && adUser._raw.memberOf))
    );

    const rawMemberOf = adUser && adUser.memberOf;
    const groups = extractGroupNames(rawMemberOf);
    let canConfigurePriceLists = canConfigurePriceListsFromGroups(
      groups,
      rawMemberOf
    );

    // Verificación explícita: si memberOf contiene alguno de los grupos admin
    const memberOfList = Array.isArray(rawMemberOf)
      ? rawMemberOf
      : rawMemberOf
      ? [rawMemberOf]
      : [];
    if (
      memberOfList.some((dn) => {
        const text = String(dn || '').toLowerCase();
        return (
          text.includes('informatica') ||
          text.includes('directorio_rw') ||
          text.includes('directorio')
        );
      })
    ) {
      canConfigurePriceLists = true;
    }

    // Respaldo rápido: usuario administrador conocido
    const samAccountLower = String(authUser || '')
      .split('@')[0]
      .split('\\\\')
      .pop()
      .toLowerCase();
    if (
      samAccountLower === 'hecaballero' ||
      String(authUser || '').toLowerCase() === 'hecaballero@tracto.com.py'
    ) {
      canConfigurePriceLists = true;
    }

    console.log(
      '[AUTH AD] Grupos detectados para el usuario:',
      groups,
      'canConfigure:',
      canConfigurePriceLists
    );

    req.session.user = {
      username: authUser,
      displayName:
        (adUser && (adUser.displayName || adUser.cn)) || authUser,
      email: (adUser && (adUser.mail || adUser.userPrincipalName)) || null,
      groups,
      canConfigurePriceLists,
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

// Mapeo de columnas filtrables a propiedades OData
const COLUMN_FILTER_MAP = {
  Stock: 'QuantityOnStock',
  Comprometido: 'QuantityOrderedByCustomers',
  Pedido: 'QuantityOrderedFromVendors',
  Fecha: 'CreateDate',
  Codigo: 'ItemCode',
  Descripcion: 'ItemName',
  NombreInterno: 'ForeignName',
  Familia: 'SWW',
  Marca: 'U_Marca',
  Fabricante: 'Manufacturer',
};

// Columnas de texto (usan operadores contains/startswith/eq)
const TEXT_FILTER_COLUMNS = new Set([
  'Codigo',
  'Descripcion',
  'NombreInterno',
  'Familia',
  'Marca',
  'Fabricante',
]);

const TEXT_OPERATORS = new Set(['contains', 'startswith', 'eq']);

const NUMERIC_OPERATORS = new Set(['eq', 'gt', 'ge', 'lt', 'le', 'ne']);

function parseColumnFilters(query) {
  const result = {};
  for (const key of Object.keys(query || {})) {
    const m = /^colFilter_([A-Za-z]+)_(.+)$/.exec(key);
    if (!m) continue;
    const col = m[1];
    const field = m[2];
    const value = query[key];
    if (value === undefined || value === null || value === '') continue;
    if (!result[col]) result[col] = {};
    result[col][field] = value;
  }
  return result;
}

function buildColumnFilterConditions(colFilters) {
  const conditions = [];

  for (const [col, spec] of Object.entries(colFilters || {})) {
    const prop = COLUMN_FILTER_MAP[col];
    if (!prop) continue;

    if (col === 'Fecha') {
      // Fecha específica: colFilter_Fecha_date=YYYY-MM-DD
      if (spec.date) {
        const d = String(spec.date);
        if (/^\d{4}-\d{2}-\d{2}$/.test(d)) {
          conditions.push(`CreateDate ge '${d}T00:00:00'`);
          conditions.push(`CreateDate le '${d}T23:59:59'`);
        }
      }
      // Año: colFilter_Fecha_year=YYYY
      if (spec.year) {
        const y = parseInt(spec.year, 10);
        if (Number.isFinite(y) && y >= 1900 && y <= 9999) {
          conditions.push(`CreateDate ge '${y}-01-01T00:00:00'`);
          conditions.push(`CreateDate le '${y}-12-31T23:59:59'`);
        }
      }
      // Mes: colFilter_Fecha_month=1..12 (requiere year)
      if (spec.month) {
        const mo = parseInt(spec.month, 10);
        const y = spec.year ? parseInt(spec.year, 10) : null;
        if (Number.isFinite(mo) && mo >= 1 && mo <= 12 && Number.isFinite(y)) {
          const start = new Date(Date.UTC(y, mo - 1, 1));
          const end = new Date(Date.UTC(y, mo, 0, 23, 59, 59));
          const fmt = (dt) => dt.toISOString().slice(0, 19);
          conditions.push(`CreateDate ge '${fmt(start)}'`);
          conditions.push(`CreateDate le '${fmt(end)}'`);
        }
      }
      continue;
    }

    // Texto
    if (TEXT_FILTER_COLUMNS.has(col)) {
      const op = String(spec.op || 'contains').toLowerCase();
      if (!TEXT_OPERATORS.has(op)) continue;
      const raw = spec.val;
      if (raw === undefined || raw === null || String(raw).trim() === '') continue;
      const safe = escapeODataString(String(raw));
      if (op === 'contains') {
        conditions.push(`contains(${prop},'${safe}')`);
      } else if (op === 'startswith') {
        conditions.push(`startswith(${prop},'${safe}')`);
      } else {
        conditions.push(`${prop} eq '${safe}'`);
      }
      continue;
    }

    // Numéricas
    const op = String(spec.op || 'eq').toLowerCase();
    if (!NUMERIC_OPERATORS.has(op)) continue;
    const raw = spec.val;
    if (raw === undefined || raw === null || raw === '') continue;
    const num = Number(raw);
    if (!Number.isFinite(num)) continue;
    conditions.push(`${prop} ${op} ${num}`);
  }

  return conditions;
}

function buildArticulosQuery({
  page,
  limit,
  search,
  rubro,
  fabricante,
  marca,
  stockEstado,
  colFilters,
}) {
  const filters = ["ItemType eq 'itItems'"];

  const columnConditions = buildColumnFilterConditions(colFilters);
  for (const cond of columnConditions) {
    filters.push(cond);
  }

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

  if (stockEstado) {
    switch (stockEstado) {
      case 'con_stock':
        filters.push('QuantityOnStock gt 0');
        break;
      case 'sin_stock':
        filters.push('QuantityOnStock le 0');
        break;
      case 'con_comprometido':
        filters.push('QuantityOrderedByCustomers gt 0');
        break;
      case 'con_pedido':
        filters.push('QuantityOrderedFromVendors gt 0');
        break;
      case 'con_disponible':
        filters.push(
          '(QuantityOnStock gt QuantityOrderedByCustomers or QuantityOrderedFromVendors gt 0)'
        );
        break;
      case 'faltante':
        filters.push(
          'QuantityOnStock sub QuantityOrderedByCustomers add QuantityOrderedFromVendors lt 0'
        );
        break;
      default:
        break;
    }
  }

  const skip = (page - 1) * limit;
  const top = limit;

  const params = new URLSearchParams();
  params.set('$filter', filters.join(' and '));
  params.set(
    '$select',
    'ItemCode,ItemName,ForeignName,QuantityOnStock,SalesUnit,SWW,ItemsGroupCode,Manufacturer,CreateDate,U_Marca,U_Modelo,QuantityOrderedByCustomers,QuantityOrderedFromVendors,ItemWarehouseInfoCollection,ItemPrices'
  );
  params.set('$orderby', 'ItemCode');
  params.set('$top', String(top));
  params.set('$skip', String(skip));
  params.set('$inlinecount', 'allpages');

  return `/b1s/v1/Items?${params.toString()}`;
}

app.get('/api/articulos/config-precios', requireAuth, (req, res) => {
  const config = readPriceListsConfig();
  return res.json(config);
});

app.post('/api/articulos/config-precios', requireAuth, (req, res) => {
  const user = req.session && req.session.user;
  if (!user || user.canConfigurePriceLists !== true) {
    return res
      .status(403)
      .json({ error: { message: 'No tiene permisos para configurar listas de precios' } });
  }

  const body = req.body || {};
  const visibleLists = Array.isArray(body.visibleLists)
    ? body.visibleLists.map(Number).filter((n) => Number.isFinite(n))
    : [];

  const ok = writePriceListsConfig({ visibleLists });
  if (!ok) {
    return res
      .status(500)
      .json({ error: { message: 'No se pudo guardar la configuración' } });
  }

  return res.json({ ok: true, visibleLists });
});

const IA_SYSTEM_PROMPT = `Eres un asistente que traduce consultas en lenguaje natural sobre artículos (repuestos, tractores, maquinaria agrícola) a un objeto JSON de filtros para un sistema SAP Business One.

Debes responder SIEMPRE y ÚNICAMENTE con un objeto JSON válido, sin texto adicional, sin markdown, sin explicaciones.

El JSON debe tener EXACTAMENTE esta forma:
{
  "search": string,
  "rubro": string,
  "fabricante": string,
  "marca": string,
  "stockEstado": "conStock" | "sinStock" | "conComprometido" | "conPedido" | "",
  "colFilters": {
    "Stock": { "op": "eq" | "gt" | "ge" | "lt" | "le" | "ne", "val": number },
    "Comprometido": { "op": "eq" | "gt" | "ge" | "lt" | "le" | "ne", "val": number },
    "Pedido": { "op": "eq" | "gt" | "ge" | "lt" | "le" | "ne", "val": number },
    "Fecha": { "year": number, "month": number, "date": "YYYY-MM-DD" }
  }
}

Reglas:
- "search": texto libre para buscar por código o descripción (ej: "Lovol", "filtro aceite"). Cadena vacía si no aplica.
- "rubro": nombre del rubro/grupo de artículos si el usuario lo menciona (ej: "Repuestos", "Tractores"). Cadena vacía si no aplica.
- "fabricante": nombre del fabricante si se menciona (ej: "Lovol", "John Deere"). Cadena vacía si no aplica.
- "marca": marca del artículo si se menciona. Cadena vacía si no aplica.
- "stockEstado": 
  * "conStock" si pide artículos con stock disponible (> 0).
  * "sinStock" si pide artículos sin stock.
  * "conComprometido" si pide artículos con cantidad comprometida.
  * "conPedido" si pide artículos con pedidos pendientes.
  * "" si no aplica.
- "colFilters": solo incluye las claves que el usuario mencione explícitamente. Omite las que no apliquen.
  * "Stock", "Comprometido", "Pedido": usan "op" y "val" numérico. Ej: "stock > 2" => { "op": "gt", "val": 2 }.
  * "Fecha": usa "year" (número), "month" (1-12) y/o "date" ("YYYY-MM-DD"). Omite los campos no mencionados.

Si el usuario no especifica nada para un campo, usa cadena vacía "" o {} según corresponda. Nunca inventes valores.`;

function sanitizeIaResponse(raw) {
  const out = {
    search: '',
    rubro: '',
    fabricante: '',
    marca: '',
    stockEstado: '',
    colFilters: {},
  };
  if (!raw || typeof raw !== 'object') return out;

  if (typeof raw.search === 'string') out.search = raw.search.trim();
  if (typeof raw.rubro === 'string') out.rubro = raw.rubro.trim();
  if (typeof raw.fabricante === 'string') out.fabricante = raw.fabricante.trim();
  if (typeof raw.marca === 'string') out.marca = raw.marca.trim();

  const validStock = new Set(['conStock', 'sinStock', 'conComprometido', 'conPedido', '']);
  if (typeof raw.stockEstado === 'string' && validStock.has(raw.stockEstado)) {
    out.stockEstado = raw.stockEstado;
  }

  const validOps = new Set(['eq', 'gt', 'ge', 'lt', 'le', 'ne']);
  const cf = raw.colFilters && typeof raw.colFilters === 'object' ? raw.colFilters : {};

  for (const key of ['Stock', 'Comprometido', 'Pedido']) {
    const spec = cf[key];
    if (spec && typeof spec === 'object') {
      const op = String(spec.op || '').toLowerCase();
      const val = Number(spec.val);
      if (validOps.has(op) && Number.isFinite(val)) {
        out.colFilters[key] = { op, val };
      }
    }
  }

  const fecha = cf.Fecha;
  if (fecha && typeof fecha === 'object') {
    const f = {};
    const y = parseInt(fecha.year, 10);
    if (Number.isFinite(y) && y >= 1900 && y <= 9999) f.year = y;
    const m = parseInt(fecha.month, 10);
    if (Number.isFinite(m) && m >= 1 && m <= 12) f.month = m;
    if (typeof fecha.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(fecha.date)) {
      f.date = fecha.date;
    }
    if (Object.keys(f).length) out.colFilters.Fecha = f;
  }

  return out;
}

app.post('/api/articulos/ia-prompt', requireAuth, async (req, res) => {
  const prompt = (req.body && req.body.prompt ? String(req.body.prompt) : '').trim();
  if (!prompt) {
    return res
      .status(400)
      .json({ error: { message: 'El prompt es obligatorio' } });
  }

  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) {
    return res
      .status(500)
      .json({ error: { message: 'Falta DEEPSEEK_API_KEY en el entorno' } });
  }

  try {
    const response = await fetch(DEEPSEEK_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'deepseek-chat',
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: IA_SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
      }),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      console.error('Error DeepSeek:', response.status, text);
      return res.status(502).json({
        error: { message: 'Error al consultar el servicio de IA' },
      });
    }

    const data = await response.json();
    const content =
      data &&
      data.choices &&
      data.choices[0] &&
      data.choices[0].message &&
      data.choices[0].message.content;

    if (!content) {
      return res
        .status(502)
        .json({ error: { message: 'Respuesta vacía del servicio de IA' } });
    }

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (_) {
      return res
        .status(502)
        .json({ error: { message: 'La IA no devolvió un JSON válido' } });
    }

    const sanitized = sanitizeIaResponse(parsed);
    return res.json(sanitized);
  } catch (err) {
    console.error('Error en /api/articulos/ia-prompt:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al procesar la consulta de IA' } });
  }
});

app.get('/api/marcas', requireAuth, async (req, res) => {
  try {
    const marcas = await loadMarcasUnicas();
    return res.json(marcas);
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const marcas = await loadMarcasUnicas();
        return res.json(marcas);
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

app.get('/api/articulos/catalogos', requireAuth, async (req, res) => {
  try {
    await ensureSession();

    const [itemGroups, manufacturers, priceLists] = await Promise.all([
      loadItemGroups().catch((err) => {
        console.warn('No se pudo cargar el catálogo de grupos:', err.message);
        return new Map();
      }),
      loadManufacturers().catch((err) => {
        console.warn('No se pudo cargar el catálogo de fabricantes:', err.message);
        return new Map();
      }),
      loadPriceLists().catch((err) => {
        console.warn('No se pudo cargar el catálogo de listas de precios:', err.message);
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

    const priceListsArr = Array.from(priceLists.entries())
      .map(([code, name]) => ({ code: Number(code), name }))
      .sort((a, b) => a.code - b.code);

    return res.json({ rubros, fabricantes, marcas, priceLists: priceListsArr });
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
  const stockEstado = (req.query.stockEstado || '').trim();
  const colFilters = parseColumnFilters(req.query);

  // Fallback para 'faltante': Service Layer puede rechazar expresiones
  // aritméticas en $filter, por lo que se consulta con un filtro simple
  // y se filtra/pagina en memoria.
  if (stockEstado === 'faltante') {
    return handleFaltante(req, res, {
      page,
      limit,
      search,
      rubro,
      fabricante,
      marca,
      colFilters,
    });
  }

  const query = buildArticulosQuery({
    page,
    limit,
    search,
    rubro,
    fabricante,
    marca,
    stockEstado,
    colFilters,
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
    const priceListsPromise = loadPriceLists().catch((err) => {
      console.warn('No se pudo cargar el catálogo de listas de precios:', err.message);
      return new Map();
    });

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    const [warehouses, itemGroups, manufacturers, priceLists] = await Promise.all([
      warehousesPromise,
      itemGroupsPromise,
      manufacturersPromise,
      priceListsPromise,
    ]);
    return sendArticulosResponse(res, response.data, {
      page,
      limit,
      warehouses,
      itemGroups,
      manufacturers,
      priceLists,
    });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const [warehouses, itemGroups, manufacturers, priceLists] = await Promise.all([
          loadWarehouses().catch(() => new Map()),
          loadItemGroups().catch(() => new Map()),
          loadManufacturers().catch(() => new Map()),
          loadPriceLists().catch(() => new Map()),
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
          priceLists,
        });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

async function handleFaltante(
  req,
  res,
  { page, limit, search, rubro, fabricante, marca, colFilters }
) {
  // Construir query sin paginación y con filtro simple soportado por SAP
  const baseQuery = buildArticulosQuery({
    page: 1,
    limit: 200,
    search,
    rubro,
    fabricante,
    marca,
    stockEstado: '',
    colFilters,
  });

  // Reemplazar el filtro de stock por uno simple y quitar paginación
  const url = new URL(baseQuery, 'http://localhost');
  const params = url.searchParams;
  const existingFilter = params.get('$filter') || '';
  const simpleFilter = existingFilter
    ? `${existingFilter} and QuantityOrderedByCustomers gt 0`
    : 'QuantityOrderedByCustomers gt 0';
  params.set('$filter', simpleFilter);
  params.delete('$top');
  params.delete('$skip');
  params.delete('$inlinecount');
  const query = `${url.pathname}?${params.toString()}`;

  try {
    await ensureSession();

    const [warehouses, itemGroups, manufacturers, priceLists] = await Promise.all([
      loadWarehouses().catch(() => new Map()),
      loadItemGroups().catch(() => new Map()),
      loadManufacturers().catch(() => new Map()),
      loadPriceLists().catch(() => new Map()),
    ]);

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    const raw = Array.isArray(response.data && response.data.value)
      ? response.data.value
      : [];

    const faltantes = raw.filter((item) => {
      const disponible =
        (Number(item.QuantityOnStock) || 0) -
        (Number(item.QuantityOrderedByCustomers) || 0) +
        (Number(item.QuantityOrderedFromVendors) || 0);
      return disponible < 0;
    });

    const total = faltantes.length;
    const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;
    const start = (page - 1) * limit;
    const pageItems = faltantes.slice(start, start + limit);

    return sendArticulosResponse(
      res,
      { value: pageItems, 'odata.count': total },
      { page, limit, warehouses, itemGroups, manufacturers, priceLists }
    );
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const [warehouses, itemGroups, manufacturers, priceLists] = await Promise.all([
          loadWarehouses().catch(() => new Map()),
          loadItemGroups().catch(() => new Map()),
          loadManufacturers().catch(() => new Map()),
          loadPriceLists().catch(() => new Map()),
        ]);
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        const raw = Array.isArray(retry.data && retry.data.value)
          ? retry.data.value
          : [];
        const faltantes = raw.filter((item) => {
          const disponible =
            (Number(item.QuantityOnStock) || 0) -
            (Number(item.QuantityOrderedByCustomers) || 0) +
            (Number(item.QuantityOrderedFromVendors) || 0);
          return disponible < 0;
        });
        const total = faltantes.length;
        const start = (page - 1) * limit;
        const pageItems = faltantes.slice(start, start + limit);
        return sendArticulosResponse(
          res,
          { value: pageItems, 'odata.count': total },
          { page, limit, warehouses, itemGroups, manufacturers, priceLists }
        );
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
}

function sendArticulosResponse(
  res,
  sapData,
  { page, limit, warehouses, itemGroups, manufacturers, priceLists }
) {
  const raw = Array.isArray(sapData.value) ? sapData.value : [];
  const total = Number(sapData['odata.count'] ?? sapData['@odata.count'] ?? 0) || 0;
  const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;
  const whMap = warehouses instanceof Map ? warehouses : new Map();
  const groupMap = itemGroups instanceof Map ? itemGroups : new Map();
  const manufMap = manufacturers instanceof Map ? manufacturers : new Map();
  const priceMap = priceLists instanceof Map ? priceLists : new Map();

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

    const prices = Array.isArray(item.ItemPrices)
      ? item.ItemPrices.map((p) => {
          const code = Number(p.PriceList);
          return {
            PriceList: code,
            PriceListName: priceMap.get(code) || String(p.PriceList),
            Price: Number(p.Price) || 0,
            Currency: p.Currency || '',
          };
        })
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
      Available:
        (Number(item.QuantityOnStock) || 0) -
        (Number(item.QuantityOrderedByCustomers) || 0) +
        (Number(item.QuantityOrderedFromVendors) || 0),
      Warehouses: warehouses,
      Prices: prices,
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
