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
const hana = require('@sap/hana-client');

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
  HANA_HOST,
  HANA_PORT,
  HANA_USER,
  HANA_PASSWORD,
  HANA_SCHEMA,
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

// Grupos de AD con permiso para usar el módulo de IA (en minúsculas)
const IA_ALLOWED_GROUPS = ['informatica', 'directorio', 'directorio_rw'];

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

// Vendedor por defecto cuando no hay coincidencia por email/usuario
function getDefaultVendedor() {
  const rawCode = process.env.DEFAULT_SLP_CODE;
  const parsed = parseInt(rawCode, 10);
  const slpCode = Number.isFinite(parsed) ? parsed : -1;
  return {
    slpCode,
    slpName: 'Ventas Casa Central / General',
    empId: null,
    sucursalDefault: '01',
    slpAsignadoManual: true,
  };
}

// Resuelve los datos del vendedor cruzando OHEM (empleado) con OSLP (vendedor)
// y OUSR (usuario SAP) a partir del email de login o del nombre de usuario AD.
// Si no hay coincidencia, devuelve un vendedor por defecto (slpAsignadoManual = true).
async function obtenerDatosVendedor(identificadorUsuario) {
  const raw = String(identificadorUsuario || '').trim();
  if (!raw) return getDefaultVendedor();
  // Prefijo del usuario (antes de @) para el LIKE
  const prefix = raw.includes('@') ? raw.split('@')[0] : raw;
  const sql = `SELECT T0."empID" AS "empId", T0."salesPrson" AS "slpCode", T1."SlpName" AS "slpName", T0."email" AS "email"
    FROM "TRACTOAGRO".OHEM T0
    INNER JOIN "TRACTOAGRO".OSLP T1 ON T0."salesPrson" = T1."SlpCode"
    LEFT JOIN "TRACTOAGRO".OUSR T2 ON T0."userId" = T2."USERID"
    WHERE (LOWER(T0."email") = LOWER(?) OR LOWER(T0."email") LIKE LOWER(? || '@%') OR LOWER(T2."USER_CODE") = LOWER(?))
      AND T1."Active" = 'Y'
    LIMIT 1`;
  try {
    const rows = await hanaExec(sql, [raw, prefix, raw]);
    if (!rows || !rows.length) return getDefaultVendedor();
    const r = rows[0];
    return {
      slpCode: r.slpCode !== undefined && r.slpCode !== null ? Number(r.slpCode) : null,
      slpName: r.slpName !== undefined && r.slpName !== null ? String(r.slpName) : '',
      empId: r.empId !== undefined && r.empId !== null ? Number(r.empId) : null,
      sucursalDefault: '01',
      slpAsignadoManual: false,
    };
  } catch (err) {
    console.warn('No se pudo resolver el vendedor en HANA:', err.message);
    return getDefaultVendedor();
  }
}

function canUseIAFromGroups(groups, rawMemberOf) {
  if (Array.isArray(groups)) {
    const lower = groups.map((g) => String(g).toLowerCase());
    if (IA_ALLOWED_GROUPS.some((g) => lower.includes(g))) {
      return true;
    }
  }
  if (rawMemberOf) {
    const list = Array.isArray(rawMemberOf) ? rawMemberOf : [rawMemberOf];
    for (const dn of list) {
      if (!dn) continue;
      const text = String(dn).toLowerCase();
      if (IA_ALLOWED_GROUPS.some((g) => text.includes(`cn=${g}`))) {
        return true;
      }
    }
  }
  return false;
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

// ---------------------------------------------------------------------------
// Conexión reutilizable a SAP HANA
// ---------------------------------------------------------------------------
let hanaClient = null;
let hanaClientPromise = null;

function getHanaClient() {
  if (hanaClient) return Promise.resolve(hanaClient);
  if (hanaClientPromise) return hanaClientPromise;

  hanaClientPromise = new Promise((resolve, reject) => {
    if (!HANA_HOST || !HANA_USER || !HANA_PASSWORD) {
      hanaClientPromise = null;
      return reject(
        new Error(
          'Faltan variables de entorno de HANA (HANA_HOST, HANA_USER, HANA_PASSWORD)'
        )
      );
    }

    const client = hana.createConnection();
    const params = {
      serverNode: `${HANA_HOST}:${HANA_PORT || 30015}`,
      uid: HANA_USER,
      pwd: HANA_PASSWORD,
    };
    if (HANA_SCHEMA) params.currentSchema = HANA_SCHEMA;

    client.connect(params, (err) => {
      if (err) {
        hanaClientPromise = null;
        return reject(err);
      }
      hanaClient = client;
      console.log('Conexión HANA establecida');
      resolve(client);
    });
  });

  return hanaClientPromise;
}

function hanaExec(sql, params = []) {
  return getHanaClient().then(
    (client) =>
      new Promise((resolve, reject) => {
        client.exec(sql, params, (err, rows) => {
          if (err) return reject(err);
          resolve(rows || []);
        });
      })
  );
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
// NOTA: ya no se usa en /api/articulos/catalogos (ahora consulta HANA directamente).
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

// Middleware de autorización para el módulo de IA
function requireIA(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: { message: 'No autenticado' } });
  }
  if (user.canUseIA === true) return next();
  return res
    .status(403)
    .json({ error: { message: 'No tiene permisos para usar el módulo de IA' } });
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

    // Permiso para usar el módulo de IA (mismos grupos que listas de precios)
    let canUseIA = canUseIAFromGroups(groups, rawMemberOf);
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
      canUseIA = true;
    }
    if (
      samAccountLower === 'hecaballero' ||
      String(authUser || '').toLowerCase() === 'hecaballero@tracto.com.py'
    ) {
      canUseIA = true;
    }

    // Resolver vendedor SAP (OHEM/OSLP/OUSR) por email o usuario AD
    const emailForVendor =
      (adUser && (adUser.mail || adUser.userPrincipalName)) || authUser;
    const samAccountForVendor = String(authUser || '')
      .split('@')[0]
      .split('\\\\')
      .pop();
    // Intentar primero por email; si no hay coincidencia, por username AD
    let vendedor = await obtenerDatosVendedor(emailForVendor);
    if (!vendedor || vendedor.slpAsignadoManual === true) {
      const porUsuario = await obtenerDatosVendedor(samAccountForVendor);
      if (porUsuario && porUsuario.slpAsignadoManual !== true) {
        vendedor = porUsuario;
      }
    }

    req.session.user = {
      username: authUser,
      displayName:
        (adUser && (adUser.displayName || adUser.cn)) || authUser,
      email: (adUser && (adUser.mail || adUser.userPrincipalName)) || null,
      groups,
      canConfigurePriceLists,
      canUseIA,
      slpCode: vendedor ? vendedor.slpCode : null,
      slpName: vendedor ? vendedor.slpName : '',
      empId: vendedor ? vendedor.empId : null,
      sucursalDefault: vendedor && vendedor.sucursalDefault ? vendedor.sucursalDefault : '01',
      slpAsignadoManual: vendedor ? vendedor.slpAsignadoManual === true : true,
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
  grupos,
  fabricantes,
  marcas,
  stockEstado,
  colFilters,
  itemGroups,
}) {
  const filters = ["ItemType eq 'itItems'"];

  // Resolver filtro de texto de Rubro (nombre de grupo) a ItemsGroupCode
  let effectiveColFilters = colFilters;
  if (colFilters && colFilters.Rubro && itemGroups instanceof Map) {
    const spec = colFilters.Rubro;
    const rawVal = spec && spec.val !== undefined && spec.val !== null
      ? String(spec.val).trim()
      : '';
    if (rawVal) {
      const op = String(spec.op || 'contains').toLowerCase();
      const needle = rawVal.toLowerCase();
      const matchedCodes = [];
      for (const [code, name] of itemGroups.entries()) {
        const groupName = String(name || '').toLowerCase();
        let match = false;
        if (op === 'eq') match = groupName === needle;
        else if (op === 'startswith') match = groupName.startsWith(needle);
        else match = groupName.includes(needle);
        if (match) {
          const n = parseInt(code, 10);
          if (Number.isFinite(n)) matchedCodes.push(n);
        }
      }
      effectiveColFilters = { ...colFilters };
      delete effectiveColFilters.Rubro;
      if (matchedCodes.length) {
        filters.push(`(${matchedCodes.map((c) => `ItemsGroupCode eq ${c}`).join(' or ')})`);
      } else {
        // Sin coincidencias: forzar resultado vacío
        filters.push('ItemsGroupCode eq -1');
      }
    }
  }

  const columnConditions = buildColumnFilterConditions(effectiveColFilters);
  for (const cond of columnConditions) {
    filters.push(cond);
  }

  if (search) {
    const safe = escapeODataString(search);
    filters.push(
      `(contains(ItemCode,'${safe}') or contains(ItemName,'${safe}'))`
    );
  }

  // Grupos (múltiples): resolver nombres a ItemsGroupCode
  const gruposList = Array.isArray(grupos) && grupos.length
    ? grupos
    : (rubro !== undefined && rubro !== null && rubro !== '' ? [rubro] : []);
  if (gruposList.length && itemGroups instanceof Map) {
    const matchedCodes = new Set();
    for (const g of gruposList) {
      const n = parseInt(g, 10);
      if (Number.isFinite(n) && String(n) === String(g).trim()) {
        matchedCodes.add(n);
        continue;
      }
      const needle = String(g).trim().toLowerCase();
      for (const [code, name] of itemGroups.entries()) {
        if (String(name || '').toLowerCase() === needle) {
          const c = parseInt(code, 10);
          if (Number.isFinite(c)) matchedCodes.add(c);
        }
      }
    }
    if (matchedCodes.size) {
      filters.push(`(${Array.from(matchedCodes).map((c) => `ItemsGroupCode eq ${c}`).join(' or ')})`);
    } else {
      filters.push('ItemsGroupCode eq -1');
    }
  }

  // Fabricantes (múltiples): resolver nombres a Manufacturer code
  const fabricantesList = Array.isArray(fabricantes) && fabricantes.length
    ? fabricantes
    : (fabricante !== undefined && fabricante !== null && fabricante !== '' ? [fabricante] : []);
  if (fabricantesList.length) {
    const matchedCodes = new Set();
    for (const f of fabricantesList) {
      const n = parseInt(f, 10);
      if (Number.isFinite(n) && String(n) === String(f).trim()) {
        matchedCodes.add(n);
      }
    }
    if (matchedCodes.size) {
      filters.push(`(${Array.from(matchedCodes).map((c) => `Manufacturer eq ${c}`).join(' or ')})`);
    } else {
      filters.push('Manufacturer eq -1');
    }
  }

  // Marcas (múltiples)
  const marcasList = Array.isArray(marcas) && marcas.length
    ? marcas
    : (marca !== undefined && marca !== null && marca !== '' ? [marca] : []);
  if (marcasList.length) {
    const safeList = marcasList.map((m) => `U_Marca eq '${escapeODataString(m)}'`);
    filters.push(`(${safeList.join(' or ')})`);
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

const IA_SQL_SYSTEM_PROMPT = `Eres un experto en SAP HANA SQL. Tu tarea es interpretar consultas en lenguaje natural sobre productos/artículos de la vista "TRACTOAGRO"."V_PRODUCTOS" y responder SIEMPRE con un objeto JSON válido, sin texto adicional, sin markdown, sin bloques de código.

Esquema de la vista "TRACTOAGRO"."V_PRODUCTOS":
- ACTIVO (char 'Y'/'N')
- CODIGO_TRACTO (nvarchar) — código del artículo
- NOMBRE (nvarchar) — descripción
- NOMBRE_INTERNO (nvarchar)
- CODIGO_FABRICA (nvarchar)
- RUBRO (nvarchar)
- MARCA (nvarchar)
- MODELO (nvarchar)
- FABRICANTE (nvarchar)
- FAMILIA (nvarchar)
- UNIDAD (nvarchar)
- STOCK_TOTAL (decimal)
- COMPROMETIDO (decimal)
- EN_PEDIDO (decimal)
- DISPONIBLE (decimal)
- FECHA_CREACION (date)
- FECHA_ULT_VENTA (date)
- PRECIO_ULT_COMPRA (decimal)
- MONEDA_ULT_COMPRA (nvarchar)
- FECHA_ULT_COMPRA (date)
- FECHA_ULT_ACT (date)
- COSTO_PROM (decimal)

Esquema de la vista "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA" (para consultas de ventas, rotación, facturación y devoluciones):
- CODIGO_TRACTO (nvarchar) — código del artículo
- NOMBRE (nvarchar) — descripción del artículo
- RUBRO (nvarchar) — rubro/grupo del artículo
- MARCA (nvarchar) — marca del artículo
- FAMILIA (nvarchar) — familia del artículo (obtenida de SWW de OITM)
- FECHA_VENTA (date) — fecha del documento de venta
- ANIO (integer) — año de la venta
- MES (integer) — mes de la venta (1-12)
- CANTIDAD (decimal) — cantidad vendida (negativa en notas de crédito)
- TOTAL_GS (decimal) — importe en guaraníes (negativo en notas de crédito)
- TOTAL_USD (decimal) — importe en dólares (negativo en notas de crédito)
- CODIGO_CLIENTE (nvarchar) — código del cliente
- CLIENTE (nvarchar) — nombre del cliente
- CODIGO_VENDEDOR (nvarchar) — código del vendedor
- TIPO_DOCUMENTO (nvarchar) — valores posibles: 'Factura', 'Factura Reserva', 'Nota de Credito'

IMPORTANTE sobre "V_VENTAS_ARTICULOS_ANALITICA":
- La vista YA descuenta automáticamente las notas de crédito: las cantidades e importes de las notas de crédito vienen con signo negativo.
- También incluye las facturas de reserva bajo TIPO_DOCUMENTO = 'Factura Reserva'.
- Por lo tanto, para calcular ventas netas, rotación o facturación SIEMPRE usa SUM("CANTIDAD"), SUM("TOTAL_GS") o SUM("TOTAL_USD") directamente, SIN restar ni filtrar notas de crédito manualmente.
- Si el usuario pregunta por ventas netas o devoluciones, puedes filtrar o desglosar por TIPO_DOCUMENTO ('Factura', 'Factura Reserva', 'Nota de Credito') usando GROUP BY "TIPO_DOCUMENTO" o una condición WHERE "TIPO_DOCUMENTO" = '...'.
- Cuando el usuario pida "ventas", "facturación", "rotación", "más vendidos", "top vendidos", "ventas por rubro/marca/familia", "ventas del mes/año", etc., usa esta vista (NO "V_PRODUCTOS").
- Cuando el usuario pida stock, inventario, existencias, quiebres o valorización, usa "V_PRODUCTOS".
- IMPORTANTE — Rankings de ventas por artículo: cuando el usuario pida "top artículos más vendidos", "ranking de artículos", "artículos más vendidos", "productos más vendidos" o similar, agrupa SIEMPRE por "CODIGO_TRACTO" y "NOMBRE" (ambas columnas en el GROUP BY) para evitar perder la descripción del artículo. Ejemplo:
  SELECT "CODIGO_TRACTO", "NOMBRE", SUM("CANTIDAD") AS "CANTIDAD_VENDIDA", SUM("TOTAL_GS") AS "TOTAL_GS"
  FROM "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA"
  GROUP BY "CODIGO_TRACTO", "NOMBRE"
  ORDER BY "TOTAL_GS" DESC
  LIMIT 10
  Usa "tipoVisual": "grafico_barra" (o "texto" si el usuario pide un listado detallado).
- IMPORTANTE — Familia de productos en ventas: la vista "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA" incluye la columna "FAMILIA" (obtenida de SWW de OITM). Cuando el usuario pregunte por familia de productos en ventas (ej: "Top familias con mayor facturación", "ventas por familia", "ranking de familias más vendidas"), DEBES:
  * Agrupar por "FAMILIA".
  * Omitir valores nulos o vacíos con la condición: "FAMILIA" IS NOT NULL AND "FAMILIA" != ''
  * Sumar "TOTAL_GS" o "TOTAL_USD" según la moneda solicitada (por defecto "TOTAL_GS").
  * Ordenar DESCENDENTE por la métrica y aplicar LIMIT (5 por defecto, o el N indicado).
  Ejemplo:
  SELECT "FAMILIA", SUM("TOTAL_GS") AS "TOTAL_GS"
  FROM "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA"
  WHERE "FAMILIA" IS NOT NULL AND "FAMILIA" != ''
  GROUP BY "FAMILIA"
  ORDER BY "TOTAL_GS" DESC
  LIMIT 5
  Usa "tipoVisual": "grafico_barra" (o "grafico_pie" si el usuario pide participación/distribución).
- IMPORTANTE — La columna "FAMILIA" existe tanto en "TRACTOAGRO"."V_PRODUCTOS" como en "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA". Usa "V_PRODUCTOS" para consultas de stock/inventario por familia y "V_VENTAS_ARTICULOS_ANALITICA" para consultas de ventas/facturación por familia.
- IMPORTANTE — Filtros de texto en ventas (RUBRO, MARCA, NOMBRE, CLIENTE, etc.): usa SIEMPRE comparaciones insensibles a mayúsculas y acentos con UPPER(...) LIKE y comodines '%'. Ejemplos:
  * "ventas de repuestos agrícolas" => UPPER("RUBRO") LIKE '%REPUESTO%AGRICOLA%' o UPPER("RUBRO") LIKE '%AGRICOLA%'
  * "ventas de la marca Lovol" => UPPER("MARCA") LIKE '%LOVOL%'
  * "ventas a clientes de Asunción" => UPPER("CLIENTE") LIKE '%ASUNCION%'
  No uses comparaciones exactas (=) para estos campos de texto libre.
- IMPORTANTE — Tolerancia a acentos en LIKE (SAP HANA): en SAP HANA las búsquedas con LIKE deben ser tolerantes a acentos en vocales. Para palabras con vocales acentuadas (á, é, í, ó, ú, Á, É, Í, Ó, Ú), reemplaza la vocal acentuada por el comodín de un carácter '_' para que coincida tanto con la vocal sin acento como con la acentuada. Ejemplos:
  * "agrícola" => UPPER("RUBRO") LIKE '%AGR_COLA%' o UPPER("RUBRO") LIKE '%AGRIC%LA%'
  * "mecánica" => UPPER("RUBRO") LIKE '%MEC_NICA%'
  * "eléctrico" => UPPER("RUBRO") LIKE '%EL_CTRICO%'
  * "neumáticos" => UPPER("NOMBRE") LIKE '%NEUM_TICOS%'
  * "Asunción" => UPPER("CLIENTE") LIKE '%ASUNCI_N%'
  Aplica esta regla SIEMPRE que la palabra del usuario contenga vocales acentuadas.
- IMPORTANTE — "lo que va del año" / año actual: cuando el usuario pida "lo que va del año", "este año", "año actual", "YTD" o similar, filtra por el año en curso usando "ANIO" = YEAR(CURRENT_DATE) o, alternativamente, "FECHA_VENTA" >= TO_DATE(CONCAT(YEAR(CURRENT_DATE), '-01-01'), 'YYYY-MM-DD'). Ejemplo:
  SELECT SUM("TOTAL_GS") AS "VENTAS_ANIO_ACTUAL"
  FROM "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA"
  WHERE "ANIO" = YEAR(CURRENT_DATE)
- IMPORTANTE — "último año" / fechas relativas sin año fijo: cuando el usuario pida "último año", "últimos 12 meses", "último período" o similar SIN especificar un año fijo, NO uses YEAR(CURRENT_DATE) directamente (la base puede tener fechas desfasadas y devolver conjuntos vacíos). En su lugar, usa una de estas estrategias:
  * Filtrar por el año máximo disponible en la vista:
    WHERE "ANIO" = (SELECT MAX("ANIO") FROM "TRACTOAGRO"."V_VENTAS_ARTICULOS_ANALITICA")
  * O filtrar por los últimos 365 días:
    WHERE "FECHA_VENTA" >= ADD_DAYS(CURRENT_DATE, -365)
  Elige la estrategia que mejor se ajuste a la intención del usuario y evita retornar conjuntos vacíos por desfase de fechas.

Clasifica la consulta del usuario en uno de dos modos:

MODO "lista": cuando el usuario quiere ver registros/artículos concretos (listados, búsquedas, "muéstrame los...", "qué artículos...", "cuáles tienen...").
Devuelve EXACTAMENTE:
{
  "modo": "lista",
  "whereClause": "condicion_sql_hana_sin_la_palabra_WHERE",
  "explicacion": "texto breve en español describiendo el filtro aplicado"
}

MODO "resumen": cuando el usuario pide totales, sumas, promedios, conteos, agrupaciones, comparaciones o KPIs ("cuántos", "total de", "suma de", "promedio", "por rubro", "por marca", "top 5", etc.).
Devuelve EXACTAMENTE:
{
  "modo": "resumen",
  "sql": "sentencia_select_completa_sobre_TRACTOAGRO.V_PRODUCTOS",
  "tipoVisual": "kpi" | "grafico_barra" | "grafico_pie" | "texto",
  "explicacion": "texto breve en español describiendo el resultado"
}

Reglas ESTRICTAS:
0. PRIORIDAD MÁXIMA — Agrupaciones:
   - Si el usuario incluye "por [campo]" (ej: "por rubro", "por marca", "por familia", "por fabricante", "por modelo", "por unidad") o palabras como "distribución", "distribucion", "comparativa", "ranking", "top", "top 5", "top 10", DEBES generar obligatoriamente una consulta con GROUP BY sobre esa columna, con "tipoVisual": "grafico_barra" o "grafico_pie", y LIMIT 5 (o el N indicado), ordenada DESCENDENTE por la métrica solicitada.
   - Ejemplo para "valorización por rubro":
     SELECT "RUBRO", ROUND(SUM(CASE WHEN "STOCK_TOTAL" > 0 THEN "STOCK_TOTAL" * COALESCE("COSTO_PROM", 0) ELSE 0 END), 0) AS "VALORIZACION"
     FROM "TRACTOAGRO"."V_PRODUCTOS"
     GROUP BY "RUBRO"
     ORDER BY "VALORIZACION" DESC
     LIMIT 5
   - Ejemplo para "stock por marca":
     SELECT "MARCA", COALESCE(SUM("STOCK_TOTAL"), 0) AS "STOCK"
     FROM "TRACTOAGRO"."V_PRODUCTOS"
     GROUP BY "MARCA"
     ORDER BY "STOCK" DESC
     LIMIT 5
   - Esta regla tiene prioridad sobre cualquier otra y NUNCA debe devolverse como "kpi" de una sola fila cuando el usuario pidió agrupación.

1. En modo "lista", "whereClause" NO debe incluir la palabra WHERE, ni SELECT, ni ORDER BY, ni LIMIT, ni punto y coma. Si no hay filtros, usa "1=1".
2. En modo "resumen", "sql" debe ser una sentencia SELECT completa y válida en SAP HANA sobre "TRACTOAGRO"."V_PRODUCTOS". Puede incluir GROUP BY, ORDER BY, agregaciones (SUM, COUNT, AVG, MIN, MAX) y LIMIT. NO incluyas punto y coma final.
3. Usa comillas dobles para identificadores y comillas simples para strings. Escapa comillas simples internas duplicándolas ('').
4. Para fechas usa TO_DATE('YYYY-MM-DD','YYYY-MM-DD').
5. NUNCA uses DROP, INSERT, UPDATE, DELETE, ALTER, CREATE, TRUNCATE, MERGE, GRANT, REVOKE, CALL, EXEC, ATTACH, DETACH, RENAME ni punto y coma.
6. Elige "tipoVisual" con precisión:
   - "kpi": para totales o métricas globales en una sola fila (ej: "resumen de inventario", "valorización total", "cuántos artículos con stock"). Devuelve una fila con una o varias métricas agregadas.
   - "grafico_barra": para agrupaciones y rankings comparables (ej: "por rubro", "por marca", "top 5 familias", "ranking de artículos más vendidos").
   - "grafico_pie": para distribuciones porcentuales o de participación (ej: "participación por rubro", "distribución por familia").
   - "texto": para resultados que no son numéricos o no aplican gráfico.
   - NUNCA uses "lista" como tipoVisual en modo "resumen". El modo "lista" se usa ÚNICAMENTE cuando el usuario pide listar, buscar o filtrar artículos específicos (ej: "muéstrame los tractores Lovol", "artículos con stock > 2", "repuestos de filtro").
7. Interpreta jerga de inventario:
   - "quiebre", "faltantes", "ruptura de stock" => STOCK_TOTAL <= 0
   - "agotados", "sin stock", "sin existencia" => STOCK_TOTAL <= 0
   - "con stock", "disponibles", "con existencia" => STOCK_TOTAL > 0
   - "por recibir", "en camino", "pedidos pendientes" => EN_PEDIDO > 0
   - "comprometidos", "reservados" => COMPROMETIDO > 0

8. Resúmenes de inventario (modo "resumen"):
   - Si el usuario pide "resumen de inventario", "estado general", "reporte de stock", "panorama de inventario" o similar, genera EXACTAMENTE esta consulta SQL que devuelva métricas consolidadas en una sola fila:
     SELECT
       COUNT(CASE WHEN "STOCK_TOTAL" > 0 THEN 1 END) AS "ITEMS_CON_STOCK",
       COALESCE(SUM("STOCK_TOTAL"), 0) AS "TOTAL_STOCK",
       COALESCE(SUM("COMPROMETIDO"), 0) AS "TOTAL_COMPROMETIDO",
       COALESCE(SUM("EN_PEDIDO"), 0) AS "TOTAL_EN_PEDIDO",
       ROUND(SUM(CASE WHEN "STOCK_TOTAL" > 0 THEN "STOCK_TOTAL" * COALESCE("COSTO_PROM", 0) ELSE 0 END), 0) AS "VALOR_INVENTARIO"
     FROM "TRACTOAGRO"."V_PRODUCTOS"
     Usa "tipoVisual": "kpi".
   - PROHIBIDO en métricas de inventario: NO incluyas condiciones WHERE que filtren campos de texto como "ACTIVO" = 'TRUE', "ACTIVO" = 'Y', "ACTIVO" = 'SI' ni similares. Las métricas deben calcularse sobre el universo visible completo de la vista.
   - Usa siempre COALESCE(SUM(...), 0) para evitar NULLs y ROUND(..., 0) para la valorización.
   - Si el usuario pide "valorización por rubro", "valor de inventario por rubro", "top rubros por valor" o similar, genera:
     SELECT "RUBRO", SUM("STOCK_TOTAL" * "COSTO_PROM") AS "VALORIZACION"
     FROM "TRACTOAGRO"."V_PRODUCTOS"
     WHERE "ACTIVO" = 'Y'
       AND "COSTO_PROM" IS NOT NULL
       AND "COSTO_PROM" > 0
       AND "STOCK_TOTAL" > 0
     GROUP BY "RUBRO"
     ORDER BY "VALORIZACION" DESC
     LIMIT 5
     Usa "tipoVisual": "grafico_barra".

9. Valorización monetaria:
   - Siempre calcula la valorización como SUM("STOCK_TOTAL" * "COSTO_PROM").
   - Excluye registros con "COSTO_PROM" IS NULL o "COSTO_PROM" <= 0.
   - Si el usuario pide valorización total, usa:
     SELECT SUM("STOCK_TOTAL" * "COSTO_PROM") AS "VALORIZACION_TOTAL"
     FROM "TRACTOAGRO"."V_PRODUCTOS"
     WHERE "ACTIVO" = 'Y'
       AND "COSTO_PROM" IS NOT NULL
       AND "COSTO_PROM" > 0
       AND "STOCK_TOTAL" > 0
     Usa "tipoVisual": "kpi".

10. Explicación ejecutiva:
   - En modo "resumen", "explicacion" debe ser un ENCABEZADO DESCRIPTIVO del análisis, NO un resumen con cifras.
   - PROHIBIDO inventar cifras, totales, porcentajes o valores numéricos en "explicacion" antes de ejecutar el SQL. La IA no conoce los resultados reales.
   - Ejemplos válidos: "Resumen consolidado de inventario", "Distribución de valorización por rubro", "Ranking de stock por marca", "Comparativa de comprometido por familia".
   - Cuando la consulta sea sobre ventas, facturación, rotación o devoluciones (usando "V_VENTAS_ARTICULOS_ANALITICA"), la "explicacion" DEBE indicar claramente que los montos representan VENTAS NETAS ya descontadas las notas de crédito. Ejemplos válidos: "Ventas netas por rubro (notas de crédito ya descontadas)", "Ranking de artículos más vendidos — ventas netas", "Facturación neta mensual (incluye facturas de reserva, notas de crédito descontadas)".
   - No incluyas markdown ni saltos de línea en "explicacion".

11. Devuelve SOLO el objeto JSON, sin explicaciones adicionales ni bloques de código.`;

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
    "Fecha": { "year": number, "month": number, "date": "YYYY-MM-DD" },
    "Codigo": { "op": "contains" | "startswith" | "eq", "val": string },
    "Descripcion": { "op": "contains" | "startswith" | "eq", "val": string },
    "NombreInterno": { "op": "contains" | "startswith" | "eq", "val": string },
    "Familia": { "op": "contains" | "startswith" | "eq", "val": string },
    "Rubro": { "op": "contains" | "startswith" | "eq", "val": string },
    "Fabricante": { "op": "contains" | "startswith" | "eq", "val": string },
    "Marca": { "op": "contains" | "startswith" | "eq", "val": string }
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
  * Columnas de texto ("Codigo", "Descripcion", "NombreInterno", "Familia", "Rubro", "Fabricante", "Marca"): usan "op" ("contains" | "startswith" | "eq") y "val" (string).
    - Usa "contains" cuando el usuario diga "contiene", "que incluya", "con la palabra", o simplemente mencione un fragmento (ej: "código que contenga 123" => { "op": "contains", "val": "123" }).
    - Usa "startswith" cuando diga "empieza con", "comienza con", "inicia con".
    - Usa "eq" cuando diga "es igual a", "exactamente", "código X" (valor exacto).
    - Distribuye las intenciones de texto del usuario en la propiedad más adecuada:
      * Código de artículo => "Codigo".
      * Descripción/nombre del artículo => "Descripcion".
      * Nombre interno / nombre extranjero => "NombreInterno".
      * Familia / subfamilia / SWW => "Familia".
      * Rubro / grupo de artículos => "Rubro".
      * Fabricante => "Fabricante".
      * Marca => "Marca".
    - Si el usuario menciona un texto genérico sin indicar columna, colócalo en "search" y NO en colFilters.

Reglas semánticas de inventario (jerga de negocio):
- "quiebre de stock", "quiebre", "ruptura de stock", "faltantes", "faltante":
  * NO busques la palabra "quiebre" ni "faltante" en "search".
  * Asigna "colFilters.Stock" = { "op": "le", "val": 0 }.
  * Si además el usuario menciona pedidos, comprometidos o "por entregar", agrega "colFilters.Comprometido" = { "op": "gt", "val": 0 }.
  * Si el usuario no menciona pedidos, puedes usar "stockEstado" = "sinStock" como alternativa equivalente.
- "agotados", "sin existencia", "sin stock", "no hay", "cero stock":
  * Asigna "stockEstado" = "sinStock".
  * NO coloques estas palabras en "search".
- "con existencia", "disponibles", "en stock", "hay stock", "con stock":
  * Asigna "stockEstado" = "conStock".
  * NO coloques estas palabras en "search".
- "por recibir", "en camino", "en tránsito", "pedidos pendientes", "por llegar":
  * Asigna "stockEstado" = "conPedido".
  * NO coloques estas palabras en "search".
- "comprometidos", "reservados", "vendidos pendientes":
  * Asigna "stockEstado" = "conComprometido".
  * NO coloques estas palabras en "search".

Reglas de limpieza de "search":
- En "search" SOLO deben ir nombres o códigos reales de artículos (ej: "Lovol", "filtro aceite", "12345").
- NUNCA incluyas en "search" palabras genéricas o de relleno como: "productos", "producto", "artículos", "articulos", "repuestos", "repuesto", "muéstrame", "muestrame", "mostrar", "listar", "lista", "dame", "quiero", "ver", "buscar", "busca", "quiebre", "faltante", "faltantes", "agotados", "disponibles", "existencia", "stock", "pedido", "pedidos", "comprometido", "comprometidos", "en camino", "por recibir".
- Si después de limpiar no queda ningún término real de artículo, deja "search" como cadena vacía "".

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

  const validTextOps = new Set(['contains', 'startswith', 'eq']);
  const textCols = [
    'Codigo',
    'Descripcion',
    'NombreInterno',
    'Familia',
    'Rubro',
    'Fabricante',
    'Marca',
  ];
  for (const key of textCols) {
    const spec = cf[key];
    if (spec && typeof spec === 'object') {
      const op = String(spec.op || 'contains').toLowerCase();
      const val = spec.val !== undefined && spec.val !== null ? String(spec.val) : '';
      if (validTextOps.has(op) && val.trim() !== '') {
        out.colFilters[key] = { op, val };
      }
    }
  }

  return out;
}

const FORBIDDEN_SQL_WORDS = [
  'DROP',
  'INSERT',
  'UPDATE',
  'DELETE',
  'ALTER',
  'CREATE',
  'TRUNCATE',
  'MERGE',
  'GRANT',
  'REVOKE',
  'CALL',
  'EXEC',
  'EXECUTE',
  'ATTACH',
  'DETACH',
  'RENAME',
];

function isSafeWhereClause(clause) {
  if (typeof clause !== 'string') return false;
  const trimmed = clause.trim();
  if (!trimmed) return false;
  if (trimmed.includes(';')) return false;
  if (/--|\/\*/.test(trimmed)) return false;
  const upper = trimmed.toUpperCase();
  for (const word of FORBIDDEN_SQL_WORDS) {
    const re = new RegExp(`\\b${word}\\b`);
    if (re.test(upper)) return false;
  }
  return true;
}

function isSafeSelectSql(sql) {
  if (typeof sql !== 'string') return false;
  const trimmed = sql.trim();
  if (!trimmed) return false;
  if (trimmed.includes(';')) return false;
  if (/--|\/\*/.test(trimmed)) return false;
  const upper = trimmed.toUpperCase();
  if (!/^SELECT\b/.test(upper)) return false;
  for (const word of FORBIDDEN_SQL_WORDS) {
    const re = new RegExp(`\\b${word}\\b`);
    if (re.test(upper)) return false;
  }
  return true;
}

app.post('/api/articulos/ia-prompt', requireAuth, requireIA, async (req, res) => {
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

  const page = parsePositiveInt(req.body && req.body.page, 1);
  const limit = parsePositiveInt(req.body && req.body.limit, 20, 200);
  const offset = (page - 1) * limit;

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
        messages: [
          { role: 'system', content: IA_SQL_SYSTEM_PROMPT },
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

    const usage = (data && data.usage) || {};
    const promptTokens = Number(usage.prompt_tokens) || 0;
    const completionTokens = Number(usage.completion_tokens) || 0;
    const totalTokens = Number(usage.total_tokens) || 0;
    console.log(
      `[DEEPSEEK USAGE] Tokens usados: ${totalTokens} (Prompt: ${promptTokens}, Resp: ${completionTokens})`
    );

    if (!content) {
      return res
        .status(502)
        .json({ error: { message: 'Respuesta vacía del servicio de IA' } });
    }

    // Limpiar posibles bloques de código o prefijos
    let cleaned = String(content).trim();
    cleaned = cleaned.replace(/^```[a-zA-Z]*\s*/i, '').replace(/```$/i, '').trim();

    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (_) {
      return res.status(502).json({
        error: { message: 'La IA no devolvió un JSON válido' },
      });
    }

    const modo = parsed && parsed.modo === 'resumen' ? 'resumen' : 'lista';
    const explicacion =
      parsed && typeof parsed.explicacion === 'string'
        ? parsed.explicacion.trim()
        : '';

    const usageOut = {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: totalTokens,
    };

    if (modo === 'lista') {
      let whereClause = parsed && typeof parsed.whereClause === 'string'
        ? parsed.whereClause.trim()
        : '';
      whereClause = whereClause.replace(/^WHERE\s+/i, '').trim();

      if (!isSafeWhereClause(whereClause)) {
        return res.status(400).json({
          error: {
            message: 'La cláusula generada por la IA no es segura o no es válida',
          },
        });
      }

      const baseSelect = `SELECT "ACTIVO","CODIGO_TRACTO","NOMBRE","NOMBRE_INTERNO","CODIGO_FABRICA","RUBRO","MARCA","MODELO","FABRICANTE","FAMILIA","UNIDAD","STOCK_TOTAL","COMPROMETIDO","EN_PEDIDO","DISPONIBLE","FECHA_CREACION","FECHA_ULT_VENTA","PRECIO_ULT_COMPRA","MONEDA_ULT_COMPRA","FECHA_ULT_COMPRA","FECHA_ULT_ACT","COSTO_PROM" FROM "TRACTOAGRO"."V_PRODUCTOS" WHERE `;

      const countSql = `SELECT COUNT(*) AS "TOTAL" FROM "TRACTOAGRO"."V_PRODUCTOS" WHERE ${whereClause}`;
      const dataSql = `${baseSelect}${whereClause} ORDER BY "CODIGO_TRACTO" LIMIT ${limit} OFFSET ${offset}`;

      console.log('[IA SQL GENERADO]', whereClause);

      const [countRows, dataRows] = await Promise.all([
        hanaExec(countSql),
        hanaExec(dataSql),
      ]);

      console.log('[IA HANA RESULT]', dataRows);

      const total = countRows && countRows[0] ? Number(countRows[0].TOTAL) || 0 : 0;
      const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;

      return res.json({
        modo: 'lista',
        explicacion,
        data: dataRows || [],
        total,
        page,
        limit,
        totalPages,
        whereClause,
        usage: usageOut,
      });
    }

    // modo === 'resumen'
    const sql = parsed && typeof parsed.sql === 'string' ? parsed.sql.trim() : '';
    if (!isSafeSelectSql(sql)) {
      return res.status(400).json({
        error: {
          message: 'La sentencia SQL generada por la IA no es segura o no es válida',
        },
      });
    }

    const validVisual = new Set(['kpi', 'grafico_barra', 'grafico_pie', 'texto']);
    const tipoVisual =
      parsed && validVisual.has(parsed.tipoVisual) ? parsed.tipoVisual : 'texto';

    console.log('[IA SQL GENERADO]', sql);

    const rows = await hanaExec(sql);

    console.log('[IA HANA RESULT]', rows);

    return res.json({
      modo: 'resumen',
      explicacion,
      tipoVisual,
      data: rows || [],
      usage: usageOut,
    });
  } catch (err) {
    console.error('Error en /api/articulos/ia-prompt:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al procesar la consulta de IA' } });
  }
});

app.post('/api/articulos/ia-pagina', requireAuth, requireIA, async (req, res) => {
  const body = req.body || {};
  const whereClauseRaw = typeof body.whereClause === 'string' ? body.whereClause.trim() : '';
  const whereClause = whereClauseRaw.replace(/^WHERE\s+/i, '').trim();

  if (!isSafeWhereClause(whereClause)) {
    return res.status(400).json({
      error: { message: 'La cláusula de filtro no es segura o no es válida' },
    });
  }

  const page = parsePositiveInt(body.page, 1);
  const limit = parsePositiveInt(body.limit, 20, 200);
  const offset = (page - 1) * limit;

  const baseSelect = `SELECT "ACTIVO","CODIGO_TRACTO","NOMBRE","NOMBRE_INTERNO","CODIGO_FABRICA","RUBRO","MARCA","MODELO","FABRICANTE","FAMILIA","UNIDAD","STOCK_TOTAL","COMPROMETIDO","EN_PEDIDO","DISPONIBLE","FECHA_CREACION","FECHA_ULT_VENTA","PRECIO_ULT_COMPRA","MONEDA_ULT_COMPRA","FECHA_ULT_COMPRA","FECHA_ULT_ACT","COSTO_PROM" FROM "TRACTOAGRO"."V_PRODUCTOS" WHERE `;

  const countSql = `SELECT COUNT(*) AS "TOTAL" FROM "TRACTOAGRO"."V_PRODUCTOS" WHERE ${whereClause}`;
  const dataSql = `${baseSelect}${whereClause} ORDER BY "CODIGO_TRACTO" LIMIT ${limit} OFFSET ${offset}`;

  try {
    console.log('[IA PAGINA SQL]', dataSql);
    const [countRows, dataRows] = await Promise.all([
      hanaExec(countSql),
      hanaExec(dataSql),
    ]);
    const total = countRows && countRows[0] ? Number(countRows[0].TOTAL) || 0 : 0;
    const totalPages = limit > 0 ? Math.ceil(total / limit) : 0;

    return res.json({
      modo: 'lista',
      data: dataRows || [],
      total,
      page,
      limit,
      totalPages,
      whereClause,
    });
  } catch (err) {
    console.error('Error en /api/articulos/ia-pagina:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al paginar resultados de IA en HANA' } });
  }
});

app.get('/api/vendedores', requireAuth, async (req, res) => {
  const sql = `SELECT "SlpCode" AS "slpCode", "SlpName" AS "slpName" FROM "TRACTOAGRO".OSLP WHERE "Active" = 'Y' ORDER BY "SlpName" ASC`;
  try {
    const rows = await hanaExec(sql);
    const data = (rows || [])
      .map((r) => ({
        slpCode: r.slpCode !== undefined && r.slpCode !== null ? Number(r.slpCode) : null,
        slpName: r.slpName !== undefined && r.slpName !== null ? String(r.slpName) : '',
      }))
      .filter((v) => v.slpCode !== null);
    return res.json({ data });
  } catch (err) {
    console.error('Error en /api/vendedores:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar vendedores en HANA' } });
  }
});

app.post('/api/cotizaciones', requireAuth, async (req, res) => {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: { message: 'No autenticado' } });
  }

  const body = req.body || {};
  const cardCode = String(body.cardCode || '').trim();
  const comments = String(body.comments || '').trim();
  const lines = Array.isArray(body.lines) ? body.lines : [];
  const uSucursal = String(body.U_Sucursal || body.uSucursal || '').trim();
  const uTipoOfer = String(body.U_TipoOfer || body.uTipoOfer || '2').trim() || '2';

  if (!uSucursal) {
    return res
      .status(400)
      .json({ error: { message: 'Debe seleccionar una sucursal (U_Sucursal)' } });
  }

  // SalesPersonCode: siempre desde la sesión (vendedor vinculado al usuario AD)
  let salesPersonCode = null;
  if (user.slpCode !== undefined && user.slpCode !== null) {
    salesPersonCode = Number(user.slpCode);
  }
  if (salesPersonCode === null) {
    salesPersonCode = getDefaultVendedor().slpCode;
  }

  if (!cardCode) {
    return res
      .status(400)
      .json({ error: { message: 'Debe seleccionar un cliente (CardCode)' } });
  }
  if (!lines.length) {
    return res
      .status(400)
      .json({ error: { message: 'Debe agregar al menos un ítem a la cotización' } });
  }

  const documentLines = [];
  for (const l of lines) {
    const itemCode = String(l.itemCode || '').trim();
    const quantity = Number(l.quantity);
    if (!itemCode) {
      return res
        .status(400)
        .json({ error: { message: 'Cada línea debe tener ItemCode' } });
    }
    if (!Number.isFinite(quantity) || quantity <= 0) {
      return res.status(400).json({
        error: { message: `Cantidad inválida para el ítem ${itemCode}` },
      });
    }
    const line = { ItemCode: itemCode, Quantity: quantity };
    if (l.warehouseCode) line.WarehouseCode = String(l.warehouseCode);
    // Precio con IVA (PriceAfterVAT) y UnitPrice: solo si vienen con valor
    if (l.priceAfterVAT !== undefined && l.priceAfterVAT !== null && l.priceAfterVAT !== '') {
      const pav = Number(l.priceAfterVAT);
      if (Number.isFinite(pav) && pav >= 0) {
        line.PriceAfterVAT = pav;
      }
    }
    if (l.unitPrice !== undefined && l.unitPrice !== null && l.unitPrice !== '') {
      const unitPrice = Number(l.unitPrice);
      if (Number.isFinite(unitPrice) && unitPrice >= 0) {
        line.UnitPrice = unitPrice;
      }
    }
    // DiscountPercent: solo si viene con valor
    if (l.discountPercent !== undefined && l.discountPercent !== null && l.discountPercent !== '') {
      const disc = Number(l.discountPercent);
      if (Number.isFinite(disc) && disc >= 0 && disc <= 100) {
        line.DiscountPercent = disc;
      }
    }
    documentLines.push(line);
  }

  const payload = {
    CardCode: cardCode,
    SalesPersonCode: Number(salesPersonCode),
    U_Sucursal: uSucursal,
    U_TipoOfer: uTipoOfer,
    DocumentLines: documentLines,
  };
  // DocumentsOwner: siempre desde la sesión (empleado vinculado al usuario AD)
  if (user.empId !== null && user.empId !== undefined) {
    payload.DocumentsOwner = Number(user.empId);
  }
  if (comments) payload.Comments = comments;

  try {
    await ensureSession();

    const response = await sapClient.post('/b1s/v1/Quotations', payload, {
      headers: { Cookie: buildCookieHeader() },
    });

    const doc = response.data || {};
    return res.json({
      ok: true,
      docEntry: doc.DocEntry,
      docNum: doc.DocNum,
      cardCode: doc.CardCode,
      salesPersonCode: doc.SalesPersonCode,
    });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.post('/b1s/v1/Quotations', payload, {
          headers: { Cookie: buildCookieHeader() },
        });
        const doc = retry.data || {};
        return res.json({
          ok: true,
          docEntry: doc.DocEntry,
          docNum: doc.DocNum,
          cardCode: doc.CardCode,
          salesPersonCode: doc.SalesPersonCode,
        });
      } catch (retryError) {
        return handleCotizacionError(res, retryError);
      }
    }
    return handleCotizacionError(res, error);
  }
});

function handleCotizacionError(res, error) {
  const status = error.response ? error.response.status : 500;
  const data = error.response ? error.response.data : { message: error.message };
  console.error('Error creando cotización en SAP B1:', status, data);
  let message = 'No se pudo crear la oferta de ventas en SAP B1';
  if (data && data.error && data.error.message && data.error.message.value) {
    message = data.error.message.value;
  } else if (data && data.message) {
    message = data.message;
  }
  return res.status(status >= 400 && status < 600 ? status : 500).json({
    error: { message },
  });
}

app.get('/api/clientes/:cardCode', requireAuth, async (req, res) => {
  const cardCode = String(req.params.cardCode || '').trim();
  if (!cardCode) {
    return res
      .status(400)
      .json({ error: { message: 'El código de cliente es obligatorio' } });
  }

  const sql = `SELECT "CardCode", "CardName", "ListNum", COALESCE("Discount", 0) AS "Discount" FROM "TRACTOAGRO".OCRD WHERE "CardCode" = ?`;

  try {
    const rows = await hanaExec(sql, [cardCode]);
    if (!rows || !rows.length) {
      return res
        .status(404)
        .json({ error: { message: 'Cliente no encontrado' } });
    }
    const r = rows[0];
    return res.json({
      CardCode: r.CardCode !== undefined && r.CardCode !== null ? String(r.CardCode) : cardCode,
      CardName: r.CardName !== undefined && r.CardName !== null ? String(r.CardName) : '',
      ListNum: r.ListNum !== undefined && r.ListNum !== null ? Number(r.ListNum) : null,
      Discount: r.Discount !== undefined && r.Discount !== null ? Number(r.Discount) : 0,
    });
  } catch (err) {
    console.error('Error en /api/clientes/:cardCode:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar cliente en HANA' } });
  }
});

// Fallback: consulta precios directamente en HANA (ITM1) para una lista de precios
async function preciosDesdeHana(listNum, itemCodes) {
  const result = {};
  if (!Number.isFinite(Number(listNum)) || !Array.isArray(itemCodes) || !itemCodes.length) {
    return result;
  }
  const placeholders = itemCodes.map(() => '?').join(', ');
  const sql = `SELECT "ItemCode", COALESCE(NULLIF("Price", 0), 0) AS "precio", "Currency" AS "moneda" FROM "TRACTOAGRO".ITM1 WHERE "PriceList" = ? AND "ItemCode" IN (${placeholders})`;
  try {
    const params = [Number(listNum), ...itemCodes];
    const rows = await hanaExec(sql, params);
    for (const r of rows || []) {
      const code = r.ItemCode !== undefined && r.ItemCode !== null ? String(r.ItemCode) : '';
      if (!code) continue;
      result[code] = {
        precio: r.precio !== undefined && r.precio !== null ? Number(r.precio) : 0,
        moneda: r.moneda !== undefined && r.moneda !== null ? String(r.moneda) : '',
      };
    }
  } catch (err) {
    console.warn('Fallback HANA ITM1 falló:', err.message);
  }
  return result;
}

// Obtiene el ListNum del cliente desde OCRD (HANA)
async function obtenerListNumCliente(cardCode) {
  try {
    const rows = await hanaExec(
      `SELECT "ListNum" FROM "TRACTOAGRO".OCRD WHERE "CardCode" = ?`,
      [cardCode]
    );
    if (rows && rows.length && rows[0].ListNum !== undefined && rows[0].ListNum !== null) {
      return Number(rows[0].ListNum);
    }
  } catch (err) {
    console.warn('No se pudo obtener ListNum del cliente:', err.message);
  }
  return null;
}

// Fallback directo: precios desde ITM1 uniendo con OCRD por ListNum del cliente
async function preciosDesdeHanaPorCliente(cardCode, itemCodes) {
  const result = {};
  if (!cardCode || !Array.isArray(itemCodes) || !itemCodes.length) return result;
  const placeholders = itemCodes.map(() => '?').join(', ');
  const sql = `SELECT T0."ItemCode", COALESCE(NULLIF(T0."Price", 0), 0) AS "precio", T0."Currency" AS "moneda" FROM "TRACTOAGRO".ITM1 T0 INNER JOIN "TRACTOAGRO".OCRD T1 ON T1."ListNum" = T0."PriceList" WHERE T1."CardCode" = ? AND T0."ItemCode" IN (${placeholders})`;
  try {
    const params = [cardCode, ...itemCodes];
    const rows = await hanaExec(sql, params);
    for (const r of rows || []) {
      const code = r.ItemCode !== undefined && r.ItemCode !== null ? String(r.ItemCode) : '';
      if (!code) continue;
      result[code] = {
        precio: r.precio !== undefined && r.precio !== null ? Number(r.precio) : 0,
        moneda: r.moneda !== undefined && r.moneda !== null ? String(r.moneda) : '',
      };
    }
  } catch (err) {
    console.warn('Fallback HANA (ITM1+OCRD) falló:', err.message);
  }
  return result;
}

app.post('/api/articulos/precios-service-layer', requireAuth, async (req, res) => {
  const body = req.body || {};
  const cardCode = String(body.cardCode || '').trim();
  const itemCodes = Array.isArray(body.itemCodes)
    ? body.itemCodes.map((c) => String(c || '').trim()).filter((c) => c !== '')
    : [];

  console.log('Consultando precios para:', cardCode, itemCodes);

  if (!cardCode) {
    return res
      .status(400)
      .json({ error: { message: 'El parámetro cardCode es obligatorio' } });
  }
  if (!itemCodes.length) {
    return res.json({});
  }

  try {
    // 1) Prioridad: consulta directa a HANA (ITM1 INNER JOIN OCRD por CardCode)
    const result = {};
    const directo = await preciosDesdeHanaPorCliente(cardCode, itemCodes);
    for (const code of itemCodes) {
      const r = directo[code];
      if (r && Number.isFinite(Number(r.precio)) && Number(r.precio) > 0) {
        result[code] = {
          precio: Number(r.precio),
          descuento: 0,
          moneda: r.moneda || '',
        };
      }
    }

    // 2) Fallback por ListNum para los que aún no tienen precio
    const faltantes = itemCodes.filter((code) => {
      const r = result[code];
      return !r || !Number.isFinite(Number(r.precio)) || Number(r.precio) <= 0;
    });
    if (faltantes.length) {
      console.log('Fallback HANA por ListNum para:', faltantes);
      const listNum = await obtenerListNumCliente(cardCode);
      if (Number.isFinite(Number(listNum))) {
        const fallback = await preciosDesdeHana(listNum, faltantes);
        for (const code of faltantes) {
          const fb = fallback[code];
          if (fb && Number.isFinite(Number(fb.precio)) && Number(fb.precio) > 0) {
            result[code] = {
              precio: Number(fb.precio),
              descuento: 0,
              moneda: fb.moneda || '',
            };
          }
        }
      }
    }

    // 3) Si aún quedan sin precio, intentar Service Layer (ItemPriceService_GetItemPrice)
    const aunFaltantes = itemCodes.filter((code) => {
      const r = result[code];
      return !r || !Number.isFinite(Number(r.precio)) || Number(r.precio) <= 0;
    });
    if (aunFaltantes.length) {
      try {
        await ensureSession();
        const today = new Date().toISOString().split('T')[0];
        const CONCURRENCY = 8;
        for (let i = 0; i < aunFaltantes.length; i += CONCURRENCY) {
          const batch = aunFaltantes.slice(i, i + CONCURRENCY);
          const responses = await Promise.all(
            batch.map(async (itemCode) => {
              try {
                const resp = await sapClient.post(
                  '/b1s/v1/ItemPriceService_GetItemPrice',
                  {
                    ItemPriceParams: {
                      CardCode: cardCode,
                      ItemCode: itemCode,
                      Date: today,
                    },
                  },
                  { headers: { Cookie: buildCookieHeader() } }
                );
                return { itemCode, data: resp.data || {} };
              } catch (err) {
                console.warn(
                  `Service Layer sin precio para ${itemCode}:`,
                  err.response ? err.response.status : err.message
                );
                return { itemCode, data: null };
              }
            })
          );
          for (const { itemCode, data } of responses) {
            if (!data) continue;
            const price = Number(data.Price) || 0;
            const discount = Number(data.Discount) || 0;
            const currency = data.Currency || '';
            if (price > 0) {
              result[itemCode] = {
                precio: price,
                descuento: Number.isFinite(discount) ? discount : 0,
                moneda: currency,
              };
            }
          }
        }
      } catch (slErr) {
        console.warn('Service Layer falló, se mantiene el resultado de HANA:', slErr.message);
      }
    }

    console.log('Precios devueltos:', result);
    return res.json(result);
  } catch (error) {
    console.error('Error en /api/articulos/precios-service-layer:', error.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar precios' } });
  }
});

app.post('/api/articulos/precios-cliente', requireAuth, async (req, res) => {
  const body = req.body || {};
  const listNum = parseInt(body.listNum, 10);
  const itemCodes = Array.isArray(body.itemCodes)
    ? body.itemCodes.map((c) => String(c || '').trim()).filter((c) => c !== '')
    : [];

  if (!Number.isFinite(listNum)) {
    return res
      .status(400)
      .json({ error: { message: 'El parámetro listNum es obligatorio y numérico' } });
  }
  if (!itemCodes.length) {
    return res.json({});
  }

  const placeholders = itemCodes.map(() => '?').join(', ');
  const sql = `SELECT T0."ItemCode", COALESCE(NULLIF(T0."Price", 0), 0) AS "precioConIva", T0."Currency" AS "moneda" FROM "TRACTOAGRO".ITM1 T0 WHERE T0."PriceList" = ? AND T0."ItemCode" IN (${placeholders})`;

  try {
    const params = [listNum, ...itemCodes];
    const rows = await hanaExec(sql, params);
    const result = {};
    for (const r of rows || []) {
      const code = r.ItemCode !== undefined && r.ItemCode !== null ? String(r.ItemCode) : '';
      if (!code) continue;
      result[code] = {
        precio: r.precioConIva !== undefined && r.precioConIva !== null ? Number(r.precioConIva) : 0,
        moneda: r.moneda !== undefined && r.moneda !== null ? String(r.moneda) : '',
      };
    }
    return res.json(result);
  } catch (err) {
    console.error('Error en /api/articulos/precios-cliente:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar precios en HANA' } });
  }
});

app.get('/api/clientes/:cardCode/condiciones', requireAuth, async (req, res) => {
  const cardCode = String(req.params.cardCode || '').trim();
  if (!cardCode) {
    return res
      .status(400)
      .json({ error: { message: 'El código de cliente es obligatorio' } });
  }

  const safe = escapeODataString(cardCode);
  const query = `/b1s/v1/BusinessPartners('${safe}')?$select=CardCode,CardName,PriceListNum,Discount,Currency`;

  try {
    await ensureSession();
    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });
    const bp = response.data || {};
    return res.json({
      CardCode: bp.CardCode || cardCode,
      CardName: bp.CardName || '',
      ListNum: bp.PriceListNum !== undefined && bp.PriceListNum !== null ? Number(bp.PriceListNum) : null,
      Discount: bp.Discount !== undefined && bp.Discount !== null ? Number(bp.Discount) : 0,
      Currency: bp.Currency || '',
    });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        const bp = retry.data || {};
        return res.json({
          CardCode: bp.CardCode || cardCode,
          CardName: bp.CardName || '',
          ListNum: bp.PriceListNum !== undefined && bp.PriceListNum !== null ? Number(bp.PriceListNum) : null,
          Discount: bp.Discount !== undefined && bp.Discount !== null ? Number(bp.Discount) : 0,
          Currency: bp.Currency || '',
        });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

app.get('/api/articulos/:itemCode/precio', requireAuth, async (req, res) => {
  const itemCode = String(req.params.itemCode || '').trim();
  const listNumRaw = req.query.listNum;
  const listNum = parseInt(listNumRaw, 10);

  if (!itemCode) {
    return res
      .status(400)
      .json({ error: { message: 'El código de artículo es obligatorio' } });
  }
  if (!Number.isFinite(listNum)) {
    return res
      .status(400)
      .json({ error: { message: 'El parámetro listNum es obligatorio y numérico' } });
  }

  const sql = `SELECT COALESCE(NULLIF(T0."Price", 0), 0) AS "precioConIva", T0."Price" AS "precioNeto", T0."Currency" AS "moneda" FROM "TRACTOAGRO".ITM1 T0 WHERE T0."ItemCode" = ? AND T0."PriceList" = ?`;

  try {
    const rows = await hanaExec(sql, [itemCode, listNum]);
    if (!rows || !rows.length) {
      return res.json({
        ItemCode: itemCode,
        PriceList: listNum,
        precioConIva: 0,
        precioNeto: 0,
        moneda: '',
        // Compatibilidad con el frontend anterior
        Price: 0,
        Currency: '',
      });
    }
    const r = rows[0];
    const precioConIva =
      r.precioConIva !== undefined && r.precioConIva !== null ? Number(r.precioConIva) : 0;
    const precioNeto =
      r.precioNeto !== undefined && r.precioNeto !== null ? Number(r.precioNeto) : 0;
    const moneda = r.moneda !== undefined && r.moneda !== null ? String(r.moneda) : '';
    return res.json({
      ItemCode: itemCode,
      PriceList: listNum,
      precioConIva,
      precioNeto,
      moneda,
      // Compatibilidad con el frontend anterior
      Price: precioConIva,
      Currency: moneda,
    });
  } catch (err) {
    console.error('Error en /api/articulos/:itemCode/precio:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar precio en HANA' } });
  }
});

app.get('/api/articulos/:codigo/detalle', requireAuth, async (req, res) => {
  const codigo = String(req.params.codigo || '').trim();
  if (!codigo) {
    return res
      .status(400)
      .json({ error: { message: 'El código es obligatorio' } });
  }

  const safe = escapeODataString(codigo);
  const query = `/b1s/v1/Items('${safe}')?$select=ItemCode,ItemName,ForeignName,SWW,QuantityOnStock,QuantityOrderedByCustomers,QuantityOrderedFromVendors,ItemWarehouseInfoCollection,ItemPrices`;

  try {
    await ensureSession();

    const [warehouses, priceLists] = await Promise.all([
      loadWarehouses().catch(() => new Map()),
      loadPriceLists().catch(() => new Map()),
    ]);

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

    const item = response.data || {};
    const whMap = warehouses instanceof Map ? warehouses : new Map();
    const priceMap = priceLists instanceof Map ? priceLists : new Map();

    const whs = Array.isArray(item.ItemWarehouseInfoCollection)
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

    return res.json({
      ItemCode: item.ItemCode || codigo,
      ItemName: item.ItemName || '',
      FrgnName: item.ForeignName || '',
      SWW: item.SWW || '',
      QuantityOnStock: Number(item.QuantityOnStock) || 0,
      IsCommited: Number(item.QuantityOrderedByCustomers) || 0,
      OnOrder: Number(item.QuantityOrderedFromVendors) || 0,
      Available:
        (Number(item.QuantityOnStock) || 0) -
        (Number(item.QuantityOrderedByCustomers) || 0) +
        (Number(item.QuantityOrderedFromVendors) || 0),
      Warehouses: whs,
      Prices: prices,
    });
  } catch (error) {
    if (error.response && error.response.status === 401) {
      try {
        sapSession = { b1session: null, routeid: null };
        await login();
        const retry = await sapClient.get(query, {
          headers: { Cookie: buildCookieHeader() },
        });
        const item = retry.data || {};
        return res.json({
          ItemCode: item.ItemCode || codigo,
          ItemName: item.ItemName || '',
          FrgnName: item.ForeignName || '',
          SWW: item.SWW || '',
          QuantityOnStock: Number(item.QuantityOnStock) || 0,
          IsCommited: Number(item.QuantityOrderedByCustomers) || 0,
          OnOrder: Number(item.QuantityOrderedFromVendors) || 0,
          Available:
            (Number(item.QuantityOnStock) || 0) -
            (Number(item.QuantityOrderedByCustomers) || 0) +
            (Number(item.QuantityOrderedFromVendors) || 0),
          Warehouses: [],
          Prices: [],
        });
      } catch (retryError) {
        return handleError(res, retryError);
      }
    }
    return handleError(res, error);
  }
});

app.get('/api/articulos/:codigo/series', requireAuth, async (req, res) => {
  const codigo = String(req.params.codigo || '').trim();
  if (!codigo) {
    return res
      .status(400)
      .json({ error: { message: 'El código es obligatorio' } });
  }

  const sql = `SELECT "NUMERO_SERIE","SERIE_FABRICANTE","NUMERO_LOTE","DEPOSITO","FECHA_INGRESO","COSTO_LOCAL","TIPO_CAMBIO_INGRESO","COSTO_USD_INGRESO","ESTADO_DESC" FROM "TRACTOAGRO"."V_PRODUCTOS_SERIES_COSTO" WHERE "CODIGO_TRACTO" = ? ORDER BY "FECHA_INGRESO" DESC`;

  try {
    const rows = await hanaExec(sql, [codigo]);
    return res.json({ data: rows || [] });
  } catch (err) {
    console.error('Error en /api/articulos/:codigo/series:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar series en HANA' } });
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

function parseCsvParam(value) {
  if (!value) return [];
  return String(value)
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v !== '' && v !== 'Todos' && v !== 'Todas');
}

app.get('/api/articulos/filtros-disponibles', requireAuth, async (req, res) => {
  const grupos = parseCsvParam(req.query.grupos || req.query.grupo);
  const marcas = parseCsvParam(req.query.marcas || req.query.marca);
  const fabricantes = parseCsvParam(req.query.fabricantes || req.query.fabricante);

  const conditions = [];
  const params = [];

  if (grupos.length) {
    const placeholders = grupos.map(() => '?').join(', ');
    conditions.push(`"RUBRO" IN (${placeholders})`);
    for (const g of grupos) params.push(g);
  }
  if (marcas.length) {
    const placeholders = marcas.map(() => '?').join(', ');
    conditions.push(`"MARCA" IN (${placeholders})`);
    for (const m of marcas) params.push(m);
  }
  if (fabricantes.length) {
    const placeholders = fabricantes.map(() => '?').join(', ');
    conditions.push(`"FABRICANTE" IN (${placeholders})`);
    for (const f of fabricantes) params.push(f);
  }

  const whereSql = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const sql = `SELECT DISTINCT "RUBRO" AS "grupo", "MARCA" AS "marca", "FABRICANTE" AS "fabricante" FROM "TRACTOAGRO"."V_PRODUCTOS" ${whereSql}`;

  try {
    const rows = await hanaExec(sql, params);

    const gruposSet = new Set();
    const marcasSet = new Set();
    const fabricantesSet = new Set();

    for (const r of rows || []) {
      if (r.grupo !== undefined && r.grupo !== null && String(r.grupo).trim() !== '') {
        gruposSet.add(String(r.grupo).trim());
      }
      if (r.marca !== undefined && r.marca !== null && String(r.marca).trim() !== '') {
        marcasSet.add(String(r.marca).trim());
      }
      if (r.fabricante !== undefined && r.fabricante !== null && String(r.fabricante).trim() !== '') {
        fabricantesSet.add(String(r.fabricante).trim());
      }
    }

    const sortEs = (a, b) => a.localeCompare(b, 'es', { sensitivity: 'base' });

    return res.json({
      grupos: Array.from(gruposSet).sort(sortEs),
      marcas: Array.from(marcasSet).sort(sortEs),
      fabricantes: Array.from(fabricantesSet).sort(sortEs),
    });
  } catch (err) {
    console.error('Error en /api/articulos/filtros-disponibles:', err.message);
    return res
      .status(500)
      .json({ error: { message: 'Error al consultar filtros disponibles en HANA' } });
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

    // Marcas activas desde HANA (tabla de usuario @MARCAS), con fallback a V_PRODUCTOS
    // Se usa exclusivamente el campo "Code" tanto para la clave como para el texto visible.
    let marcas = [];
    try {
      const rows = await hanaExec(
        `SELECT "Code" AS "code" FROM "TRACTOAGRO"."@MARCAS" WHERE "U_Activo" = 'Si' ORDER BY "Code" ASC`
      );
      marcas = (rows || [])
        .map((r) => {
          const code = r.code !== undefined && r.code !== null ? String(r.code) : '';
          return { code, name: code };
        })
        .filter((m) => m.code !== '');
    } catch (err) {
      console.warn(
        'No se pudo consultar @MARCAS en HANA, se usará fallback desde V_PRODUCTOS:',
        err.message
      );
      try {
        const rows = await hanaExec(
          `SELECT DISTINCT "MARCA" AS "code" FROM "TRACTOAGRO"."V_PRODUCTOS" WHERE "MARCA" IS NOT NULL AND "MARCA" != '' ORDER BY "MARCA" ASC`
        );
        marcas = (rows || [])
          .map((r) => {
            const code = r.code !== undefined && r.code !== null ? String(r.code) : '';
            return { code, name: code };
          })
          .filter((m) => m.code !== '');
      } catch (fallbackErr) {
        console.warn(
          'No se pudieron cargar las marcas desde HANA:',
          fallbackErr.message
        );
        marcas = [];
      }
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
  const grupos = parseCsvParam(req.query.grupos || req.query.rubro);
  const fabricantes = parseCsvParam(req.query.fabricantes || req.query.fabricante);
  const marcas = parseCsvParam(req.query.marcas || req.query.marca);
  const stockEstado = (req.query.stockEstado || '').trim();
  const colFilters = parseColumnFilters(req.query);
  const rubro = grupos.length === 1 ? grupos[0] : '';
  const fabricante = fabricantes.length === 1 ? fabricantes[0] : '';
  const marca = marcas.length === 1 ? marcas[0] : '';

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

    const [warehouses, itemGroups, manufacturers, priceLists] = await Promise.all([
      warehousesPromise,
      itemGroupsPromise,
      manufacturersPromise,
      priceListsPromise,
    ]);

    const query = buildArticulosQuery({
      page,
      limit,
      search,
      rubro,
      fabricante,
      marca,
      grupos,
      fabricantes,
      marcas,
      stockEstado,
      colFilters,
      itemGroups,
    });

    const response = await sapClient.get(query, {
      headers: { Cookie: buildCookieHeader() },
    });

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
        const query = buildArticulosQuery({
          page,
          limit,
          search,
          rubro,
          fabricante,
          marca,
          grupos,
          fabricantes,
          marcas,
          stockEstado,
          colFilters,
          itemGroups,
        });
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
