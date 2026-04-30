/**
 * /api/auth/login.js
 * RACREAA — Autenticación JWT Multi-Tenant
 * Vercel Serverless Function
 *
 * Flujo:
 *   1. Recibe { email, password, tenant_slug }
 *   2. Valida rate limiting por IP (Upstash Redis)
 *   3. Busca el tenant por slug → valida is_active
 *   4. Busca operator por email dentro del tenant (RLS)
 *   5. Verifica password con bcrypt (timing-safe)
 *   6. Emite JWT firmado con HS256 (claims: sub, tenant_id, role, jti)
 *   7. Emite Refresh Token opaco → persiste en DB
 *   8. Registra evento en audit_logs
 *   9. Responde con access_token (15min) + refresh_token HttpOnly cookie
 *
 * Env vars requeridas:
 *   DATABASE_URL, JWT_SECRET, JWT_EXPIRY, JWT_REFRESH_EXPIRY,
 *   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN,
 *   ALLOWED_ORIGINS
 */

import { Pool }    from 'pg';
import bcrypt      from 'bcryptjs';
import jwt         from 'jsonwebtoken';
import crypto      from 'crypto';

/* ─────────────────────────────────────────
   CONFIGURACIÓN
   ───────────────────────────────────────── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

const JWT_SECRET          = process.env.JWT_SECRET;
const JWT_EXPIRY          = process.env.JWT_EXPIRY          || '15m';
const JWT_REFRESH_EXPIRY  = process.env.JWT_REFRESH_EXPIRY  || '7d';
const ALLOWED_ORIGINS     = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());

/* ─────────────────────────────────────────
   RATE LIMITING — Upstash Redis
   Límite: 5 intentos fallidos por IP en 15min
   Bloqueo: 30min tras superar el límite
   ───────────────────────────────────────── */
async function checkRateLimit(ip) {
  if (!process.env.UPSTASH_REDIS_REST_URL) {
    // Sin Redis configurado, permitir (solo en dev)
    if (process.env.NODE_ENV === 'development') return { allowed: true, remaining: 99 };
    throw new Error('RATE_LIMIT_UNCONFIGURED');
  }

  const key      = `racreaa:login_fail:${ip}`;
  const blockKey = `racreaa:login_block:${ip}`;
  const headers  = {
    Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
    'Content-Type': 'application/json',
  };
  const base = process.env.UPSTASH_REDIS_REST_URL;

  // Verificar bloqueo activo
  const blockRes = await fetch(`${base}/get/${blockKey}`, { headers });
  const blockData = await blockRes.json();
  if (blockData.result) {
    return { allowed: false, blocked: true, retryAfter: 1800 };
  }

  // Obtener contador de fallos
  const getRes  = await fetch(`${base}/get/${key}`, { headers });
  const getData = await getRes.json();
  const count   = parseInt(getData.result || '0', 10);

  return { allowed: true, failCount: count, remaining: Math.max(0, 5 - count) };
}

async function recordFailedAttempt(ip) {
  if (!process.env.UPSTASH_REDIS_REST_URL) return;

  const key      = `racreaa:login_fail:${ip}`;
  const blockKey = `racreaa:login_block:${ip}`;
  const headers  = {
    Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
    'Content-Type': 'application/json',
  };
  const base = process.env.UPSTASH_REDIS_REST_URL;

  // Incrementar contador con TTL de 15min
  await fetch(`${base}/pipeline`, {
    method: 'POST',
    headers,
    body: JSON.stringify([
      ['INCR', key],
      ['EXPIRE', key, 900], // 15 minutos
    ]),
  });

  // Re-obtener contador
  const res  = await fetch(`${base}/get/${key}`, { headers });
  const data = await res.json();
  const count = parseInt(data.result || '0', 10);

  // Si superó el límite → activar bloqueo de 30min
  if (count >= 5) {
    await fetch(`${base}/set/${blockKey}/1/ex/1800`, { headers });
  }
}

async function clearFailedAttempts(ip) {
  if (!process.env.UPSTASH_REDIS_REST_URL) return;
  const key     = `racreaa:login_fail:${ip}`;
  const headers = {
    Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
    'Content-Type': 'application/json',
  };
  await fetch(`${process.env.UPSTASH_REDIS_REST_URL}/del/${key}`, { headers });
}

/* ─────────────────────────────────────────
   HELPERS
   ───────────────────────────────────────── */

function sanitizeEmail(email) {
  return typeof email === 'string' ? email.toLowerCase().trim().slice(0, 255) : '';
}

function sanitizeSlug(slug) {
  return typeof slug === 'string' ? slug.toLowerCase().trim().replace(/[^a-z0-9-]/g, '').slice(0, 64) : '';
}

/**
 * Genera un Refresh Token opaco de 64 bytes (criptográficamente seguro).
 * Se hashea con SHA-256 antes de persistir en DB.
 */
function generateRefreshToken() {
  const raw  = crypto.randomBytes(64).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

/**
 * Emite el JWT de acceso con los claims mínimos necesarios.
 * jti = JWT ID único para revocación individual si se implementa una denylist.
 */
function issueAccessToken(operator, tenant) {
  const jti = crypto.randomUUID();
  const payload = {
    sub:        operator.id,
    jti,
    tenant_id:  tenant.id,
    tenant_slug:tenant.slug,
    role:       operator.role,
    full_name:  operator.full_name,
    email:      operator.email,
    iat:        Math.floor(Date.now() / 1000),
  };
  return {
    token: jwt.sign(payload, JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: JWT_EXPIRY,
      issuer:    'racreaa.dmzkitchensupport.com',
      audience:  tenant.slug,
    }),
    jti,
  };
}

/**
 * Construye el Set-Cookie header para el Refresh Token HttpOnly.
 * HttpOnly + Secure + SameSite=Strict elimina acceso desde JS.
 */
function buildRefreshCookie(rawToken) {
  const maxAge = 60 * 60 * 24 * 7; // 7 días en segundos
  const parts  = [
    `racreaa_rt=${rawToken}`,
    `Max-Age=${maxAge}`,
    `Path=/api/auth`,      // solo accesible desde los endpoints de auth
    `HttpOnly`,
    `Secure`,
    `SameSite=Strict`,
  ];
  return parts.join('; ');
}

/* ─────────────────────────────────────────
   HANDLER PRINCIPAL
   ───────────────────────────────────────── */
export default async function handler(req, res) {

  /* ── CORS ── */
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Methods',     'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',     'Content-Type, X-Request-ID');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();

  /* ── Solo POST ── */
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  /* ── Security headers ── */
  res.setHeader('X-Content-Type-Options',    'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control',             'no-store');

  /* ── Metadata de la solicitud ── */
  const clientIP  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || '';
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();

  /* ── Rate limiting ── */
  let rateCheck;
  try {
    rateCheck = await checkRateLimit(clientIP);
  } catch (e) {
    console.error('[RACREAA/login] Rate limit error:', e.message);
    return res.status(503).json({ success: false, message: 'Servicio temporalmente no disponible.' });
  }

  if (!rateCheck.allowed) {
    // Registrar intento bloqueado (sin acceder a DB de operadores)
    await logAuthEvent(null, null, 'LOGIN_BLOCKED', clientIP, userAgent, requestId, null);
    return res.status(429).json({
      success:    false,
      message:    'Demasiados intentos fallidos. Intente nuevamente en 30 minutos.',
      retryAfter: rateCheck.retryAfter,
    });
  }

  /* ── Validar body ── */
  const { email: rawEmail, password, tenant_slug: rawSlug } = req.body || {};

  const email       = sanitizeEmail(rawEmail);
  const tenantSlug  = sanitizeSlug(rawSlug);

  if (!email || !password || !tenantSlug) {
    return res.status(400).json({
      success: false,
      message: 'Los campos email, password y tenant_slug son obligatorios.',
    });
  }

  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ success: false, message: 'Credenciales inválidas.' });
  }

  const client = await pool.connect();

  try {
    /* ── 1. Buscar tenant por slug ── */
    const tenantResult = await client.query(
      `SELECT id, slug, name, brand_name, is_active, plan
       FROM racreaa.tenants
       WHERE slug = $1
       LIMIT 1`,
      [tenantSlug]
    );

    const tenant = tenantResult.rows[0];

    // Si no existe el tenant, continuar con bcrypt dummy para evitar timing attack
    if (!tenant || !tenant.is_active) {
      await bcrypt.compare(password, '$2a$12$dummyhashtopreventtimingattackXXXXXXXXXXXXXXXXX');
      await recordFailedAttempt(clientIP);
      await logAuthEvent(null, tenantSlug, 'LOGIN_TENANT_NOT_FOUND', clientIP, userAgent, requestId, null);
      return res.status(401).json({ success: false, message: 'Credenciales incorrectas.' });
    }

    /* ── 2. SET RLS context y buscar operador ── */
    await client.query(`SET LOCAL app.current_tenant_id = $1`, [tenant.id]);

    const operatorResult = await client.query(
      `SELECT id, tenant_id, email, full_name, role, password_hash, is_active, last_login_at
       FROM racreaa.operators
       WHERE email = $1
         AND tenant_id = $2
       LIMIT 1`,
      [email, tenant.id]
    );

    const operator = operatorResult.rows[0];

    // Operador no encontrado → bcrypt dummy para timing-safe
    if (!operator) {
      await bcrypt.compare(password, '$2a$12$dummyhashtopreventtimingattackXXXXXXXXXXXXXXXXX');
      await recordFailedAttempt(clientIP);
      await logAuthEvent(null, tenant.id, 'LOGIN_USER_NOT_FOUND', clientIP, userAgent, requestId, null);
      return res.status(401).json({ success: false, message: 'Credenciales incorrectas.' });
    }

    // Operador inactivo
    if (!operator.is_active) {
      await bcrypt.compare(password, '$2a$12$dummyhashtopreventtimingattackXXXXXXXXXXXXXXXXX');
      await recordFailedAttempt(clientIP);
      await logAuthEvent(operator.id, tenant.id, 'LOGIN_USER_INACTIVE', clientIP, userAgent, requestId, null);
      return res.status(401).json({ success: false, message: 'Cuenta inactiva. Contacte al administrador.' });
    }

    /* ── 3. Verificar contraseña (bcrypt) ── */
    const passwordValid = await bcrypt.compare(password, operator.password_hash);

    if (!passwordValid) {
      await recordFailedAttempt(clientIP);
      await logAuthEvent(operator.id, tenant.id, 'LOGIN_WRONG_PASSWORD', clientIP, userAgent, requestId, null);
      return res.status(401).json({
        success:   false,
        message:   'Credenciales incorrectas.',
        remaining: Math.max(0, rateCheck.remaining - 1),
      });
    }

    /* ── 4. Emitir tokens ── */
    const { token: accessToken, jti } = issueAccessToken(operator, tenant);
    const { raw: refreshRaw, hash: refreshHash } = generateRefreshToken();

    /* ── 5. Persistir refresh token en DB ── */
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 días

    await client.query(`
      INSERT INTO racreaa.refresh_tokens (
        id, operator_id, tenant_id,
        token_hash, jti,
        client_ip, user_agent,
        expires_at, created_at
      ) VALUES (
        gen_random_uuid(), $1, $2,
        $3, $4,
        $5, $6,
        $7, NOW()
      )
    `, [
      operator.id, tenant.id,
      refreshHash, jti,
      clientIP, userAgent,
      refreshExpiresAt,
    ]);

    /* ── 6. Actualizar last_login_at ── */
    await client.query(
      `UPDATE racreaa.operators SET last_login_at = NOW() WHERE id = $1`,
      [operator.id]
    );

    /* ── 7. Audit trail ── */
    await logAuthEventClient(client, operator.id, tenant.id, 'LOGIN_SUCCESS', clientIP, userAgent, requestId, jti);

    /* ── 8. Limpiar contador de fallos tras login exitoso ── */
    await clearFailedAttempts(clientIP);

    /* ── 9. Responder ── */
    res.setHeader('Set-Cookie', buildRefreshCookie(refreshRaw));

    return res.status(200).json({
      success:      true,
      access_token: accessToken,
      token_type:   'Bearer',
      expires_in:   JWT_EXPIRY,
      operator: {
        id:        operator.id,
        full_name: operator.full_name,
        email:     operator.email,
        role:      operator.role,
      },
      tenant: {
        id:          tenant.id,
        slug:        tenant.slug,
        name:        tenant.name,
        brand_name:  tenant.brand_name,
        plan:        tenant.plan,
      },
    });

  } catch (err) {
    console.error('[RACREAA/login] Error:', err);
    await logAuthEvent(null, null, 'LOGIN_SERVER_ERROR', clientIP, userAgent, requestId, null);
    return res.status(500).json({ success: false, message: 'Error interno. El incidente ha sido registrado.' });
  } finally {
    client.release();
  }
}

/* ─────────────────────────────────────────
   HELPERS DE AUDIT LOG
   ───────────────────────────────────────── */

/** Versión con cliente de transacción existente */
async function logAuthEventClient(client, operatorId, tenantId, action, ip, ua, requestId, jti) {
  try {
    await client.query(`
      INSERT INTO racreaa.audit_logs (
        id, tenant_id, operator_id,
        action, entity_type, entity_id,
        client_ip, user_agent, request_id,
        payload_hash, occurred_at
      ) VALUES (
        gen_random_uuid(), $1, $2,
        $3, 'auth', $4,
        $5, $6, $7,
        $8, NOW()
      )
    `, [
      tenantId, operatorId,
      action, jti || operatorId,
      ip, ua, requestId,
      crypto.createHash('sha256').update(JSON.stringify({ action, operatorId, tenantId, jti, ip })).digest('hex'),
    ]);
  } catch (e) {
    console.error('[RACREAA/login] Audit log error:', e.message);
  }
}

/** Versión standalone (para casos de error antes de abrir transacción) */
async function logAuthEvent(operatorId, tenantId, action, ip, ua, requestId, jti) {
  const c = await pool.connect();
  try {
    await logAuthEventClient(c, operatorId, tenantId, action, ip, ua, requestId, jti);
  } finally {
    c.release();
  }
}
