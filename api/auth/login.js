/**
 * /api/auth/login.js
 * RACREAA — Autenticación JWT Multi-Tenant
 */

import { Pool }   from 'pg';
import bcrypt     from 'bcryptjs';
import jwt        from 'jsonwebtoken';
import crypto     from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_EXPIRY         = process.env.JWT_EXPIRY         || '15m';
const JWT_REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';
const ALLOWED_ORIGINS    = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
const REDIS_URL          = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN        = process.env.UPSTASH_REDIS_REST_TOKEN;
const HAS_REDIS          = !!(REDIS_URL && REDIS_TOKEN);

/* ── Rate Limiting (opcional — requiere Upstash) ── */
async function checkRateLimit(ip) {
  if (!HAS_REDIS) return { allowed: true, remaining: 5 };
  try {
    const blockKey = `racreaa:login_block:${ip}`;
    const headers  = { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' };
    const blockRes = await fetch(`${REDIS_URL}/get/${blockKey}`, { headers });
    const blockData = await blockRes.json();
    if (blockData.result) return { allowed: false, blocked: true, retryAfter: 1800 };
    const countRes  = await fetch(`${REDIS_URL}/get/racreaa:login_fail:${ip}`, { headers });
    const countData = await countRes.json();
    const count     = parseInt(countData.result || '0', 10);
    return { allowed: true, failCount: count, remaining: Math.max(0, 5 - count) };
  } catch { return { allowed: true, remaining: 5 }; }
}

async function recordFailedAttempt(ip) {
  if (!HAS_REDIS) return;
  try {
    const key     = `racreaa:login_fail:${ip}`;
    const headers = { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' };
    await fetch(`${REDIS_URL}/pipeline`, {
      method: 'POST', headers,
      body: JSON.stringify([['INCR', key], ['EXPIRE', key, 900]]),
    });
    const res   = await fetch(`${REDIS_URL}/get/${key}`, { headers });
    const data  = await res.json();
    const count = parseInt(data.result || '0', 10);
    if (count >= 5) {
      await fetch(`${REDIS_URL}/set/racreaa:login_block:${ip}/1/ex/1800`, { headers });
    }
  } catch {}
}

async function clearFailedAttempts(ip) {
  if (!HAS_REDIS) return;
  try {
    const headers = { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' };
    await fetch(`${REDIS_URL}/del/racreaa:login_fail:${ip}`, { headers });
  } catch {}
}

/* ── Helpers ── */
function sanitizeEmail(email) {
  return typeof email === 'string' ? email.toLowerCase().trim().slice(0, 255) : '';
}
function sanitizeSlug(slug) {
  return typeof slug === 'string' ? slug.toLowerCase().trim().replace(/[^a-z0-9-]/g, '').slice(0, 64) : '';
}
function generateRefreshToken() {
  const raw  = crypto.randomBytes(64).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}
function issueAccessToken(operator, tenant) {
  const jti = crypto.randomUUID();
  return {
    token: jwt.sign({
      sub: operator.id, jti,
      tenant_id: tenant.id, tenant_slug: tenant.slug,
      role: operator.role, full_name: operator.full_name, email: operator.email,
    }, JWT_SECRET, { algorithm: 'HS256', expiresIn: JWT_EXPIRY,
      issuer: 'racreaa.dmzkitchensupport.com', audience: tenant.slug }),
    jti,
  };
}
function buildRefreshCookie(raw) {
  return [`racreaa_rt=${raw}`, `Max-Age=${60*60*24*7}`, `Path=/api/auth`, `HttpOnly`, `Secure`, `SameSite=Strict`].join('; ');
}
function hashPayload(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

async function logEvent(client, operatorId, tenantId, action, ip, ua, requestId, jti) {
  try {
    await client.query(`
      INSERT INTO racreaa.audit_logs (id,tenant_id,operator_id,action,entity_type,entity_id,client_ip,user_agent,request_id,payload_hash,occurred_at)
      VALUES (gen_random_uuid(),$1,$2,$3,'auth',$4,$5,$6,$7,$8,NOW())
    `, [tenantId, operatorId, action, jti||operatorId, ip, ua, requestId,
        hashPayload({ action, operatorId, tenantId, jti, ip })]);
  } catch {}
}

/* ── Handler ── */
export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false, message:'Method Not Allowed' });

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control', 'no-store');

  const clientIP  = req.headers['x-forwarded-for']?.split(',')[0].trim() || 'unknown';
  const userAgent = req.headers['user-agent'] || '';
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();

  /* Rate limit */
  const rateCheck = await checkRateLimit(clientIP);
  if (!rateCheck.allowed) {
    return res.status(429).json({ success:false, message:'Demasiados intentos. Intente en 30 minutos.', retryAfter: rateCheck.retryAfter });
  }

  /* Validar body */
  const { email: rawEmail, password, tenant_slug: rawSlug } = req.body || {};
  const email      = sanitizeEmail(rawEmail);
  const tenantSlug = sanitizeSlug(rawSlug);

  if (!email || !password || !tenantSlug) {
    return res.status(400).json({ success:false, message:'Los campos email, password y tenant_slug son obligatorios.' });
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ success:false, message:'Credenciales inválidas.' });
  }

  const client = await pool.connect();
  try {
    /* Buscar tenant */
    const tenantRes = await client.query(
      `SELECT id,slug,name,brand_name,is_active,plan FROM racreaa.tenants WHERE slug=$1 LIMIT 1`,
      [tenantSlug]
    );
    const tenant = tenantRes.rows[0];
    if (!tenant || !tenant.is_active) {
      await bcrypt.compare(password, '$2a$12$dummyhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
      await recordFailedAttempt(clientIP);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.' });
    }

    /* Buscar operator */
    const opRes = await client.query(
      `SELECT id,tenant_id,email,full_name,role,password_hash,is_active FROM racreaa.operators WHERE email=$1 AND tenant_id=$2 LIMIT 1`,
      [email, tenant.id]
    );
    const operator = opRes.rows[0];
    if (!operator) {
      await bcrypt.compare(password, '$2a$12$dummyhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
      await recordFailedAttempt(clientIP);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.' });
    }
    if (!operator.is_active) {
      await bcrypt.compare(password, '$2a$12$dummyhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
      return res.status(401).json({ success:false, message:'Cuenta inactiva. Contacte al administrador.' });
    }

    /* Verificar password */
    const valid = await bcrypt.compare(password, operator.password_hash);
    if (!valid) {
      await recordFailedAttempt(clientIP);
      await logEvent(client, operator.id, tenant.id, 'LOGIN_WRONG_PASSWORD', clientIP, userAgent, requestId, null);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.', remaining: Math.max(0,(rateCheck.remaining||5)-1) });
    }

    /* Emitir tokens */
    const { token: accessToken, jti } = issueAccessToken(operator, tenant);
    const { raw: refreshRaw, hash: refreshHash } = generateRefreshToken();
    const refreshExp = new Date(Date.now() + 7*24*60*60*1000);

    await client.query(`BEGIN`);
    await client.query(
      `INSERT INTO racreaa.refresh_tokens (id,operator_id,tenant_id,token_hash,jti,client_ip,user_agent,expires_at,created_at)
       VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,NOW())`,
      [operator.id, tenant.id, refreshHash, jti, clientIP, userAgent, refreshExp]
    );
    await client.query(`UPDATE racreaa.operators SET last_login_at=NOW() WHERE id=$1`, [operator.id]);
    await logEvent(client, operator.id, tenant.id, 'LOGIN_SUCCESS', clientIP, userAgent, requestId, jti);
    await client.query(`COMMIT`);

    await clearFailedAttempts(clientIP);
    res.setHeader('Set-Cookie', buildRefreshCookie(refreshRaw));

    return res.status(200).json({
      success: true,
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: JWT_EXPIRY,
      operator: { id:operator.id, full_name:operator.full_name, email:operator.email, role:operator.role },
      tenant:   { id:tenant.id, slug:tenant.slug, name:tenant.name, brand_name:tenant.brand_name, plan:tenant.plan },
    });

  } catch (err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[RACREAA/login]', err.message);
    return res.status(500).json({ success:false, message:'Error interno. El incidente ha sido registrado.' });
  } finally {
    client.release();
  }
}
