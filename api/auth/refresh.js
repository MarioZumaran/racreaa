/**
 * /api/auth/refresh.js
 * RACREAA — Rotación de Access Token via Refresh Token
 *
 * Flujo:
 *   1. Lee el Refresh Token desde la cookie HttpOnly (racreaa_rt)
 *   2. Hashea con SHA-256 y busca en DB (sin exponer el token raw)
 *   3. Valida expiración y que el token no esté revocado
 *   4. Emite nuevo Access Token + rota el Refresh Token (RTR: Refresh Token Rotation)
 *   5. Revoca el RT anterior → detecta reutilización (posible robo)
 */

import { Pool }  from 'pg';
import jwt       from 'jsonwebtoken';
import crypto    from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '15m';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());

function issueAccessToken(operator, tenant) {
  const jti = crypto.randomUUID();
  return {
    token: jwt.sign({
      sub:         operator.id,
      jti,
      tenant_id:   tenant.id,
      tenant_slug: tenant.slug,
      role:        operator.role,
      full_name:   operator.full_name,
      email:       operator.email,
    }, JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: JWT_EXPIRY,
      issuer:    'racreaa.dmzkitchensupport.com',
      audience:  tenant.slug,
    }),
    jti,
  };
}

function generateRefreshToken() {
  const raw  = crypto.randomBytes(64).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

function buildRefreshCookie(rawToken) {
  return [
    `racreaa_rt=${rawToken}`,
    `Max-Age=${60 * 60 * 24 * 7}`,
    `Path=/api/auth`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Strict`,
  ].join('; ');
}

function clearRefreshCookie() {
  return `racreaa_rt=; Max-Age=0; Path=/api/auth; HttpOnly; Secure; SameSite=Strict`;
}

function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k.trim(), v.join('=').trim()];
    })
  );
}

export default async function handler(req, res) {

  /* ── CORS ── */
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Methods',     'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',     'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')    return res.status(405).end();

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  const clientIP  = req.headers['x-forwarded-for']?.split(',')[0].trim() || 'unknown';
  const userAgent = req.headers['user-agent'] || '';

  /* ── Leer cookie HttpOnly ── */
  const cookies      = parseCookies(req.headers.cookie);
  const refreshRaw   = cookies['racreaa_rt'];

  if (!refreshRaw) {
    return res.status(401).json({ success: false, message: 'Sin sesión activa.' });
  }

  const refreshHash = crypto.createHash('sha256').update(refreshRaw).digest('hex');

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /* ── Buscar token en DB ── */
    const rtResult = await client.query(`
      SELECT
        rt.id, rt.operator_id, rt.tenant_id,
        rt.jti, rt.expires_at, rt.revoked_at,
        rt.reuse_detected,
        op.id        AS op_id,
        op.full_name AS op_full_name,
        op.email     AS op_email,
        op.role      AS op_role,
        op.is_active AS op_active,
        t.id         AS t_id,
        t.slug       AS t_slug,
        t.name       AS t_name,
        t.brand_name AS t_brand_name,
        t.is_active  AS t_active,
        t.plan       AS t_plan
      FROM racreaa.refresh_tokens rt
      JOIN racreaa.operators op ON op.id = rt.operator_id
      JOIN racreaa.tenants   t  ON t.id  = rt.tenant_id
      WHERE rt.token_hash = $1
      LIMIT 1
      FOR UPDATE  -- bloquear fila para prevenir race conditions
    `, [refreshHash]);

    const rt = rtResult.rows[0];

    /* ── Token no encontrado ── */
    if (!rt) {
      await client.query('ROLLBACK');
      res.setHeader('Set-Cookie', clearRefreshCookie());
      return res.status(401).json({ success: false, message: 'Sesión inválida.' });
    }

    /* ── Detección de reutilización (posible robo de RT) ── */
    if (rt.revoked_at !== null) {
      // Este RT ya fue usado — posible token theft
      // Revocar TODOS los tokens del operador como medida de seguridad
      await client.query(`
        UPDATE racreaa.refresh_tokens
        SET revoked_at = NOW(), reuse_detected = TRUE
        WHERE operator_id = $1 AND revoked_at IS NULL
      `, [rt.operator_id]);

      // Audit trail de incidente
      await client.query(`
        INSERT INTO racreaa.audit_logs (
          id, tenant_id, operator_id,
          action, entity_type, entity_id,
          client_ip, user_agent, payload_hash, occurred_at
        ) VALUES (
          gen_random_uuid(), $1, $2,
          'REFRESH_TOKEN_REUSE_DETECTED', 'auth', $2,
          $3, $4, $5, NOW()
        )
      `, [
        rt.tenant_id, rt.operator_id,
        clientIP, userAgent,
        crypto.createHash('sha256').update(JSON.stringify({ event:'REUSE', op: rt.operator_id, ip: clientIP })).digest('hex'),
      ]);

      await client.query('COMMIT');
      res.setHeader('Set-Cookie', clearRefreshCookie());
      return res.status(401).json({
        success: false,
        message: 'Sesión comprometida. Por seguridad, todas las sesiones han sido cerradas. Inicie sesión nuevamente.',
      });
    }

    /* ── Token expirado ── */
    if (new Date() > new Date(rt.expires_at)) {
      await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at = NOW() WHERE id = $1`, [rt.id]);
      await client.query('COMMIT');
      res.setHeader('Set-Cookie', clearRefreshCookie());
      return res.status(401).json({ success: false, message: 'Sesión expirada. Inicie sesión nuevamente.' });
    }

    /* ── Operador o tenant inactivos ── */
    if (!rt.op_active || !rt.t_active) {
      await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at = NOW() WHERE id = $1`, [rt.id]);
      await client.query('COMMIT');
      res.setHeader('Set-Cookie', clearRefreshCookie());
      return res.status(401).json({ success: false, message: 'Cuenta inactiva.' });
    }

    /* ── RTR: Revocar token actual ── */
    await client.query(`
      UPDATE racreaa.refresh_tokens SET revoked_at = NOW() WHERE id = $1
    `, [rt.id]);

    /* ── Emitir nuevo Access Token ── */
    const operator = { id: rt.op_id, full_name: rt.op_full_name, email: rt.op_email, role: rt.op_role };
    const tenant   = { id: rt.t_id, slug: rt.t_slug, name: rt.t_name, brand_name: rt.t_brand_name, plan: rt.t_plan };

    const { token: newAccessToken, jti: newJti } = issueAccessToken(operator, tenant);

    /* ── Emitir nuevo Refresh Token ── */
    const { raw: newRtRaw, hash: newRtHash } = generateRefreshToken();
    const newExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await client.query(`
      INSERT INTO racreaa.refresh_tokens (
        id, operator_id, tenant_id,
        token_hash, jti,
        client_ip, user_agent,
        expires_at, created_at
      ) VALUES (
        gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, NOW()
      )
    `, [
      rt.operator_id, rt.tenant_id,
      newRtHash, newJti,
      clientIP, userAgent, newExpires,
    ]);

    /* ── Audit log ── */
    await client.query(`
      INSERT INTO racreaa.audit_logs (
        id, tenant_id, operator_id,
        action, entity_type, entity_id,
        client_ip, user_agent, payload_hash, occurred_at
      ) VALUES (
        gen_random_uuid(), $1, $2,
        'TOKEN_REFRESHED', 'auth', $2,
        $3, $4, $5, NOW()
      )
    `, [
      rt.tenant_id, rt.operator_id,
      clientIP, userAgent,
      crypto.createHash('sha256').update(JSON.stringify({ jti: newJti, op: rt.operator_id })).digest('hex'),
    ]);

    await client.query('COMMIT');

    res.setHeader('Set-Cookie', buildRefreshCookie(newRtRaw));

    return res.status(200).json({
      success:      true,
      access_token: newAccessToken,
      token_type:   'Bearer',
      expires_in:   JWT_EXPIRY,
      operator: {
        id:        operator.id,
        full_name: operator.full_name,
        email:     operator.email,
        role:      operator.role,
      },
      tenant,
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[RACREAA/refresh] Error:', err);
    return res.status(500).json({ success: false, message: 'Error interno.' });
  } finally {
    client.release();
  }
}
