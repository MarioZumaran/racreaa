/**
 * /api/auth/logout.js
 * RACREAA — Cierre de Sesión Seguro
 *
 * Flujo:
 *   1. Lee el Refresh Token de la cookie HttpOnly
 *   2. Lo hashea y revoca en DB
 *   3. Si body incluye { all_devices: true } → revoca todos los RT del operador
 *   4. Limpia la cookie
 *   5. Registra en audit_logs
 */

import { Pool }  from 'pg';
import jwt       from 'jsonwebtoken';
import crypto    from 'crypto';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());

function parseCookies(h) {
  if (!h) return {};
  return Object.fromEntries(h.split(';').map(c => { const [k,...v]=c.trim().split('='); return [k.trim(),v.join('=').trim()]; }));
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Methods',     'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',     'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')    return res.status(405).end();

  res.setHeader('Cache-Control', 'no-store');

  const clientIP  = req.headers['x-forwarded-for']?.split(',')[0].trim() || 'unknown';
  const userAgent = req.headers['user-agent'] || '';
  const allDevices = req.body?.all_devices === true;

  const cookies    = parseCookies(req.headers.cookie);
  const refreshRaw = cookies['racreaa_rt'];

  // Siempre limpiar la cookie, independientemente del resultado
  const clearCookie = `racreaa_rt=; Max-Age=0; Path=/api/auth; HttpOnly; Secure; SameSite=Strict`;

  // Extraer operatorId del Access Token si viene en el header (para revocar todos los dispositivos)
  let operatorIdFromJWT = null;
  let tenantIdFromJWT   = null;
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
      operatorIdFromJWT = decoded.sub;
      tenantIdFromJWT   = decoded.tenant_id;
    } catch (_) { /* token expirado — igualmente procedemos con logout */ }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let operatorId = operatorIdFromJWT;
    let tenantId   = tenantIdFromJWT;

    if (refreshRaw) {
      const hash = crypto.createHash('sha256').update(refreshRaw).digest('hex');

      // Buscar y revocar el RT específico
      const rtRes = await client.query(`
        UPDATE racreaa.refresh_tokens
        SET revoked_at = NOW()
        WHERE token_hash = $1 AND revoked_at IS NULL
        RETURNING operator_id, tenant_id
      `, [hash]);

      if (rtRes.rows[0]) {
        operatorId = operatorId || rtRes.rows[0].operator_id;
        tenantId   = tenantId   || rtRes.rows[0].tenant_id;
      }
    }

    // Revocar todos los RT del operador si se solicitó
    if (allDevices && operatorId) {
      await client.query(`
        UPDATE racreaa.refresh_tokens
        SET revoked_at = NOW()
        WHERE operator_id = $1 AND revoked_at IS NULL
      `, [operatorId]);
    }

    // Audit trail
    if (operatorId) {
      await client.query(`
        INSERT INTO racreaa.audit_logs (
          id, tenant_id, operator_id,
          action, entity_type, entity_id,
          client_ip, user_agent, payload_hash, occurred_at
        ) VALUES (
          gen_random_uuid(), $1, $2,
          $3, 'auth', $2,
          $4, $5, $6, NOW()
        )
      `, [
        tenantId, operatorId,
        allDevices ? 'LOGOUT_ALL_DEVICES' : 'LOGOUT',
        clientIP, userAgent,
        crypto.createHash('sha256').update(JSON.stringify({ op: operatorId, allDevices, ip: clientIP })).digest('hex'),
      ]);
    }

    await client.query('COMMIT');
    res.setHeader('Set-Cookie', clearCookie);
    return res.status(200).json({ success: true, message: 'Sesión cerrada correctamente.' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[RACREAA/logout] Error:', err);
    res.setHeader('Set-Cookie', clearCookie); // limpiar cookie aunque haya error
    return res.status(500).json({ success: false, message: 'Error interno.' });
  } finally {
    client.release();
  }
}
