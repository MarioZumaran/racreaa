/**
 * /api/auth/set-password.js
 * Permite a un operador crear su contraseña usando un token de reset
 */
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:5 });
const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim()),
  'https://mariozumaran.github.io',
  'https://dmz-audit.netlify.app',
  'https://racreaa.vercel.app',
].filter(Boolean);

function sha256(d){ return crypto.createHash('sha256').update(JSON.stringify(d)).digest('hex'); }

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false, message:'Method Not Allowed' });
  res.setHeader('Cache-Control','no-store');

  const { token, password } = req.body || {};

  // Validaciones
  if (!token || typeof token !== 'string' || token.length < 10) {
    return res.status(400).json({ success:false, message:'Token inválido.' });
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ success:false, message:'La contraseña debe tener mínimo 8 caracteres.' });
  }
  if (!/[A-Z]/.test(password)) {
    return res.status(400).json({ success:false, message:'La contraseña debe contener al menos una mayúscula.' });
  }
  if (!/[0-9]/.test(password)) {
    return res.status(400).json({ success:false, message:'La contraseña debe contener al menos un número.' });
  }

  const clientIP = (req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
  const ua       = req.headers['user-agent']||'';
  const client   = await pool.connect();

  try {
    await client.query('BEGIN');

    // Buscar operador por token
    const opRes = await client.query(`
      SELECT id, tenant_id, email, full_name, role,
             must_change_password, reset_token_expires
      FROM racreaa.operators
      WHERE password_reset_token = $1
        AND is_active = TRUE
        AND reset_token_expires > NOW()
      LIMIT 1
    `, [token]);

    const op = opRes.rows[0];
    if (!op) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        message: 'El enlace es inválido o ha expirado. Solicita uno nuevo al administrador.'
      });
    }

    // Hashear nueva contraseña
    const hash = await bcrypt.hash(password, 12);

    // Actualizar contraseña y limpiar token
    await client.query(`
      UPDATE racreaa.operators
      SET password_hash         = $1,
          must_change_password  = FALSE,
          password_reset_token  = NULL,
          reset_token_expires   = NULL,
          last_login_at         = NOW()
      WHERE id = $2
    `, [hash, op.id]);

    // Revocar todos los refresh tokens anteriores (sesión limpia)
    await client.query(`
      UPDATE racreaa.refresh_tokens
      SET revoked_at = NOW()
      WHERE operator_id = $1 AND revoked_at IS NULL
    `, [op.id]);

    // Audit log
    await client.query(`
      INSERT INTO racreaa.audit_logs
        (id, tenant_id, operator_id, action, entity_type, entity_id,
         client_ip, user_agent, payload_hash, occurred_at)
      VALUES
        (gen_random_uuid(), $1, $2, 'PASSWORD_SET', 'operator', $2,
         $3, $4, $5, NOW())
    `, [
      op.tenant_id, op.id,
      clientIP, ua,
      sha256({ action:'PASSWORD_SET', operatorId:op.id, ip:clientIP })
    ]);

    await client.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: 'Contraseña creada correctamente.',
      email:   op.email
    });

  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[set-password]', err.message);
    return res.status(500).json({ success:false, message:'Error interno.' });
  } finally {
    client.release();
  }
};
