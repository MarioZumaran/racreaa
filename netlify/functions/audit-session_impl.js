/**
 * audit-session_impl.js — DMZ Audit
 * Gestión de sesiones colaborativas multi-auditor.
 *
 * Endpoints (vía query param action):
 *   POST action=create  → Crear sesión, devuelve session_code de 6 chars
 *   POST action=join    → Unirse a sesión por código, bloquear sección
 *   GET  action=status  → Polling: estado completo de la sesión
 *   POST action=release → Liberar sección (si auditor abandona)
 *   POST action=expire  → Expirar sesión manualmente (solo host)
 */
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
});

const JWT_SECRET = process.env.JWT_SECRET;

const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()),
  'https://dmzkitchensupport.github.io',
  'https://mariozumaran.github.io',
  'https://dmz-audit.netlify.app',
].filter(Boolean);

const SECTIONS = ['alimentos', 'salon', 'fotos'];

function verifyToken(h) {
  if (!h?.startsWith('Bearer ')) throw new Error('AUTH_MISSING');
  try { return jwt.verify(h.slice(7), JWT_SECRET); }
  catch { throw new Error('AUTH_INVALID'); }
}

function sanitize(v, max = 200) {
  return typeof v === 'string' ? v.slice(0, max).replace(/[<>]/g, '') : '';
}

/** Genera código de sesión: 6 chars alfanumérico mayúscula, legible */
function genSessionCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sin 0,O,I,1
  let code = '';
  const bytes = crypto.randomBytes(6);
  for (let i = 0; i < 6; i++) code += chars[bytes[i] % chars.length];
  return code;
}

function genSessionId() {
  return 'SES-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  res.setHeader('Cache-Control', 'no-store');

  let claims;
  try { claims = verifyToken(req.headers.authorization); }
  catch { return res.status(401).json({ success: false, message: 'No autorizado.' }); }

  const tenantId   = claims.tenant_id;
  const operatorId = claims.sub;
  const operatorName = claims.full_name || claims.email || 'Auditor';

  const action = req.query.action || req.body?.action;
  const client = await pool.connect();

  try {
    /* ────────────────────────────────────────────────
     * CREATE — host crea sesión, bloquea su sección
     * ──────────────────────────────────────────────── */
    if (req.method === 'POST' && action === 'create') {
      const body = req.body || {};
      const hostSection = sanitize(body.section || 'alimentos', 20);
      if (!SECTIONS.includes(hostSection)) {
        return res.status(400).json({ success: false, message: 'Sección inválida.' });
      }

      // Generar código único (retry si colisión)
      let sessionCode, attempts = 0;
      do {
        sessionCode = genSessionCode();
        const check = await client.query(
          `SELECT id FROM racreaa.audit_sessions WHERE session_code = $1 LIMIT 1`,
          [sessionCode]
        );
        if (!check.rows[0]) break;
        attempts++;
      } while (attempts < 5);

      const sessionId = genSessionId();
      const initialLocks = {
        [hostSection]: {
          operator_id:   operatorId,
          operator_name: operatorName,
          locked_at:     new Date().toISOString(),
        }
      };

      await client.query(`
        INSERT INTO racreaa.audit_sessions
          (id, tenant_id, host_operator_id, session_code,
           establecimiento, fecha, servicio,
           status, section_locks, created_at, updated_at, expires_at)
        VALUES ($1, $2::uuid, $3, $4, $5, $6, $7,
                'open', $8::jsonb, NOW(), NOW(), NOW() + INTERVAL '4 hours')
      `, [
        sessionId, tenantId, operatorId, sessionCode,
        sanitize(body.establecimiento || ''),
        body.fecha || null,
        sanitize(body.servicio || ''),
        JSON.stringify(initialLocks),
      ]);

      return res.status(200).json({
        success:      true,
        session_id:   sessionId,
        session_code: sessionCode,
        section:      hostSection,
        expires_in:   '4 horas',
        message:      `Sesión creada. Código: ${sessionCode}`,
      });
    }

    /* ────────────────────────────────────────────────
     * JOIN — auditor se une por código y bloquea sección
     * ──────────────────────────────────────────────── */
    if (req.method === 'POST' && action === 'join') {
      const body = req.body || {};
      const code    = sanitize(body.session_code || '', 10).toUpperCase();
      const section = sanitize(body.section || '', 20);

      if (!code || !SECTIONS.includes(section)) {
        return res.status(400).json({ success: false, message: 'Código o sección inválidos.' });
      }

      // Buscar sesión activa
      const sRes = await client.query(`
        SELECT * FROM racreaa.audit_sessions
        WHERE session_code = $1
          AND tenant_id = $2::uuid
          AND status = 'open'
          AND expires_at > NOW()
        LIMIT 1
      `, [code, tenantId]);

      if (!sRes.rows[0]) {
        return res.status(404).json({ success: false, message: 'Sesión no encontrada o expirada.' });
      }

      const session = sRes.rows[0];
      const locks   = session.section_locks || {};

      // Verificar que la sección no esté ya tomada por otro operador
      if (locks[section] && locks[section].operator_id !== operatorId) {
        return res.status(409).json({
          success: false,
          message: `La sección "${section}" ya está siendo evaluada por ${locks[section].operator_name}.`,
          section_taken_by: locks[section].operator_name,
        });
      }

      // Bloquear sección
      locks[section] = {
        operator_id:   operatorId,
        operator_name: operatorName,
        locked_at:     new Date().toISOString(),
      };

      await client.query(`
        UPDATE racreaa.audit_sessions
        SET section_locks = $1::jsonb, updated_at = NOW()
        WHERE id = $2
      `, [JSON.stringify(locks), session.id]);

      return res.status(200).json({
        success:        true,
        session_id:     session.id,
        session_code:   session.session_code,
        section:        section,
        establecimiento: session.establecimiento,
        fecha:          session.fecha,
        servicio:       session.servicio,
        section_locks:  locks,
        message:        `Unido a sesión ${code}. Evaluando: ${section}.`,
      });
    }

    /* ────────────────────────────────────────────────
     * STATUS — polling: estado actual de la sesión
     * ──────────────────────────────────────────────── */
    if (req.method === 'GET' && action === 'status') {
      const code = sanitize(req.query.code || '', 10).toUpperCase();
      if (!code) return res.status(400).json({ success: false, message: 'Código requerido.' });

      const sRes = await client.query(`
        SELECT id, session_code, host_operator_id, establecimiento, fecha, servicio,
               status, section_locks, created_at, updated_at, expires_at
        FROM racreaa.audit_sessions
        WHERE session_code = $1 AND tenant_id = $2::uuid
        LIMIT 1
      `, [code, tenantId]);

      if (!sRes.rows[0]) {
        return res.status(404).json({ success: false, message: 'Sesión no encontrada.' });
      }

      const s = sRes.rows[0];
      const isExpired = new Date(s.expires_at) < new Date();

      // Auto-expire si venció
      if (isExpired && s.status === 'open') {
        await client.query(
          `UPDATE racreaa.audit_sessions SET status='expired', updated_at=NOW() WHERE id=$1`,
          [s.id]
        );
        s.status = 'expired';
      }

      // Calcular secciones disponibles
      const locks     = s.section_locks || {};
      const taken     = Object.keys(locks);
      const available = SECTIONS.filter(sec => !locks[sec]);

      return res.status(200).json({
        success:        true,
        session_id:     s.id,
        session_code:   s.session_code,
        status:         s.status,
        is_expired:     isExpired,
        is_host:        s.host_operator_id === operatorId,
        establecimiento: s.establecimiento,
        fecha:          s.fecha,
        servicio:       s.servicio,
        section_locks:  locks,
        sections_taken: taken,
        sections_available: available,
        updated_at:     s.updated_at,
        expires_at:     s.expires_at,
      });
    }

    /* ────────────────────────────────────────────────
     * RELEASE — liberar sección (auditor la abandonó)
     * ──────────────────────────────────────────────── */
    if (req.method === 'POST' && action === 'release') {
      const body    = req.body || {};
      const code    = sanitize(body.session_code || '', 10).toUpperCase();
      const section = sanitize(body.section || '', 20);

      const sRes = await client.query(`
        SELECT id, section_locks FROM racreaa.audit_sessions
        WHERE session_code = $1 AND tenant_id = $2::uuid AND status = 'open'
        LIMIT 1
      `, [code, tenantId]);

      if (!sRes.rows[0]) return res.status(404).json({ success: false, message: 'Sesión no encontrada.' });

      const session = sRes.rows[0];
      const locks   = session.section_locks || {};

      // Solo puede liberar quien la tomó (o admin)
      if (locks[section]?.operator_id === operatorId || claims.role === 'admin') {
        delete locks[section];
        await client.query(`
          UPDATE racreaa.audit_sessions SET section_locks=$1::jsonb, updated_at=NOW() WHERE id=$2
        `, [JSON.stringify(locks), session.id]);
        return res.status(200).json({ success: true, section_locks: locks });
      }
      return res.status(403).json({ success: false, message: 'No tienes permiso para liberar esta sección.' });
    }

    /* ────────────────────────────────────────────────
     * EXPIRE — host finaliza sesión manualmente
     * ──────────────────────────────────────────────── */
    if (req.method === 'POST' && action === 'expire') {
      const body = req.body || {};
      const code = sanitize(body.session_code || '', 10).toUpperCase();

      const sRes = await client.query(`
        SELECT id, host_operator_id FROM racreaa.audit_sessions
        WHERE session_code=$1 AND tenant_id=$2::uuid LIMIT 1
      `, [code, tenantId]);

      if (!sRes.rows[0]) return res.status(404).json({ success: false, message: 'Sesión no encontrada.' });

      const session = sRes.rows[0];
      if (session.host_operator_id !== operatorId && claims.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Solo el host puede cerrar la sesión.' });
      }

      await client.query(
        `UPDATE racreaa.audit_sessions SET status='completed', updated_at=NOW() WHERE id=$1`,
        [session.id]
      );
      return res.status(200).json({ success: true, message: 'Sesión cerrada.' });
    }

    return res.status(400).json({ success: false, message: 'Acción no válida.' });

  } catch (err) {
    console.error('[audit-session] ERROR:', err.message);
    return res.status(500).json({ success: false, message: 'Error interno.', detail: err.message });
  } finally {
    client.release();
  }
};
