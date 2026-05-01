/**
 * /api/monitor.js — Panel de monitoreo para Mario (admin only)
 * Retorna eventos de session_events + stats agregadas
 */
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:5 });
const JWT_SECRET      = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

function verifyAdmin(h) {
  if (!h?.startsWith('Bearer ')) return null;
  try {
    const d = jwt.verify(h.slice(7), JWT_SECRET);
    return (d.role === 'admin' || d.role === 'supervisor') ? d : null;
  } catch { return null; }
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET')    return res.status(405).end();
  res.setHeader('Cache-Control','no-store');

  // Solo admins pueden ver el monitor
  const claims = verifyAdmin(req.headers.authorization);
  if (!claims) return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });

  const tenantSlug   = req.query.tenant    || claims.tenant_slug || 'dmz';
  const limit        = Math.min(parseInt(req.query.limit||'100'), 500);
  const severityFilter = req.query.severity   || null;
  const typeFilter     = req.query.event_type || null;
  const operatorFilter = req.query.operator_id|| null;

  const client = await pool.connect();
  try {
    // Obtener tenant_id
    const tRes = await client.query(`SELECT id FROM racreaa.tenants WHERE slug=$1 LIMIT 1`, [tenantSlug]);
    const tenantId = tRes.rows[0]?.id;
    if (!tenantId) return res.status(404).json({ error: 'Tenant no encontrado' });

    // Construir query dinámico
    const conditions = ['se.tenant_id = $1'];
    const params     = [tenantId];
    let pi = 2;

    if (severityFilter) { conditions.push(`se.severity = $${pi++}`); params.push(severityFilter); }
    if (typeFilter)     { conditions.push(`se.event_type = $${pi++}`); params.push(typeFilter); }
    if (operatorFilter) { conditions.push(`se.operator_id = $${pi++}`); params.push(operatorFilter); }

    // Solo últimas 24 horas por defecto
    conditions.push(`se.occurred_at > NOW() - INTERVAL '24 hours'`);

    const WHERE = conditions.join(' AND ');

    // Eventos con info del operador
    const evRes = await client.query(`
      SELECT
        se.id, se.event_type, se.view_name, se.action,
        se.error_message, se.duration_ms, se.severity,
        se.client_ip, se.gps_lat, se.gps_lng,
        se.payload, se.occurred_at,
        se.operator_id,
        op.email AS operator_email,
        op.full_name AS operator_name,
        op.role AS operator_role
      FROM racreaa.session_events se
      LEFT JOIN racreaa.operators op ON op.id::TEXT = se.operator_id
      WHERE ${WHERE}
      ORDER BY se.occurred_at DESC
      LIMIT $${pi}
    `, [...params, limit]);

    // Stats del día
    const statsRes = await client.query(`
      SELECT
        COUNT(*)                                               AS total,
        COUNT(CASE WHEN severity IN ('error','critical') THEN 1 END) AS errors,
        COUNT(CASE WHEN severity = 'warn' THEN 1 END)         AS warnings,
        COUNT(DISTINCT CASE WHEN event_type = 'session_start' THEN operator_id END) AS sessions
      FROM racreaa.session_events
      WHERE tenant_id = $1
        AND occurred_at > NOW() - INTERVAL '24 hours'
    `, [tenantId]);

    // Operadores únicos con actividad reciente
    const opsRes = await client.query(`
      SELECT DISTINCT se.operator_id, op.email, op.role,
        MAX(se.occurred_at) AS last_seen,
        COUNT(*) AS event_count
      FROM racreaa.session_events se
      LEFT JOIN racreaa.operators op ON op.id::TEXT = se.operator_id
      WHERE se.tenant_id = $1
        AND se.occurred_at > NOW() - INTERVAL '24 hours'
        AND se.operator_id IS NOT NULL
      GROUP BY se.operator_id, op.email, op.role
      ORDER BY last_seen DESC
    `, [tenantId]);

    // Errores de las últimas 24h en audit_logs también
    const auditErrorsRes = await client.query(`
      SELECT action, error_message, severity, client_ip, occurred_at
      FROM racreaa.audit_logs
      WHERE tenant_id = $1
        AND severity IN ('error','critical')
        AND occurred_at > NOW() - INTERVAL '24 hours'
      ORDER BY occurred_at DESC
      LIMIT 20
    `, [tenantId]);

    const stats = statsRes.rows[0];

    return res.status(200).json({
      events: evRes.rows,
      stats: {
        total:    parseInt(stats.total),
        errors:   parseInt(stats.errors),
        warnings: parseInt(stats.warnings),
        sessions: parseInt(stats.sessions),
      },
      operators:    opsRes.rows,
      audit_errors: auditErrorsRes.rows,
      generated_at: new Date().toISOString(),
    });

  } catch(err) {
    console.error('[monitor]', err.message);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
};
