const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:5 });
const JWT_SECRET      = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim()),
  'https://mariozumaran.github.io',
  'https://dmz-audit.netlify.app',
  'https://racreaa.vercel.app',
].filter(Boolean);

function verifyToken(h) {
  if (!h?.startsWith('Bearer ')) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET); }
  catch { return null; }
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin',origin); res.setHeader('Vary','Origin'); }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='GET')    return res.status(405).end();
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');

  const claims = verifyToken(req.headers.authorization);
  const tenantSlug = req.query.tenant || (claims?.tenant_slug) || 'dmz';
  const limit = Math.min(parseInt(req.query.limit||'50'), 200);
  const offset = parseInt(req.query.offset||'0');

  const client = await pool.connect();
  try {
    // Obtener tenant_id del slug
    const tRes = await client.query(`SELECT id FROM racreaa.tenants WHERE slug=$1 AND is_active=TRUE LIMIT 1`,[tenantSlug]);
    if (!tRes.rows[0]) return res.status(404).json({ error:'Tenant no encontrado' });
    const tenantId = tRes.rows[0].id;

    // Auditorías con conteo de items
    const aRes = await client.query(`
      SELECT a.id, a.establecimiento, a.auditor_name, a.audit_date, a.service_period,
             a.global_score, a.conclusion, a.gps_lat, a.gps_lng,
             a.server_timestamp, a.status,
             COUNT(i.id) AS item_count
      FROM racreaa.audits a
      LEFT JOIN racreaa.audit_items i ON i.audit_id = a.id
      WHERE a.tenant_id = $1
      GROUP BY a.id
      ORDER BY a.server_timestamp DESC
      LIMIT $2 OFFSET $3
    `, [tenantId, limit, offset]);

    // Totales
    const totRes = await client.query(`SELECT COUNT(*) as total, ROUND(AVG(global_score),1) as avg FROM racreaa.audits WHERE tenant_id=$1`,[tenantId]);
    const tot = totRes.rows[0];

    // Distribución
    const distRes = await client.query(`
      SELECT
        COUNT(CASE WHEN global_score >= 85 THEN 1 END) as excelente,
        COUNT(CASE WHEN global_score >= 70 AND global_score < 85 THEN 1 END) as bueno,
        COUNT(CASE WHEN global_score >= 55 AND global_score < 70 THEN 1 END) as regular,
        COUNT(CASE WHEN global_score >= 40 AND global_score < 55 THEN 1 END) as deficiente,
        COUNT(CASE WHEN global_score < 40 THEN 1 END) as critico
      FROM racreaa.audits WHERE tenant_id=$1
    `,[tenantId]);
    const dist = distRes.rows[0];

    return res.status(200).json({
      audits: aRes.rows,
      total:  parseInt(tot.total)||0,
      avg:    parseFloat(tot.avg)||0,
      counts: {
        excelente: parseInt(dist.excelente)||0,
        bueno:     parseInt(dist.bueno)||0,
        regular:   parseInt(dist.regular)||0,
        deficiente:parseInt(dist.deficiente)||0,
        critico:   parseInt(dist.critico)||0,
      }
    });
  } catch(err) {
    console.error('[audits]', err.message);
    return res.status(500).json({ error:'Error interno' });
  } finally { client.release(); }
};
