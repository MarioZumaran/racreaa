const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:3 });
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin',origin); res.setHeader('Vary','Origin'); }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='GET') return res.status(405).end();
  res.setHeader('Cache-Control','public, max-age=300');
  res.setHeader('X-Content-Type-Options','nosniff');

  const slug = (req.query.slug||'').toLowerCase().trim().replace(/[^a-z0-9-]/g,'').slice(0,64);
  if (!slug) return res.status(400).json({ error:'slug requerido' });

  const client = await pool.connect();
  try {
    const r = await client.query(
      `SELECT name,brand_name,primary_color,secondary_color,logo_url,plan FROM racreaa.tenants WHERE slug=$1 AND is_active=TRUE LIMIT 1`,
      [slug]);
    if (!r.rows[0]) return res.status(404).json({ error:'Tenant no encontrado' });
    const t = r.rows[0];
    return res.status(200).json({
      name: t.name, brandName: t.brand_name||'DMZ',
      primaryColor: t.primary_color||'#B8922A', secondaryColor: t.secondary_color||'#2C2A24',
      logoUrl: t.logo_url||null, plan: t.plan,
    });
  } catch(err) {
    console.error('[branding]', err.message);
    return res.status(500).json({ error:'Error interno' });
  } finally { client.release(); }
};
