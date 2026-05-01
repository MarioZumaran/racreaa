/**
 * /api/telemetry.js — RACREAA Session Monitoring
 * Recibe eventos del frontend (errores, acciones, navegación)
 * y los persiste en session_events para análisis.
 * Endpoint ligero — no bloquea la UI, fire-and-forget desde el cliente.
 */
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:3 });
const JWT_SECRET      = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim()),
  'https://mariozumaran.github.io',
  'https://dmz-audit.netlify.app',
  'https://racreaa.vercel.app',
].filter(Boolean);

function tryVerify(h) {
  if (!h?.startsWith('Bearer ')) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET); } catch { return null; }
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).end();
  res.setHeader('Cache-Control','no-store');

  // Responder inmediatamente — no bloquear el cliente
  res.status(202).json({ ok: true });

  // Procesar en background
  setImmediate(async () => {
    try {
      const claims = tryVerify(req.headers.authorization);
      const body   = req.body || {};
      const ip     = (req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
      const ua     = req.headers['user-agent']||'';

      const events = Array.isArray(body) ? body : [body];

      for (const ev of events.slice(0, 20)) { // máx 20 eventos por batch
        const severity = ev.severity || (ev.event_type === 'error' ? 'error' : 'info');

        await pool.query(`
          INSERT INTO racreaa.session_events
            (tenant_id, operator_id, session_token, event_type, view_name,
             action, payload, error_message, duration_ms, severity,
             client_ip, user_agent, gps_lat, gps_lng, occurred_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        `, [
          claims?.tenant_id || ev.tenant_id || null,
          claims?.sub       || ev.operator_id || null,
          ev.session_token  || null,
          ev.event_type     || 'unknown',
          ev.view_name      || null,
          ev.action         || null,
          ev.payload        ? JSON.stringify(ev.payload) : null,
          ev.error_message  || null,
          ev.duration_ms    || null,
          severity,
          ip, ua,
          ev.gps?.lat || null,
          ev.gps?.lng || null,
          ev.occurred_at ? new Date(ev.occurred_at) : new Date(),
        ]);

        // Si es error crítico → también registrar en audit_logs
        if (severity === 'error' || severity === 'critical') {
          await pool.query(`
            INSERT INTO racreaa.audit_logs
              (id, tenant_id, operator_id, action, entity_type,
               client_ip, user_agent, error_message, severity, payload_hash, occurred_at)
            VALUES (gen_random_uuid(),$1,$2,$3,'session',$4,$5,$6,$7,$8,NOW())
          `, [
            claims?.tenant_id || null,
            claims?.sub || null,
            `CLIENT_ERROR:${ev.event_type}`,
            ip, ua,
            ev.error_message || '',
            severity,
            require('crypto').createHash('sha256').update(JSON.stringify(ev)).digest('hex')
          ]);
        }
      }
    } catch (err) {
      // Silencioso — telemetría nunca debe crashear el sistema
      console.error('[telemetry]', err.message);
    }
  });
};
