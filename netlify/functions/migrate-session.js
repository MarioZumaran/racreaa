/**
 * migrate-session.js — ONE-TIME migration: creates audit_sessions table
 * Call once: GET /api/migrate-session?token=DMZracreaa2026!
 * Remove after execution.
 */
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true } });

module.exports = async function handler(req, res) {
  if (req.query.token !== 'DMZracreaa2026!') return res.status(403).json({ error: 'Forbidden' });

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS racreaa.audit_sessions (
        id               TEXT PRIMARY KEY,
        tenant_id        UUID NOT NULL REFERENCES racreaa.tenants(id),
        host_operator_id TEXT NOT NULL,
        session_code     TEXT NOT NULL UNIQUE,
        establecimiento  TEXT NOT NULL DEFAULT '',
        fecha            DATE,
        servicio         TEXT DEFAULT '',
        status           TEXT NOT NULL DEFAULT 'open',
        section_locks    JSONB NOT NULL DEFAULT '{}',
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '4 hours')
      );
      CREATE INDEX IF NOT EXISTS idx_audit_sessions_code   ON racreaa.audit_sessions(session_code);
      CREATE INDEX IF NOT EXISTS idx_audit_sessions_tenant ON racreaa.audit_sessions(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_audit_sessions_status ON racreaa.audit_sessions(status);
    `);
    res.status(200).json({ ok: true, message: 'audit_sessions created' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
};
