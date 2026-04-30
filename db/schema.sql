-- =============================================================================
-- RACREAA — PostgreSQL Schema v1.0
-- Multi-Tenant, Row-Level Security, Audit Trail Inmutable
-- Compatible: PostgreSQL 15+ (Neon, Supabase, Railway, AWS RDS)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- EXTENSIONES
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- gen_random_uuid(), crypt()
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- monitoreo de queries
CREATE EXTENSION IF NOT EXISTS "btree_gist";     -- índices GiST para rangos

-- ---------------------------------------------------------------------------
-- SCHEMA AISLADO POR APLICACIÓN
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS racreaa;
SET search_path TO racreaa, public;

-- ---------------------------------------------------------------------------
-- ROLES DE BASE DE DATOS
-- Principio de mínimo privilegio — el app nunca usa el rol superuser
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  -- Rol de la aplicación (Vercel Functions)
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'racreaa_app') THEN
    CREATE ROLE racreaa_app LOGIN PASSWORD '${REPLACE_IN_PRODUCTION}';
  END IF;
  -- Rol de solo lectura para reporting
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'racreaa_readonly') THEN
    CREATE ROLE racreaa_readonly LOGIN PASSWORD '${REPLACE_IN_PRODUCTION}';
  END IF;
  -- Rol de auditoría — solo puede leer audit_logs
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'racreaa_auditor') THEN
    CREATE ROLE racreaa_auditor LOGIN PASSWORD '${REPLACE_IN_PRODUCTION}';
  END IF;
END $$;

GRANT USAGE ON SCHEMA racreaa TO racreaa_app, racreaa_readonly, racreaa_auditor;

-- ---------------------------------------------------------------------------
-- TABLA: tenants
-- Registro maestro de clientes B2B
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.tenants (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug            TEXT NOT NULL UNIQUE,          -- e.g. "nook-aruba"
  name            TEXT NOT NULL,
  brand_name      TEXT,                          -- nombre en el header
  primary_color   CHAR(7) DEFAULT '#B8922A',     -- hex color
  secondary_color CHAR(7) DEFAULT '#2C2A24',
  logo_url        TEXT,
  plan            TEXT NOT NULL DEFAULT 'starter' CHECK (plan IN ('starter','pro','enterprise')),
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON racreaa.tenants (slug);

-- ---------------------------------------------------------------------------
-- TABLA: operators
-- Usuarios operativos (auditores) vinculados a un tenant
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.operators (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES racreaa.tenants(id) ON DELETE CASCADE,
  email           TEXT NOT NULL UNIQUE,
  full_name       TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'auditor' CHECK (role IN ('admin','supervisor','auditor')),
  password_hash   TEXT NOT NULL,                 -- bcrypt hash — nunca plaintext
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_operators_tenant  ON racreaa.operators (tenant_id);
CREATE INDEX idx_operators_email   ON racreaa.operators (email);

-- ---------------------------------------------------------------------------
-- TABLA: audits
-- Registro maestro de cada auditoría de calificación de alimentos
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.audits (
  id                    TEXT PRIMARY KEY,                -- AUD-XXXXX
  tenant_id             UUID NOT NULL REFERENCES racreaa.tenants(id) ON DELETE RESTRICT,
  operator_id           TEXT NOT NULL,                  -- UUID o session token
  establecimiento       TEXT,
  auditor_name          TEXT,
  audit_date            DATE,
  service_period        TEXT,                            -- Desayuno/Comida/Cena
  global_score          SMALLINT CHECK (global_score BETWEEN 0 AND 100),
  conclusion            TEXT,
  auditor_firma         TEXT,
  chef_firma            TEXT,
  signature_image       TEXT,                           -- data URL del canvas

  -- Geolocalización del envío
  gps_lat               DOUBLE PRECISION,
  gps_lng               DOUBLE PRECISION,
  gps_accuracy          REAL,

  -- Metadatos de red y sesión
  client_gps_header     TEXT,
  client_ip             INET,
  user_agent            TEXT,
  session_token         TEXT,
  request_id            TEXT UNIQUE,

  -- Timestamps duales (cliente + servidor autoritativo)
  client_submitted_at   TIMESTAMPTZ,
  server_timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Estado del registro
  status                TEXT NOT NULL DEFAULT 'submitted'
                          CHECK (status IN ('submitted','reviewed','archived')),
  reviewed_by           UUID REFERENCES racreaa.operators(id),
  reviewed_at           TIMESTAMPTZ
)
PARTITION BY LIST (tenant_id);  -- Particionado físico por tenant

-- Índices en la tabla padre (se heredan en particiones)
CREATE INDEX idx_audits_tenant       ON racreaa.audits (tenant_id);
CREATE INDEX idx_audits_date         ON racreaa.audits (audit_date);
CREATE INDEX idx_audits_score        ON racreaa.audits (global_score);
CREATE INDEX idx_audits_server_ts    ON racreaa.audits (server_timestamp);

-- ---------------------------------------------------------------------------
-- TABLA: audit_items
-- Ítems individuales de cada auditoría (un platillo por registro)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.audit_items (
  id                  TEXT PRIMARY KEY,
  audit_id            TEXT NOT NULL REFERENCES racreaa.audits(id) ON DELETE CASCADE,
  tenant_id           UUID NOT NULL,
  item_num            SMALLINT NOT NULL,
  nombre              TEXT,
  categoria           TEXT,
  score               SMALLINT CHECK (score BETWEEN 0 AND 100),
  nivel               TEXT CHECK (nivel IN ('critico','deficiente','regular','bueno','excelente')),
  observaciones       TEXT,

  -- Criterios individuales (1-5)
  crit_presentacion   SMALLINT CHECK (crit_presentacion BETWEEN 0 AND 5),
  crit_temperatura    SMALLINT CHECK (crit_temperatura  BETWEEN 0 AND 5),
  crit_sabor          SMALLINT CHECK (crit_sabor         BETWEEN 0 AND 5),
  crit_textura        SMALLINT CHECK (crit_textura       BETWEEN 0 AND 5),
  crit_porcion        SMALLINT CHECK (crit_porcion       BETWEEN 0 AND 5),

  server_timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_items_audit    ON racreaa.audit_items (audit_id);
CREATE INDEX idx_items_tenant   ON racreaa.audit_items (tenant_id);
CREATE INDEX idx_items_nivel    ON racreaa.audit_items (nivel);

-- ---------------------------------------------------------------------------
-- TABLA: audit_evidence
-- Evidencia fotográfica con certificado de autenticidad
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.audit_evidence (
  id                  TEXT PRIMARY KEY,
  audit_id            TEXT NOT NULL REFERENCES racreaa.audits(id) ON DELETE CASCADE,
  audit_item_id       TEXT REFERENCES racreaa.audit_items(id) ON DELETE SET NULL,
  tenant_id           UUID NOT NULL,

  blob_url            TEXT NOT NULL,             -- URL de Vercel Blob (privada)
  mime_type           TEXT,
  size_bytes          INTEGER,

  -- Geolocalización de la captura
  gps_lat             DOUBLE PRECISION,
  gps_lng             DOUBLE PRECISION,
  gps_verified        BOOLEAN NOT NULL DEFAULT FALSE,

  captured_at_client  TIMESTAMPTZ,              -- timestamp del dispositivo
  server_timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- autoritativo

  operator_id         TEXT,
  integrity_hash      CHAR(64),                 -- SHA-256 del certificado de autenticidad

  CONSTRAINT uq_evidence_hash UNIQUE (integrity_hash)
);

CREATE INDEX idx_evidence_audit  ON racreaa.audit_evidence (audit_id);
CREATE INDEX idx_evidence_tenant ON racreaa.audit_evidence (tenant_id);

-- ---------------------------------------------------------------------------
-- TABLA: audit_logs  ★ INMUTABLE ★
-- Audit trail transaccional — solo INSERT, nunca UPDATE ni DELETE
-- Se implementa con una Row Security Policy y revocación de privilegios
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.audit_logs (
  id              UUID NOT NULL DEFAULT gen_random_uuid(),
  tenant_id       UUID,
  operator_id     TEXT,
  audit_id        TEXT,
  action          TEXT NOT NULL,                -- 'AUDIT_SUBMITTED', 'LOGIN', etc.
  entity_type     TEXT,
  entity_id       TEXT,
  client_ip       INET,
  user_agent      TEXT,
  request_id      TEXT,
  gps_lat         DOUBLE PRECISION,
  gps_lng         DOUBLE PRECISION,
  payload_hash    CHAR(64),                     -- SHA-256 del contexto del evento
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Clave primaria compuesta con timestamp para evitar colisiones
  PRIMARY KEY (id, occurred_at)
)
-- Particionado por rango de tiempo para archivado eficiente
PARTITION BY RANGE (occurred_at);

-- Particiones mensuales (crear via cron mensual o manualmente)
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_01
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_02
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_03
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_04
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_05
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_06
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_07
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_08
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_09
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_10
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_11
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS racreaa.audit_logs_2026_12
  PARTITION OF racreaa.audit_logs FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE INDEX idx_logs_tenant     ON racreaa.audit_logs (tenant_id);
CREATE INDEX idx_logs_operator   ON racreaa.audit_logs (operator_id);
CREATE INDEX idx_logs_audit_id   ON racreaa.audit_logs (audit_id);
CREATE INDEX idx_logs_action     ON racreaa.audit_logs (action);
CREATE INDEX idx_logs_occurred   ON racreaa.audit_logs (occurred_at DESC);

-- ---------------------------------------------------------------------------
-- INMUTABILIDAD DE audit_logs
-- Revocar UPDATE y DELETE sobre la tabla de logs para todos los roles
-- El trigger también bloquea cualquier intento a nivel de motor
-- ---------------------------------------------------------------------------
REVOKE UPDATE, DELETE, TRUNCATE ON racreaa.audit_logs FROM racreaa_app;
REVOKE UPDATE, DELETE, TRUNCATE ON racreaa.audit_logs FROM racreaa_readonly;
REVOKE UPDATE, DELETE, TRUNCATE ON racreaa.audit_logs FROM racreaa_auditor;
-- Solo el rol superuser puede borrar (para cumplimiento GDPR con proceso auditado)

CREATE OR REPLACE FUNCTION racreaa.prevent_log_modification()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RAISE EXCEPTION 'SECURITY VIOLATION: audit_logs es una tabla de solo escritura. '
    'Operación: % en fila: % — Acción bloqueada y registrada.', TG_OP, OLD.id;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_immutable_logs
  BEFORE UPDATE OR DELETE ON racreaa.audit_logs
  FOR EACH ROW EXECUTE FUNCTION racreaa.prevent_log_modification();

-- ---------------------------------------------------------------------------
-- ROW-LEVEL SECURITY (RLS) — AISLAMIENTO MULTI-TENANT
-- Cada consulta solo accede a datos de su propio tenant_id
-- El app debe hacer SET LOCAL app.current_tenant_id = '<uuid>' antes de queries
-- ---------------------------------------------------------------------------

-- Habilitar RLS en todas las tablas operativas
ALTER TABLE racreaa.audits         ENABLE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_items    ENABLE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_logs     ENABLE ROW LEVEL SECURITY;
ALTER TABLE racreaa.operators      ENABLE ROW LEVEL SECURITY;

-- FORZAR RLS incluso para el propietario de la tabla (FORCE)
ALTER TABLE racreaa.audits         FORCE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_items    FORCE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE racreaa.audit_logs     FORCE ROW LEVEL SECURITY;
ALTER TABLE racreaa.operators      FORCE ROW LEVEL SECURITY;

-- Políticas RLS: audits
CREATE POLICY tenant_isolation_audits
  ON racreaa.audits
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- Políticas RLS: audit_items
CREATE POLICY tenant_isolation_items
  ON racreaa.audit_items
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- Políticas RLS: audit_evidence
CREATE POLICY tenant_isolation_evidence
  ON racreaa.audit_evidence
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- Políticas RLS: audit_logs (solo lectura filtrada por tenant)
CREATE POLICY tenant_isolation_logs
  ON racreaa.audit_logs
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- Políticas RLS: operators
CREATE POLICY tenant_isolation_operators
  ON racreaa.operators
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- ---------------------------------------------------------------------------
-- PERMISOS POR ROL
-- ---------------------------------------------------------------------------

-- racreaa_app: CRUD operativo (sin DELETE en audits y logs)
GRANT SELECT, INSERT, UPDATE ON racreaa.tenants        TO racreaa_app;
GRANT SELECT, INSERT, UPDATE ON racreaa.operators      TO racreaa_app;
GRANT SELECT, INSERT, UPDATE ON racreaa.audits         TO racreaa_app;
GRANT SELECT, INSERT         ON racreaa.audit_items    TO racreaa_app;
GRANT SELECT, INSERT         ON racreaa.audit_evidence TO racreaa_app;
GRANT SELECT, INSERT         ON racreaa.audit_logs     TO racreaa_app;

-- racreaa_readonly: solo SELECT para reporting y dashboards
GRANT SELECT ON racreaa.audits, racreaa.audit_items, racreaa.audit_evidence, racreaa.tenants TO racreaa_readonly;

-- racreaa_auditor: solo puede leer audit_logs (compliance)
GRANT SELECT ON racreaa.audit_logs TO racreaa_auditor;

-- ---------------------------------------------------------------------------
-- FUNCIÓN: Crear partición de tenant en audits
-- Llamar una vez por cada nuevo tenant registrado
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION racreaa.create_tenant_partition(p_tenant_id UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
  partition_name TEXT;
BEGIN
  partition_name := 'audits_tenant_' || replace(p_tenant_id::TEXT, '-', '_');
  EXECUTE format(
    'CREATE TABLE IF NOT EXISTS racreaa.%I
     PARTITION OF racreaa.audits
     FOR VALUES IN (%L)',
    partition_name,
    p_tenant_id
  );
  RAISE NOTICE 'Partición creada: %', partition_name;
END;
$$;

-- ---------------------------------------------------------------------------
-- TRIGGER: updated_at automático
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION racreaa.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW(); RETURN NEW;
END;
$$;

CREATE TRIGGER trg_tenants_updated_at
  BEFORE UPDATE ON racreaa.tenants
  FOR EACH ROW EXECUTE FUNCTION racreaa.set_updated_at();

-- ---------------------------------------------------------------------------
-- VISTA MATERIALIZADA: Resumen de auditorías por tenant (para dashboard)
-- Refrescar: SELECT racreaa.refresh_audit_summary();
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS racreaa.mv_audit_summary AS
SELECT
  a.tenant_id,
  t.name                                    AS tenant_name,
  COUNT(DISTINCT a.id)                      AS total_audits,
  ROUND(AVG(a.global_score), 1)             AS avg_global_score,
  COUNT(CASE WHEN a.global_score >= 85 THEN 1 END) AS count_excelente,
  COUNT(CASE WHEN a.global_score >= 70 AND a.global_score < 85 THEN 1 END) AS count_bueno,
  COUNT(CASE WHEN a.global_score >= 55 AND a.global_score < 70 THEN 1 END) AS count_regular,
  COUNT(CASE WHEN a.global_score >= 40 AND a.global_score < 55 THEN 1 END) AS count_deficiente,
  COUNT(CASE WHEN a.global_score  < 40 THEN 1 END) AS count_critico,
  MIN(a.global_score)                       AS min_score,
  MAX(a.global_score)                       AS max_score,
  MAX(a.server_timestamp)                   AS last_audit_at
FROM racreaa.audits a
JOIN racreaa.tenants t ON t.id = a.tenant_id
GROUP BY a.tenant_id, t.name
WITH NO DATA;

CREATE UNIQUE INDEX idx_mv_summary_tenant ON racreaa.mv_audit_summary (tenant_id);

CREATE OR REPLACE FUNCTION racreaa.refresh_audit_summary()
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY racreaa.mv_audit_summary;
END;
$$;

-- ---------------------------------------------------------------------------
-- DATOS INICIALES — TENANT DEMO
-- ---------------------------------------------------------------------------
INSERT INTO racreaa.tenants (id, slug, name, brand_name, plan)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'demo',
  'DMZ Kitchen Support (Demo)',
  'DMZ',
  'enterprise'
) ON CONFLICT (slug) DO NOTHING;

-- Crear partición para el tenant demo
SELECT racreaa.create_tenant_partition('00000000-0000-0000-0000-000000000001');

-- ---------------------------------------------------------------------------
-- COMENTARIOS DE DOCUMENTACIÓN
-- ---------------------------------------------------------------------------
COMMENT ON TABLE racreaa.audit_logs    IS 'Tabla inmutable de audit trail. INSERT only. UPDATE/DELETE bloqueados por trigger y revocación de permisos.';
COMMENT ON TABLE racreaa.audits        IS 'Particionada por tenant_id. Cada tenant tiene su propia partición física.';
COMMENT ON COLUMN racreaa.audits.server_timestamp IS 'Timestamp autoritativo del servidor. Nunca modificable por el cliente.';
COMMENT ON COLUMN racreaa.audit_evidence.integrity_hash IS 'SHA-256 de {blobUrl, capturedAt, gps, operatorId}. Certificado de autenticidad de la evidencia.';
