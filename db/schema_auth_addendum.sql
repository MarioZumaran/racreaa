-- =============================================================================
-- RACREAA — Schema Addendum: Auth Tables
-- Agregar al schema.sql existente (después de la tabla operators)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- TABLA: refresh_tokens
-- Persiste los Refresh Tokens (hasheados) para invalidación y detección de robo
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS racreaa.refresh_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id     UUID NOT NULL REFERENCES racreaa.operators(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL REFERENCES racreaa.tenants(id)   ON DELETE CASCADE,
  token_hash      CHAR(64) NOT NULL UNIQUE,   -- SHA-256 del token raw
  jti             UUID,                        -- JWT ID del access token emitido
  client_ip       INET,
  user_agent      TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,                -- NULL = activo
  reuse_detected  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rt_operator   ON racreaa.refresh_tokens (operator_id);
CREATE INDEX idx_rt_tenant     ON racreaa.refresh_tokens (tenant_id);
CREATE INDEX idx_rt_hash       ON racreaa.refresh_tokens (token_hash);
CREATE INDEX idx_rt_expires    ON racreaa.refresh_tokens (expires_at);
CREATE INDEX idx_rt_active     ON racreaa.refresh_tokens (operator_id) WHERE revoked_at IS NULL;

-- RLS en refresh_tokens
ALTER TABLE racreaa.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE racreaa.refresh_tokens FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_rt
  ON racreaa.refresh_tokens
  USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id', TRUE)::UUID);

-- Permisos
GRANT SELECT, INSERT, UPDATE ON racreaa.refresh_tokens TO racreaa_app;

-- Job de limpieza — ejecutar diariamente via pg_cron o cron externo
-- DELETE FROM racreaa.refresh_tokens WHERE expires_at < NOW() - INTERVAL '30 days';

COMMENT ON TABLE racreaa.refresh_tokens IS
  'Refresh Tokens hasheados con SHA-256. El token raw NUNCA se persiste. '
  'reuse_detected = TRUE indica posible robo — todos los tokens del operador fueron revocados.';

-- ---------------------------------------------------------------------------
-- FUNCIÓN AUXILIAR: Crear operador con password hasheado
-- Usar desde scripts de seeding, nunca exponer como endpoint público
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION racreaa.create_operator(
  p_tenant_id  UUID,
  p_email      TEXT,
  p_full_name  TEXT,
  p_password   TEXT,
  p_role       TEXT DEFAULT 'auditor'
)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_hash TEXT;
  v_id   UUID;
BEGIN
  -- bcrypt con cost factor 12 (usar pgcrypto)
  v_hash := crypt(p_password, gen_salt('bf', 12));
  INSERT INTO racreaa.operators (tenant_id, email, full_name, password_hash, role)
  VALUES (p_tenant_id, lower(trim(p_email)), p_full_name, v_hash, p_role)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

COMMENT ON FUNCTION racreaa.create_operator IS
  'Crea un operador con password hasheado via bcrypt (cost=12). '
  'Solo usar desde scripts de administración con acceso directo a DB.';

-- Ejemplo de uso (NO ejecutar en producción sin reemplazar datos):
-- SELECT racreaa.create_operator(
--   '00000000-0000-0000-0000-000000000001',
--   'mario@dmzkitchensupport.com',
--   'Mario De La Mora',
--   'SuperSecurePassword2026!',
--   'admin'
-- );
