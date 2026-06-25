CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  first_name text NULL,
  last_name text NULL,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'administrator')),
  mfa_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS integration_settings (
  id integer PRIMARY KEY DEFAULT 1,
  smtp_enabled boolean NOT NULL DEFAULT false,
  smtp_host text NULL,
  smtp_port integer NULL,
  smtp_username text NULL,
  smtp_password text NULL,
  smtp_from text NULL,
  graph_enabled boolean NOT NULL DEFAULT false,
  graph_tenant_id text NULL,
  graph_client_id text NULL,
  graph_client_secret text NULL,
  graph_sender text NULL,
  microsoft_enabled boolean NOT NULL DEFAULT false,
  microsoft_tenant_id text NULL,
  microsoft_client_id text NULL,
  microsoft_audience text NULL,
  microsoft_authority text NULL,
  microsoft_admin_group text NULL,
  microsoft_user_group text NULL,
  ad_enabled boolean NOT NULL DEFAULT false,
  ad_host text NULL,
  ad_base_dn text NULL,
  ad_bind_dn text NULL,
  branding_logo_url text NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS companies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS company_users (
  company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (company_id, user_id)
);

CREATE TABLE IF NOT EXISTS enrollment_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz NULL,
  created_by uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name text NULL,
  hostname text NOT NULL,
  opnsense_version text NULL,
  plugin_version text NULL,
  wg_public_key text NOT NULL,
  wg_tunnel_ip inet NOT NULL UNIQUE,
  device_token_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  health_missed_checks integer NOT NULL DEFAULT 0,
  health_success_checks integer NOT NULL DEFAULT 0,
  last_seen_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  message text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  company_id uuid NULL REFERENCES companies(id) ON DELETE SET NULL,
  device_id uuid NULL REFERENCES devices(id) ON DELETE SET NULL,
  action text NOT NULL,
  ip_address inet NULL,
  user_agent text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_devices_company ON devices(company_id);
CREATE INDEX IF NOT EXISTS idx_audit_company ON audit_logs(company_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_company ON enrollment_codes(company_id);
