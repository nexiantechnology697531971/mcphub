import { Pool } from "pg";

const globalForPg = globalThis as typeof globalThis & {
  pgPool?: Pool;
};

export const pool =
  globalForPg.pgPool ??
  new Pool({
    connectionString:
      process.env.DATABASE_URL ??
      "postgresql://postgres:postgres@localhost:5432/nexian_mcp_hub"
  });

if (process.env.NODE_ENV !== "production") {
  globalForPg.pgPool = pool;
}

let schemaReadyPromise: Promise<void> | undefined;

async function addColumnIfMissing(tableName: string, columnName: string, definition: string) {
  await pool.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS ${columnName} ${definition};`);
}

export async function ensureDatabaseSchema() {
  if (!schemaReadyPromise) {
    schemaReadyPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS tenants (
          id TEXT PRIMARY KEY,
          slug TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await addColumnIfMissing("tenants", "tenant_type", "TEXT NOT NULL DEFAULT 'CUSTOMER'");
      await addColumnIfMissing("tenants", "status", "TEXT NOT NULL DEFAULT 'ACTIVE'");
      await addColumnIfMissing("tenants", "plan", "TEXT NOT NULL DEFAULT 'Professional'");
      await addColumnIfMissing("tenants", "vertical", "TEXT NULL");
      await addColumnIfMissing("tenants", "region", "TEXT NULL");
      await addColumnIfMissing("tenants", "parent_tenant_id", "TEXT NULL");
      await addColumnIfMissing("tenants", "branding_json", "JSONB NULL");

      await pool.query(`
        CREATE INDEX IF NOT EXISTS tenants_parent_idx
        ON tenants (parent_tenant_id);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS platform_users (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          display_name TEXT NOT NULL,
          role TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await addColumnIfMissing("platform_users", "status", "TEXT NOT NULL DEFAULT 'ACTIVE'");
      await addColumnIfMissing("platform_users", "last_active_at", "TIMESTAMPTZ NULL");
      await addColumnIfMissing("platform_users", "platform_role", "TEXT NOT NULL DEFAULT 'PLATFORM_MEMBER'");

      await pool.query(`
        UPDATE platform_users pu
        SET platform_role = CASE
          WHEN t.tenant_type = 'MSP' THEN 'PLATFORM_OWNER'
          ELSE 'PLATFORM_MEMBER'
        END
        FROM tenants t
        WHERE pu.tenant_id = t.id
          AND (pu.platform_role IS NULL OR pu.platform_role = '' OR pu.platform_role = 'OWNER' OR pu.platform_role = 'ADMIN' OR pu.platform_role = 'ANALYST' OR pu.platform_role = 'USER');
      `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS platform_users_tenant_idx
    ON platform_users (tenant_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenant_memberships (
      user_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, tenant_id)
    );
  `);

  await pool.query(`
    INSERT INTO tenant_memberships (user_id, tenant_id, role)
    SELECT id, tenant_id, role
    FROM platform_users
    ON CONFLICT (user_id, tenant_id) DO NOTHING;
  `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
          code TEXT PRIMARY KEY,
          client_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tenant_id TEXT NOT NULL,
          redirect_uri TEXT NOT NULL,
          scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          code_challenge TEXT NULL,
          code_challenge_method TEXT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          consumed_at TIMESTAMPTZ NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS oauth_authorization_codes_user_idx
        ON oauth_authorization_codes (user_id, tenant_id);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS oauth_clients (
          client_id TEXT PRIMARY KEY,
          client_secret_hash TEXT NOT NULL,
          redirect_uris TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          grant_types TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          response_types TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
          client_name TEXT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS connected_accounts (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          provider TEXT NOT NULL,
          provider_account_id TEXT NULL,
          access_token_encrypted TEXT NOT NULL,
          refresh_token_encrypted TEXT NULL,
          expires_at TIMESTAMPTZ NULL,
          scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          metadata_json JSONB NULL,
          status TEXT NOT NULL,
          last_error TEXT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS connected_accounts_tenant_user_provider_key
        ON connected_accounts (tenant_id, user_id, provider);
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS connected_accounts_tenant_user_idx
        ON connected_accounts (tenant_id, user_id);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS connector_configs (
          tenant_id TEXT NOT NULL,
          provider TEXT NOT NULL,
          config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (tenant_id, provider)
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS connector_configs_tenant_idx
        ON connector_configs (tenant_id);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS audit_events (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          user_id TEXT NULL,
          action TEXT NOT NULL,
          target_type TEXT NOT NULL,
          target_id TEXT NULL,
          metadata_json JSONB NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS audit_events_tenant_created_idx
        ON audit_events (tenant_id, created_at DESC);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS modules (
          id TEXT PRIMARY KEY,
          slug TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          description TEXT NULL,
          enabled_by_default BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS module_connectors (
          provider TEXT PRIMARY KEY,
          module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS module_connectors_module_idx
        ON module_connectors (module_id);
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS tenant_modules (
          tenant_id TEXT NOT NULL,
          module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
          enabled BOOLEAN NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (tenant_id, module_id)
        );
      `);

      await pool.query(`
        CREATE INDEX IF NOT EXISTS tenant_modules_tenant_idx
        ON tenant_modules (tenant_id);
      `);

      await pool.query(`
        INSERT INTO modules (id, slug, name, description, enabled_by_default)
        VALUES
          ('mod_msp', 'msp', 'MSP', 'Managed service provider tooling: PSA, RMM, M365 tenancy.', TRUE),
          ('mod_legal', 'legal', 'Legal', 'Legal practice management: ActionStep, SharePoint matters.', FALSE),
          ('mod_workflow', 'workflow', 'Workflow', 'Workflow automation tooling (n8n, internal automations).', TRUE),
          ('mod_microsoft365', 'microsoft365', 'Microsoft 365', 'SharePoint, OneDrive, Exchange tooling.', TRUE)
        ON CONFLICT (id) DO NOTHING;
      `);

      await pool.query(`
        INSERT INTO module_connectors (provider, module_id)
        VALUES
          ('halopsa', 'mod_msp'),
          ('ninjaone', 'mod_msp'),
          ('cipp', 'mod_msp'),
          ('itglue', 'mod_msp'),
          ('actionstep', 'mod_legal'),
          ('n8n', 'mod_workflow'),
          ('microsoft365', 'mod_microsoft365'),
          ('hubspot', 'mod_workflow')
        ON CONFLICT (provider) DO NOTHING;
      `);
    })();
  }

  await schemaReadyPromise;
}
