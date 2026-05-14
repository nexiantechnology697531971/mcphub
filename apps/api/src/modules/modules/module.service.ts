import crypto from "node:crypto";

import { ensureDatabaseSchema, pool } from "../../common/db/postgres";
import type { AuditService } from "../audit/audit.service";

type ModuleRow = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  enabled_by_default: boolean;
  created_at: Date;
  updated_at: Date;
};

type ModuleConnectorRow = {
  provider: string;
  module_id: string;
};

type TenantModuleRow = {
  tenant_id: string;
  module_id: string;
  enabled: boolean;
  updated_at: Date;
};

export interface ModuleRecord {
  id: string;
  slug: string;
  name: string;
  description?: string;
  enabledByDefault: boolean;
  connectors: string[];
  createdAt: string;
  updatedAt: string;
}

export interface TenantModuleAssignment {
  moduleId: string;
  slug: string;
  name: string;
  description?: string;
  enabled: boolean;
  enabledByDefault: boolean;
  connectors: string[];
  isOverride: boolean;
}

function toDomain(row: ModuleRow, connectors: string[]): ModuleRecord {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    description: row.description ?? undefined,
    enabledByDefault: row.enabled_by_default,
    connectors,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString()
  };
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export class ModuleService {
  private readonly ready = ensureDatabaseSchema();

  constructor(private readonly auditService: AuditService) {}

  async listModules(): Promise<ModuleRecord[]> {
    await this.ready;

    const [modulesResult, connectorsResult] = await Promise.all([
      pool.query<ModuleRow>("SELECT * FROM modules ORDER BY name ASC"),
      pool.query<ModuleConnectorRow>("SELECT provider, module_id FROM module_connectors")
    ]);

    const connectorsByModule = new Map<string, string[]>();
    for (const row of connectorsResult.rows) {
      const list = connectorsByModule.get(row.module_id) ?? [];
      list.push(row.provider);
      connectorsByModule.set(row.module_id, list);
    }

    return modulesResult.rows.map((row) => toDomain(row, connectorsByModule.get(row.id) ?? []));
  }

  async getModule(id: string): Promise<ModuleRecord | undefined> {
    await this.ready;

    const result = await pool.query<ModuleRow>("SELECT * FROM modules WHERE id = $1 LIMIT 1", [id]);
    const row = result.rows[0];
    if (!row) return undefined;

    const connectorsResult = await pool.query<ModuleConnectorRow>(
      "SELECT provider, module_id FROM module_connectors WHERE module_id = $1",
      [id]
    );
    return toDomain(row, connectorsResult.rows.map((c) => c.provider));
  }

  async createModule(input: {
    actorTenantId: string;
    actorUserId: string;
    name: string;
    description?: string;
    enabledByDefault?: boolean;
    slug?: string;
  }): Promise<ModuleRecord> {
    await this.ready;

    const name = input.name.trim();
    if (!name) throw new Error("Module name is required");

    const slug = (input.slug ?? slugify(name)) || slugify(name);
    if (!slug) throw new Error("Could not derive a slug from the module name");

    const id = `mod_${crypto.randomBytes(6).toString("hex")}`;
    const description = input.description?.trim() || null;
    const enabledByDefault = input.enabledByDefault ?? true;

    const result = await pool.query<ModuleRow>(
      `
        INSERT INTO modules (id, slug, name, description, enabled_by_default)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `,
      [id, slug, name, description, enabledByDefault]
    );

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: "MODULE_CREATED",
      targetType: "module",
      targetId: id,
      metadata: { name, slug }
    });

    return toDomain(result.rows[0], []);
  }

  async updateModule(
    id: string,
    input: {
      actorTenantId: string;
      actorUserId: string;
      name?: string;
      description?: string | null;
      enabledByDefault?: boolean;
    }
  ): Promise<ModuleRecord> {
    await this.ready;

    const updates: string[] = [];
    const params: unknown[] = [];
    let idx = 1;

    if (input.name !== undefined) {
      updates.push(`name = $${idx++}`);
      params.push(input.name.trim());
    }
    if (input.description !== undefined) {
      updates.push(`description = $${idx++}`);
      params.push(input.description?.trim() || null);
    }
    if (input.enabledByDefault !== undefined) {
      updates.push(`enabled_by_default = $${idx++}`);
      params.push(input.enabledByDefault);
    }

    if (updates.length === 0) {
      const existing = await this.getModule(id);
      if (!existing) throw new Error("Module not found");
      return existing;
    }

    updates.push(`updated_at = NOW()`);
    params.push(id);

    const result = await pool.query<ModuleRow>(
      `UPDATE modules SET ${updates.join(", ")} WHERE id = $${idx} RETURNING *`,
      params
    );
    if (!result.rows[0]) throw new Error("Module not found");

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: "MODULE_UPDATED",
      targetType: "module",
      targetId: id,
      metadata: { name: input.name, enabledByDefault: input.enabledByDefault }
    });

    const connectorsResult = await pool.query<ModuleConnectorRow>(
      "SELECT provider, module_id FROM module_connectors WHERE module_id = $1",
      [id]
    );
    return toDomain(result.rows[0], connectorsResult.rows.map((c) => c.provider));
  }

  async deleteModule(input: {
    actorTenantId: string;
    actorUserId: string;
    id: string;
  }): Promise<void> {
    await this.ready;

    const result = await pool.query<{ slug: string; name: string }>(
      "DELETE FROM modules WHERE id = $1 RETURNING slug, name",
      [input.id]
    );
    if (!result.rows[0]) throw new Error("Module not found");

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: "MODULE_DELETED",
      targetType: "module",
      targetId: input.id,
      metadata: { slug: result.rows[0].slug, name: result.rows[0].name }
    });
  }

  async setModuleConnectors(input: {
    actorTenantId: string;
    actorUserId: string;
    moduleId: string;
    providers: string[];
  }): Promise<ModuleRecord> {
    await this.ready;

    const moduleResult = await pool.query<ModuleRow>("SELECT * FROM modules WHERE id = $1 LIMIT 1", [input.moduleId]);
    if (!moduleResult.rows[0]) throw new Error("Module not found");

    const providers = [...new Set(input.providers.map((p) => p.trim()).filter(Boolean))];

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM module_connectors WHERE module_id = $1", [input.moduleId]);
      if (providers.length > 0) {
        const values = providers.map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2})`).join(", ");
        const params: unknown[] = [];
        for (const provider of providers) {
          params.push(provider, input.moduleId);
        }
        await client.query(
          `
            INSERT INTO module_connectors (provider, module_id)
            VALUES ${values}
            ON CONFLICT (provider) DO UPDATE SET module_id = EXCLUDED.module_id
          `,
          params
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: "MODULE_CONNECTORS_UPDATED",
      targetType: "module",
      targetId: input.moduleId,
      metadata: { providers }
    });

    return (await this.getModule(input.moduleId))!;
  }

  async listTenantModuleAssignments(tenantId: string): Promise<TenantModuleAssignment[]> {
    await this.ready;

    const [modulesResult, connectorsResult, overridesResult] = await Promise.all([
      pool.query<ModuleRow>("SELECT * FROM modules ORDER BY name ASC"),
      pool.query<ModuleConnectorRow>("SELECT provider, module_id FROM module_connectors"),
      pool.query<TenantModuleRow>(
        "SELECT tenant_id, module_id, enabled, updated_at FROM tenant_modules WHERE tenant_id = $1",
        [tenantId]
      )
    ]);

    const connectorsByModule = new Map<string, string[]>();
    for (const row of connectorsResult.rows) {
      const list = connectorsByModule.get(row.module_id) ?? [];
      list.push(row.provider);
      connectorsByModule.set(row.module_id, list);
    }

    const overrideByModule = new Map<string, boolean>();
    for (const row of overridesResult.rows) {
      overrideByModule.set(row.module_id, row.enabled);
    }

    return modulesResult.rows.map((row) => {
      const override = overrideByModule.get(row.id);
      return {
        moduleId: row.id,
        slug: row.slug,
        name: row.name,
        description: row.description ?? undefined,
        enabledByDefault: row.enabled_by_default,
        enabled: override !== undefined ? override : row.enabled_by_default,
        isOverride: override !== undefined,
        connectors: connectorsByModule.get(row.id) ?? []
      };
    });
  }

  async setTenantModuleEnabled(input: {
    actorTenantId: string;
    actorUserId: string;
    tenantId: string;
    moduleId: string;
    enabled: boolean;
  }): Promise<TenantModuleAssignment[]> {
    await this.ready;

    await pool.query(
      `
        INSERT INTO tenant_modules (tenant_id, module_id, enabled, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (tenant_id, module_id) DO UPDATE SET
          enabled = EXCLUDED.enabled,
          updated_at = NOW()
      `,
      [input.tenantId, input.moduleId, input.enabled]
    );

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: input.enabled ? "TENANT_MODULE_ENABLED" : "TENANT_MODULE_DISABLED",
      targetType: "tenant_module",
      targetId: input.moduleId,
      metadata: { tenantId: input.tenantId }
    });

    return this.listTenantModuleAssignments(input.tenantId);
  }

  async clearTenantModuleOverride(input: {
    actorTenantId: string;
    actorUserId: string;
    tenantId: string;
    moduleId: string;
  }): Promise<TenantModuleAssignment[]> {
    await this.ready;

    await pool.query("DELETE FROM tenant_modules WHERE tenant_id = $1 AND module_id = $2", [
      input.tenantId,
      input.moduleId
    ]);

    await this.auditService.log({
      tenantId: input.actorTenantId,
      userId: input.actorUserId,
      action: "TENANT_MODULE_RESET",
      targetType: "tenant_module",
      targetId: input.moduleId,
      metadata: { tenantId: input.tenantId }
    });

    return this.listTenantModuleAssignments(input.tenantId);
  }

  async getEnabledProvidersForTenant(tenantId: string): Promise<{
    enabledProviders: Set<string>;
    unassignedAlwaysAllowed: boolean;
  }> {
    await this.ready;

    const result = await pool.query<{
      provider: string;
      module_id: string;
      module_enabled_by_default: boolean;
      tenant_override: boolean | null;
    }>(
      `
        SELECT
          mc.provider,
          mc.module_id,
          m.enabled_by_default AS module_enabled_by_default,
          tm.enabled AS tenant_override
        FROM module_connectors mc
        INNER JOIN modules m ON m.id = mc.module_id
        LEFT JOIN tenant_modules tm
          ON tm.module_id = mc.module_id AND tm.tenant_id = $1
      `,
      [tenantId]
    );

    const enabledProviders = new Set<string>();
    for (const row of result.rows) {
      const enabled = row.tenant_override !== null ? row.tenant_override : row.module_enabled_by_default;
      if (enabled) {
        enabledProviders.add(row.provider);
      }
    }

    return { enabledProviders, unassignedAlwaysAllowed: true };
  }
}
