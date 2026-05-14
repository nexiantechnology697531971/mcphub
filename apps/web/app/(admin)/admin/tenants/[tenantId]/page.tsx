"use client";

import Link from "next/link";
import type { Route } from "next";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { PageHeader } from "../../../../../components/page-header";
import { readPlatformSession, type PlatformSession } from "../../../../../lib/platform-auth";
import {
  clearTenantModuleOverride,
  fetchPlatformTenantDetail,
  fetchTenantModules,
  setTenantModuleEnabled,
  type PlatformTenantDetail,
  type TenantModuleAssignment
} from "../../../../../lib/platform-api";

const tabs = ["Users", "Modules", "Connectors", "Audit"] as const;
type Tab = (typeof tabs)[number];

const baselinePolicies = [
  { tool: "find_customer", scope: "Read", roles: "OWNER, ADMIN, ANALYST, USER" },
  { tool: "get_ticket_with_actions", scope: "Read", roles: "OWNER, ADMIN, ANALYST, USER" },
  { tool: "create_draft_ticket", scope: "Guarded write", roles: "OWNER, ADMIN" },
  { tool: "add_internal_note", scope: "Guarded write", roles: "OWNER, ADMIN" }
];

export default function TenantDetailPage() {
  const router = useRouter();
  const params = useParams();
  const tenantId = params.tenantId as string;
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [detail, setDetail] = useState<PlatformTenantDetail | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("Users");
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [tenantModules, setTenantModules] = useState<TenantModuleAssignment[]>([]);
  const [savingModuleId, setSavingModuleId] = useState<string>("");

  useEffect(() => {
    const storedSession = readPlatformSession();
    if (!storedSession) {
      router.replace("/auth/login");
      return;
    }

    setSession(storedSession);
  }, [router]);

  useEffect(() => {
    async function loadDetail() {
      if (!session) {
        return;
      }

      setLoading(true);
      setNotice("");

      try {
        const [detailPayload, modulesPayload] = await Promise.all([
          fetchPlatformTenantDetail(tenantId, session),
          fetchTenantModules(tenantId, session)
        ]);
        setDetail(detailPayload);
        setTenantModules(modulesPayload.modules);
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Could not load tenant detail.");
      } finally {
        setLoading(false);
      }
    }

    void loadDetail();
  }, [session, tenantId]);

  async function handleToggleModule(moduleId: string, enabled: boolean) {
    if (!session) return;
    setSavingModuleId(moduleId);
    setNotice("");
    try {
      const payload = await setTenantModuleEnabled(tenantId, moduleId, enabled, session);
      setTenantModules(payload.modules);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not update module enablement.");
    } finally {
      setSavingModuleId("");
    }
  }

  async function handleResetModule(moduleId: string) {
    if (!session) return;
    setSavingModuleId(moduleId);
    setNotice("");
    try {
      const payload = await clearTenantModuleOverride(tenantId, moduleId, session);
      setTenantModules(payload.modules);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not reset module override.");
    } finally {
      setSavingModuleId("");
    }
  }

  if (loading) {
    return <div className="panel">Loading tenant...</div>;
  }

  if (!detail) {
    return <div className="empty-state"><h3>Tenant not found</h3><p>This customer workspace is not available.</p></div>;
  }

  return (
    <div className="stack">
      <div className="breadcrumb">
        <Link href={"/admin/tenants" as Route}>Tenants</Link>
        <span>/</span>
        <span>{detail.tenant.name}</span>
      </div>

      <PageHeader
        eyebrow="Tenant Workspace"
        title={detail.tenant.name}
        description={`Slug: ${detail.tenant.slug} · Status: ${detail.tenant.status} · Created: ${new Date(detail.tenant.createdAt).toLocaleDateString()}`}
      />

      {notice ? <div className="notice">{notice}</div> : null}

      <div className="tabs">
        {tabs.map((tab) => (
          <button key={tab} type="button" className={`tab ${activeTab === tab ? "active" : ""}`} onClick={() => setActiveTab(tab)}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "Users" ? (
        <div className="data-table-wrapper">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last active</th></tr></thead>
            <tbody>
              {detail.users.map((user) => (
                <tr key={user.id}>
                  <td>{user.displayName}</td>
                  <td>{user.email}</td>
                  <td><span className="chip">{user.role}</span></td>
                  <td>{user.status}</td>
                  <td>{new Date(user.lastActiveAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {activeTab === "Modules" ? (
        <div className="stack">
          <p className="muted">
            Enable or disable modules for this tenant. A disabled module hides all its connectors and tools, both in the UI and via MCP.
          </p>
          <div className="data-table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Connectors</th>
                  <th>Default</th>
                  <th>Status for this tenant</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenantModules.map((module) => (
                  <tr key={module.moduleId}>
                    <td>
                      <strong>{module.name}</strong>
                      {module.description ? <p className="muted">{module.description}</p> : null}
                    </td>
                    <td>{module.connectors.length === 0 ? <span className="muted">None</span> : module.connectors.join(", ")}</td>
                    <td>{module.enabledByDefault ? "On" : "Off"}</td>
                    <td>
                      <span className={`status-pill ${module.enabled ? "connected" : ""}`}>
                        {module.enabled ? "Enabled" : "Disabled"}
                      </span>
                      {module.isOverride ? <span className="muted"> (override)</span> : null}
                    </td>
                    <td>
                      <div className="row">
                        <button
                          type="button"
                          className="button secondary"
                          disabled={savingModuleId === module.moduleId}
                          onClick={() => void handleToggleModule(module.moduleId, !module.enabled)}
                        >
                          {module.enabled ? "Disable" : "Enable"}
                        </button>
                        {module.isOverride ? (
                          <button
                            type="button"
                            className="button tertiary"
                            disabled={savingModuleId === module.moduleId}
                            onClick={() => void handleResetModule(module.moduleId)}
                          >
                            Reset to default
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {activeTab === "Connectors" ? (
        <div className="connector-grid">
          {detail.connectors.map((connector) => (
            <article key={`${connector.provider}-${connector.userId}`} className="connector-card">
              <div className="connector-card-header">
                <div>
                  <h4>{connector.provider}</h4>
                  <span className="connector-meta">User {connector.userId}</span>
                </div>
                <span className={`status-pill ${connector.status.toLowerCase()}`}>{connector.status}</span>
              </div>
              <p className="connector-meta">Updated {new Date(connector.updatedAt).toLocaleString()}</p>
              {connector.lastError ? <p className="danger-text">{connector.lastError}</p> : null}
            </article>
          ))}

          <article className="connector-card">
            <div className="connector-card-header">
              <div>
                <h4>Policy baseline</h4>
                <span className="connector-meta">Server-enforced</span>
              </div>
            </div>
            <div className="permission-list">
              {baselinePolicies.map((policy) => (
                <article key={policy.tool} className="permission-item">
                  <div>
                    <strong>{policy.tool}</strong>
                    <p>{policy.scope} · {policy.roles}</p>
                  </div>
                  <span className="status-pill connected">Active</span>
                </article>
              ))}
            </div>
          </article>
        </div>
      ) : null}

      {activeTab === "Audit" ? (
        <div className="data-table-wrapper">
          <table>
            <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
            <tbody>
              {detail.audit.map((event) => (
                <tr key={event.id}>
                  <td>{new Date(event.createdAt).toLocaleString()}</td>
                  <td><span className="chip">{event.action}</span></td>
                  <td>{event.targetType}{event.targetId ? ` · ${event.targetId}` : ""}</td>
                  <td>{JSON.stringify(event.metadata)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
