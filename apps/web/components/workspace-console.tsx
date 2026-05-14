"use client";
import { useRouter } from "next/navigation";
import { startTransition, useEffect, useMemo, useState } from "react";

import { clearPlatformSession, hasPlatformConsoleAccess, readPlatformSession, writePlatformSession, type PlatformSession } from "../lib/platform-auth";

type Connector = {
  id: string;
  name: string;
  category: string;
  auth: "OAuth 2.0" | "API key" | "Bearer token";
  status: "Connected" | "Needs consent" | "Disconnected";
  description: string;
  lastSync: string;
  tools: string[];
  lastError?: string;
  realOAuth?: boolean;
  logoUrl: string;
  accent: string;
};

type ConnectorConfig = {
  apiUrl: string;
  authUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
  tenantId: string;
  environment: string;
  hasClientSecret: boolean;
};

type Permission = {
  tool: string;
  roles: string[];
  enabled: boolean;
};

type AuditEvent = {
  id: string;
  time: string;
  action: string;
  detail: string;
};

type DemoState = {
  workspaceName: string;
  workspaceSlug: string;
  tenantId: string;
  userId: string;
  connectors: Connector[];
  permissions: Permission[];
  audit: AuditEvent[];
};

type ProviderResponse = {
  provider: string;
  status: string;
  connected: boolean;
  lastError?: string;
};

const initialState: DemoState = {
  workspaceName: "Nexian Legal Ops",
  workspaceSlug: "nexian-legal-ops",
  tenantId: "demo-tenant",
  userId: "demo-user",
  connectors: [
    {
      id: "halopsa",
      name: "HaloPSA",
      category: "Service desk",
      auth: "OAuth 2.0",
      status: "Disconnected",
      description: "Customers, tickets, ticket actions, projects, contacts, knowledge, devices, invoices, and guarded write tools.",
      lastSync: "Not connected",
      tools: [
        "find_customer",
        "get_customer_overview",
        "list_open_tickets",
        "get_ticket",
        "get_ticket_with_actions",
        "list_ticket_actions",
        "search_projects",
        "find_contact",
        "search_documents",
        "list_devices_for_site",
        "get_recent_invoices",
        "create_draft_ticket",
        "add_internal_note"
      ],
      realOAuth: true,
      logoUrl: "https://www.topleft.team/hs-fs/hubfs/HaloPSA.jpg?width=1200&height=738&name=HaloPSA.jpg",
      accent: "halo"
    },
    {
      id: "microsoft365",
      name: "Microsoft 365 / SharePoint",
      category: "Documents",
      auth: "OAuth 2.0",
      status: "Needs consent",
      description: "Search SharePoint, projects, and tenant-approved contacts.",
      lastSync: "Scaffold only",
      tools: ["search_documents", "search_projects", "find_contact"],
      logoUrl:
        "https://upload.wikimedia.org/wikipedia/commons/thumb/e/ec/Microsoft_Office_SharePoint_%282019%E2%80%932025%29.svg/3840px-Microsoft_Office_SharePoint_%282019%E2%80%932025%29.svg.png",
      accent: "m365"
    },
    {
      id: "ninjaone",
      name: "NinjaOne",
      category: "RMM",
      auth: "OAuth 2.0",
      status: "Disconnected",
      description: "Managed devices, endpoint operations, and technician context for MSP teams.",
      lastSync: "Not configured",
      tools: [
        "search_rmm_devices",
        "get_rmm_device_overview",
        "get_rmm_device_alerts",
        "get_rmm_device_activities",
        "list_devices_for_site",
        "search_documents",
        "find_contact"
      ],
      realOAuth: true,
      logoUrl: "https://www.logo-designer.co/storage/2021/11/2021-it-firm-ninjaone-new-logo-design.png",
      accent: "ninja"
    },
    {
      id: "cipp",
      name: "CIPP",
      category: "Microsoft 365 tenancy",
      auth: "API key",
      status: "Disconnected",
      description: "Cross-tenant Microsoft 365 administration and operational context.",
      lastSync: "Not configured",
      tools: ["find_contact", "search_documents", "search_projects"],
      logoUrl:
        "https://docs.cipp.app/~gitbook/image?url=https%3A%2F%2F3168297744-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FhV8luribpATiHNQ8bdts%252Flogo%252FiccskRbgKmK11Dgbuhbk%252FCIPP-logo-main-border_00%2520-%2520Copy.png%3Falt%3Dmedia%26token%3D3d8b7c87-fce0-49ae-9e46-d371d4091416&width=260&dpr=3&quality=100&sign=24bb285c&sv=2",
      accent: "cipp"
    },
    {
      id: "n8n",
      name: "n8n",
      category: "Workflow automation",
      auth: "Bearer token",
      status: "Disconnected",
      description: "Workflow boxes, webhook execution history, and API-driven automation runs for linked customer flows.",
      lastSync: "Not configured",
      tools: ["list_workflows", "get_workflow", "list_executions", "get_execution", "trigger_webhook"],
      logoUrl: "https://n8n.io/favicon.ico",
      accent: "n8n"
    },
    {
      id: "actionstep",
      name: "ActionStep",
      category: "Legal practice management",
      auth: "OAuth 2.0",
      status: "Disconnected",
      description: "Matters (actions), participants, tasks, and time entries from ActionStep for legal practice workflows.",
      lastSync: "Not connected",
      tools: [
        "list_matters",
        "search_matters",
        "get_matter",
        "list_participants",
        "search_participants",
        "get_participant",
        "list_tasks_for_matter",
        "list_time_entries"
      ],
      realOAuth: true,
      logoUrl: "https://www.actionstep.com/wp-content/uploads/2021/02/Actionstep_Logo_RGB.png",
      accent: "actionstep"
    }
  ],
  permissions: [
    { tool: "find_customer", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "get_customer_overview", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "list_open_tickets", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "get_ticket", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "get_ticket_with_actions", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "list_ticket_actions", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "search_projects", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "find_contact", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "search_documents", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "list_devices_for_site", roles: ["Owner", "Admin", "Analyst", "User"], enabled: true },
    { tool: "get_recent_invoices", roles: ["Owner", "Admin"], enabled: true },
    { tool: "create_draft_ticket", roles: ["Owner", "Admin"], enabled: true },
    { tool: "add_internal_note", roles: ["Owner", "Admin"], enabled: false },
    { tool: "list_workflows", roles: ["Owner", "Admin", "Analyst"], enabled: true },
    { tool: "get_workflow", roles: ["Owner", "Admin", "Analyst"], enabled: true },
    { tool: "list_executions", roles: ["Owner", "Admin", "Analyst"], enabled: true },
    { tool: "get_execution", roles: ["Owner", "Admin", "Analyst"], enabled: true },
    { tool: "trigger_webhook", roles: ["Owner", "Admin"], enabled: true }
  ],
  audit: [
    { id: "a1", time: "10:22", action: "Connector updated", detail: "HaloPSA now uses the real API authorization route." },
    { id: "a2", time: "10:17", action: "Tool invoked", detail: "list_open_tickets called for tenant nexian-legal-ops." },
    { id: "a3", time: "10:01", action: "Policy reviewed", detail: "Safe write tools limited to Owner and Admin roles." },
    { id: "a4", time: "09:48", action: "Workflow execution synced", detail: "n8n execution telemetry is ready to be linked into the MCP dashboard." }
  ]
};

const storageKey = "nexian-mcp-demo-state";

function makeAuditEvent(action: string, detail: string): AuditEvent {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    action,
    detail
  };
}

function mapProviderStatus(status: string | undefined): Connector["status"] {
  if (status === "ACTIVE") {
    return "Connected";
  }

  if (status === "DISCONNECTED" || !status) {
    return "Disconnected";
  }

  return "Needs consent";
}

export function WorkspaceConsole({
  mode = "catalog",
  initialSelectedConnector
}: {
  mode?: "catalog" | "detail";
  initialSelectedConnector?: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<DemoState>(initialState);
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [selectedConnector, setSelectedConnector] = useState("halopsa");
  const [notice, setNotice] = useState("");
  const [isHydrated, setIsHydrated] = useState(false);
  const [newTenantName, setNewTenantName] = useState("");
  const [switchingTenant, setSwitchingTenant] = useState(false);
  const [creatingTenant, setCreatingTenant] = useState(false);
  const [connectorConfigs, setConnectorConfigs] = useState<Record<string, ConnectorConfig>>({});
  const [savingConfigId, setSavingConfigId] = useState("");
  const [visibleProviders, setVisibleProviders] = useState<Set<string> | null>(null);

  const origin = typeof window === "undefined" ? "http://localhost:3000" : window.location.origin;
  const apiOrigin = useMemo(
    () => process.env.NEXT_PUBLIC_API_URL ?? origin.replace(":3000", ":4000"),
    [origin]
  );

  useEffect(() => {
    const saved = window.localStorage.getItem(storageKey);
    if (saved) {
      startTransition(() => {
        setState((current) => ({ ...current, ...JSON.parse(saved) as Partial<DemoState> }));
      });
    }
    setIsHydrated(true);
  }, []);

  useEffect(() => {
    if (initialSelectedConnector && initialState.connectors.some((connector) => connector.id === initialSelectedConnector)) {
      setSelectedConnector(initialSelectedConnector);
    }
  }, [initialSelectedConnector]);

  useEffect(() => {
    const storedSession = readPlatformSession();
    if (!storedSession) {
      router.replace("/auth/login");
      return;
    }

    setSession(storedSession);
    setState((current) => ({
      ...current,
      workspaceName: storedSession.tenant.name,
      workspaceSlug: storedSession.tenant.slug,
      tenantId: storedSession.tenant.id,
      userId: storedSession.user.id
    }));
  }, [router]);

  useEffect(() => {
    if (!isHydrated) {
      return;
    }

    window.localStorage.setItem(
      storageKey,
      JSON.stringify({
        workspaceName: state.workspaceName,
        workspaceSlug: state.workspaceSlug,
        tenantId: state.tenantId,
        userId: state.userId
      })
    );
  }, [isHydrated, state.workspaceName, state.workspaceSlug, state.tenantId, state.userId]);

  useEffect(() => {
    if (!isHydrated) {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const oauthStatus = params.get("oauth");
    const provider = params.get("provider");

    if (oauthStatus === "success" && provider) {
      setNotice(`${provider} connected successfully.`);
      setState((current) => ({
        ...current,
        audit: [makeAuditEvent("Connector connected", `${provider} completed OAuth successfully.`), ...current.audit]
      }));
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, [isHydrated]);

  useEffect(() => {
    if (!isHydrated) {
      return;
    }

    async function loadProviders() {
      if (!session) {
        return;
      }

      try {
        const response = await fetch(`${apiOrigin}/providers`, {
          headers: {
            authorization: `Bearer ${session.token}`
          }
        });
        if (!response.ok) {
          throw new Error(`Failed to load providers (${response.status})`);
        }

        const payload = (await response.json()) as { providers: ProviderResponse[] };
        setVisibleProviders(new Set(payload.providers.map((provider) => provider.provider)));
        setState((current) => ({
          ...current,
          connectors: current.connectors.map((connector) => {
            const provider = payload.providers.find((candidate) => candidate.provider === connector.id);
            if (!provider) {
              return connector;
            }

            return {
              ...connector,
              status: mapProviderStatus(provider.status),
              lastSync: provider.connected ? "Connected via backend" : connector.lastSync,
              lastError: provider.lastError
            };
          })
        }));
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Unable to load connector state from API.");
      }
    }

    void loadProviders();
  }, [apiOrigin, isHydrated, session]);

  useEffect(() => {
    if (!session) {
      return;
    }

    setConnectorConfigs({});
    const sessionToken = session.token;
    const tenantName = session.tenant.name;

    async function loadConnectorConfigs() {
      try {
        const targets = visibleProviders
          ? initialState.connectors.filter((connector) => visibleProviders.has(connector.id))
          : initialState.connectors;
        const entries = await Promise.all(
          targets.map(async (connector) => {
            const response = await fetch(`${apiOrigin}/connector-config/${connector.id}`, {
              headers: {
                authorization: `Bearer ${sessionToken}`
              }
            });

            if (!response.ok) {
              throw new Error(`Failed to load ${connector.name} settings`);
            }

            const payload = (await response.json()) as { config: Partial<ConnectorConfig> };
            return [
              connector.id,
              {
                apiUrl: payload.config.apiUrl ?? "",
                authUrl: payload.config.authUrl ?? "",
                clientId: payload.config.clientId ?? "",
                clientSecret: "",
                redirectUri: payload.config.redirectUri ?? "",
                scopes: payload.config.scopes ?? "",
                tenantId: payload.config.tenantId ?? "",
                environment: payload.config.environment ?? "",
                hasClientSecret: Boolean(payload.config.hasClientSecret)
              }
            ] as const;
          })
        );

        const nextConfigs = Object.fromEntries(entries);
        setConnectorConfigs(nextConfigs);
        setState((current) => ({
          ...current,
          connectors: current.connectors.map((connector) =>
            nextConfigs[connector.id]?.apiUrl && connector.status !== "Connected"
              ? { ...connector, lastSync: "Tenant configuration loaded" }
              : connector
          )
        }));
        if (Object.values(nextConfigs).some((config) => config.apiUrl || config.clientId || config.hasClientSecret)) {
          setNotice(`Loaded shared connector settings for ${tenantName}. OAuth consent remains per user.`);
        }
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Unable to load connector configuration.");
      }
    }

    void loadConnectorConfigs();
  }, [apiOrigin, session, visibleProviders]);

  const visibleConnectors = useMemo(
    () =>
      visibleProviders
        ? state.connectors.filter((connector) => visibleProviders.has(connector.id))
        : state.connectors,
    [state.connectors, visibleProviders]
  );

  const connectedCount = visibleConnectors.filter((connector) => connector.status === "Connected").length;

  function togglePermission(tool: string) {
    setState((current) => ({
      ...current,
      permissions: current.permissions.map((permission) =>
        permission.tool === tool ? { ...permission, enabled: !permission.enabled } : permission
      ),
      audit: [makeAuditEvent("Permission changed", `${tool} access policy was updated.`), ...current.audit]
    }));
  }

  async function connectConnector(id: string) {
    const connector = state.connectors.find((item) => item.id === id);
    if (!connector) {
      return;
    }

    setSelectedConnector(id);

    if (connector.id === "halopsa" || connector.id === "ninjaone" || connector.id === "actionstep") {
      if (!session) {
        router.replace("/auth/login");
        return;
      }

      const configEntry = connectorConfigs[connector.id];
      const requiresClientSecret = connector.id === "halopsa" || connector.id === "actionstep";
      const requiresApiUrl = connector.id !== "actionstep";
      const missingApiUrl = requiresApiUrl && !configEntry?.apiUrl;
      const missingSecret =
        requiresClientSecret && !configEntry?.clientSecret && !configEntry?.hasClientSecret;
      if (missingApiUrl || !configEntry?.clientId || missingSecret) {
        const fields = [
          requiresApiUrl ? "API URL" : null,
          "client ID",
          requiresClientSecret ? "client secret" : null
        ]
          .filter(Boolean)
          .join(", ");
        setNotice(`Save the ${connector.name} ${fields} in Connector Setup before starting OAuth.`);
        return;
      }

      const response = await fetch(`${apiOrigin}/oauth/${connector.id}/url`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          returnTo: `${origin}/dashboard/connectors`
        })
      });

      if (!response.ok) {
        setNotice(`Failed to start ${connector.name} OAuth.`);
        return;
      }

      const payload = (await response.json()) as { authorizationUrl: string };
      window.location.href = payload.authorizationUrl;
      return;
    }

    if (connector.id === "n8n") {
      setNotice("n8n is ready to configure. Save the API URL and bearer token, then we can wire workflow and execution reads against your n8n instance.");
      return;
    }

    setNotice(`${connector.name} is ready to configure in the setup panel. Live auth and token exchange are still to be wired.`);
  }

  async function disconnectConnector(id: string) {
    const connector = state.connectors.find((item) => item.id === id);
    if (!connector) {
      return;
    }

    if (!session) {
      router.replace("/auth/login");
      return;
    }

    const response = await fetch(`${apiOrigin}/connected-accounts/${id}`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${session.token}`
      }
    });

    if (!response.ok) {
      setNotice(`Failed to disconnect ${connector.name}.`);
      return;
    }

    setState((current) => ({
      ...current,
      connectors: current.connectors.map((item) =>
        item.id === id ? { ...item, status: "Disconnected", lastSync: "Disconnected from backend" } : item
      ),
      audit: [makeAuditEvent("Connector disconnected", `${connector.name} was disconnected from the backend store.`), ...current.audit]
    }));
    setNotice(`${connector.name} disconnected.`);
  }

  function signOut() {
    clearPlatformSession();
    router.replace("/auth/login");
  }

  async function switchTenant(tenantId: string) {
    if (!session || tenantId === session.tenant.id) {
      return;
    }

    setSwitchingTenant(true);
    setNotice("");

    try {
      const response = await fetch(`${apiOrigin}/auth/switch-tenant`, {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ tenantId })
      });

      const payload = (await response.json()) as PlatformSession & { error?: string; message?: string };
      if (!response.ok) {
        throw new Error(payload.message ?? payload.error ?? "Could not switch tenant");
      }

      writePlatformSession(payload);
      setSession(payload);
      setState((current) => ({
        ...current,
        workspaceName: payload.tenant.name,
        workspaceSlug: payload.tenant.slug,
        tenantId: payload.tenant.id,
        userId: payload.user.id,
        audit: [makeAuditEvent("Tenant switched", `Active workspace changed to ${payload.tenant.name}.`), ...current.audit]
      }));
      setNotice(`Now working in ${payload.tenant.name}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not switch tenant.");
    } finally {
      setSwitchingTenant(false);
    }
  }

  async function createTenant() {
    if (!session || !newTenantName.trim()) {
      return;
    }

    setCreatingTenant(true);
    setNotice("");

    try {
      const response = await fetch(`${apiOrigin}/auth/tenants`, {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ workspaceName: newTenantName.trim() })
      });

      const payload = (await response.json()) as PlatformSession & { error?: string; message?: string };
      if (!response.ok) {
        throw new Error(payload.message ?? payload.error ?? "Could not create tenant");
      }

      writePlatformSession(payload);
      setSession(payload);
      setState((current) => ({
        ...current,
        workspaceName: payload.tenant.name,
        workspaceSlug: payload.tenant.slug,
        tenantId: payload.tenant.id,
        userId: payload.user.id,
        audit: [makeAuditEvent("Tenant created", `${payload.tenant.name} was created and made active.`), ...current.audit]
      }));
      setNewTenantName("");
      setNotice(`Created and switched to ${payload.tenant.name}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not create tenant.");
    } finally {
      setCreatingTenant(false);
    }
  }

  function updateConnectorConfig(id: string, patch: Partial<ConnectorConfig>) {
    setConnectorConfigs((current) => ({
      ...current,
      [id]: {
        ...{
          apiUrl: "",
          authUrl: "",
          clientId: "",
          clientSecret: "",
          redirectUri: "",
          scopes: "",
          tenantId: "",
          environment: "",
          hasClientSecret: false
        },
        ...current[id],
        ...patch
      }
    }));
  }

  async function saveConnectorConfig(id: string) {
    if (!session) {
      router.replace("/auth/login");
      return;
    }

    const configEntry = connectorConfigs[id];
    if (!configEntry) {
      return;
    }

    setSavingConfigId(id);
    setNotice("");

    try {
      const response = await fetch(`${apiOrigin}/connector-config/${id}`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          apiUrl: configEntry.apiUrl,
          authUrl: configEntry.authUrl,
          clientId: configEntry.clientId,
          clientSecret: configEntry.clientSecret,
          redirectUri: configEntry.redirectUri,
          scopes: configEntry.scopes,
          tenantId: configEntry.tenantId,
          environment: configEntry.environment
        })
      });

      const payload = (await response.json()) as { config?: Partial<ConnectorConfig>; error?: string; message?: string };
      if (!response.ok) {
        throw new Error(payload.message ?? payload.error ?? `Failed to save ${id} settings`);
      }

      updateConnectorConfig(id, {
        apiUrl: payload.config?.apiUrl ?? configEntry.apiUrl,
        authUrl: payload.config?.authUrl ?? configEntry.authUrl,
        clientId: payload.config?.clientId ?? configEntry.clientId,
        clientSecret: "",
        redirectUri: payload.config?.redirectUri ?? configEntry.redirectUri,
        scopes: payload.config?.scopes ?? configEntry.scopes,
        tenantId: payload.config?.tenantId ?? configEntry.tenantId,
        environment: payload.config?.environment ?? configEntry.environment,
        hasClientSecret: Boolean(payload.config?.hasClientSecret)
      });

      const connectorName = state.connectors.find((connector) => connector.id === id)?.name ?? id;
      setState((current) => ({
        ...current,
        connectors: current.connectors.map((connector) =>
          connector.id === id ? { ...connector, lastSync: "Configuration saved" } : connector
        ),
        audit: [makeAuditEvent("Connector config saved", `${connectorName} settings were updated.`), ...current.audit]
      }));
      setNotice(`${connectorName} settings saved.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not save connector settings.");
    } finally {
      setSavingConfigId("");
    }
  }

  const selected = state.connectors.find((connector) => connector.id === selectedConnector) ?? state.connectors[0];
  const canManageTenants = hasPlatformConsoleAccess(session);
  const selectedConfig = connectorConfigs[selected.id] ?? {
    apiUrl: "",
    authUrl: "",
    clientId: "",
    clientSecret: "",
    redirectUri: "",
    scopes: "",
    tenantId: "",
    environment: "",
    hasClientSecret: false
  };

  if (mode === "detail") {
    return (
      <div className="stack">
        {notice ? <div className="notice">{notice}</div> : null}
        <article className="panel stack connector-catalog-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Connector Setup</span>
              <h2>{selected.name}</h2>
            </div>
            <div className="row">
              <button className="button secondary" onClick={() => router.push("/dashboard/connectors")} type="button">
                Back to connectors
              </button>
            </div>
          </div>
          <div className="setup-card stack">
            <div className="connector-brand-row">
              <span className={`connector-logo connector-logo-${selected.accent}`}>
                <img src={selected.logoUrl} alt={`${selected.name} logo`} className="connector-logo-image" />
              </span>
              <div>
                <strong>{selected.name}</strong>
                <p className="muted connector-meta">
                  {selected.category} · {selected.auth}
                </p>
              </div>
            </div>
            <p className="muted">{selected.description}</p>
            <p className="connector-meta">
              {selected.id === "halopsa"
                ? "Live MCP tools: customer lookup, ticketing, action history, project search, contacts, documents, site devices, invoices, and guarded writes."
                : selected.id === "n8n"
                  ? "n8n is set up for workflow catalog, execution lookups, and webhook-triggered automation runs across linked boxes."
                  : selected.id === "actionstep"
                    ? "ActionStep tools: matters (actions), participants, tasks, and time entries. The regional API endpoint is discovered automatically from the OAuth token response."
                    : "Configuration is stored per tenant so each customer can have its own connector settings."}
            </p>
            <p className="connector-meta">
              Shared app settings are loaded tenant-wide. Each user still completes their own OAuth consent and gets their own connected account token.
            </p>
          </div>
          <div className="field-grid">
            {selected.id !== "actionstep" ? (
              <label className="stack">
                <span className="field-label">API URL</span>
                <input
                  value={selectedConfig.apiUrl}
                  onChange={(event) => updateConnectorConfig(selected.id, { apiUrl: event.target.value })}
                  placeholder={
                    selected.id === "halopsa"
                      ? "https://yourhalo.example.com"
                      : selected.id === "ninjaone"
                        ? "https://app.ninjarmm.com"
                        : selected.id === "n8n"
                          ? "https://n8n.example.com/api/v1"
                          : "https://cipp.example.com"
                  }
                />
              </label>
            ) : null}
            {selected.id === "actionstep" ? (
              <label className="stack">
                <span className="field-label">Environment</span>
                <select
                  value={selectedConfig.environment ?? "production"}
                  onChange={(event) => updateConnectorConfig(selected.id, { environment: event.target.value })}
                >
                  <option value="production">Production (go.actionstep.com)</option>
                  <option value="staging">Staging (go.actionstepstaging.com)</option>
                </select>
              </label>
            ) : null}
            {selected.id === "halopsa" || selected.id === "ninjaone" ? (
              <label className="stack">
                <span className="field-label">Auth URL</span>
                <input
                  value={selectedConfig.authUrl}
                  onChange={(event) => updateConnectorConfig(selected.id, { authUrl: event.target.value })}
                  placeholder={
                    selected.id === "halopsa"
                      ? "Optional: https://yourhalo.example.com/auth"
                      : "Optional: https://app.ninjarmm.com"
                  }
                />
              </label>
            ) : null}
            <label className="stack">
              <span className="field-label">
                {selected.id === "n8n" ? "Workflow or project key" : "Client ID"}
              </span>
              <input
                value={selectedConfig.clientId}
                onChange={(event) => updateConnectorConfig(selected.id, { clientId: event.target.value })}
                placeholder={
                  selected.id === "n8n"
                    ? "Optional: default workflow or project identifier"
                    : "Enter the application client ID"
                }
              />
            </label>
            {selected.id === "halopsa" || selected.id === "ninjaone" || selected.id === "n8n" || selected.id === "actionstep" ? (
              <label className="stack">
                <span className="field-label">
                  {selected.id === "n8n" ? "Webhook base URL" : "Redirect URI"}
                </span>
                <input
                  value={selectedConfig.redirectUri}
                  onChange={(event) => updateConnectorConfig(selected.id, { redirectUri: event.target.value })}
                  placeholder={
                    selected.id === "n8n"
                      ? "https://n8n.example.com/webhook"
                      : selected.id === "ninjaone"
                        ? "https://api.example.com/oauth/ninjaone/callback"
                        : selected.id === "actionstep"
                          ? "https://api.example.com/oauth/actionstep/callback"
                          : "https://api.example.com/oauth/halopsa/callback"
                  }
                />
              </label>
            ) : null}
            {selected.id === "halopsa" || selected.id === "ninjaone" || selected.id === "actionstep" ? (
              <label className="stack">
                <span className="field-label">Scopes</span>
                <input
                  value={selectedConfig.scopes}
                  onChange={(event) => updateConnectorConfig(selected.id, { scopes: event.target.value })}
                  placeholder={
                    selected.id === "actionstep"
                      ? "actions participants tasks timeentries"
                      : "scope-one scope-two"
                  }
                />
              </label>
            ) : null}
            {selected.id === "cipp" ? (
              <label className="stack">
                <span className="field-label">Tenant ID</span>
                <input
                  value={selectedConfig.tenantId}
                  onChange={(event) => updateConnectorConfig(selected.id, { tenantId: event.target.value })}
                  placeholder="Microsoft 365 tenant ID"
                />
              </label>
            ) : null}
          </div>
          <label className="stack">
            <span className="field-label">
              {selected.id === "n8n" ? "Bearer token / API key" : selected.id === "ninjaone" ? "Client secret (optional)" : "Client secret"}
            </span>
            <input
              type="password"
              value={selectedConfig.clientSecret}
              onChange={(event) => updateConnectorConfig(selected.id, { clientSecret: event.target.value })}
              placeholder={
                selectedConfig.hasClientSecret
                  ? "Saved already. Enter a new secret to replace it."
                  : selected.id === "n8n"
                    ? "Enter the n8n bearer token or API key"
                    : selected.id === "ninjaone"
                      ? "Leave blank when using client authorization without a secret"
                    : "Enter the client secret"
              }
            />
          </label>
          <div className="connector-meta">
            {selected.id === "ninjaone"
              ? selectedConfig.hasClientSecret
                ? "A client secret is saved for this connector, but NinjaOne can also run without one."
                : "No secret saved. This is fine if your NinjaOne app uses client authorization without a secret."
              : selectedConfig.hasClientSecret
                ? "A secret is already saved for this connector."
                : "No secret saved yet."}
          </div>
          {(selectedConfig.apiUrl || selectedConfig.clientId || selectedConfig.hasClientSecret) ? (
            <div className="notice">
              Shared tenant settings are already loaded for {state.workspaceName}. You only need to save here if you want to replace the tenant-wide connector app settings.
            </div>
          ) : null}
          <div className="row">
            <button className="button secondary" onClick={() => void saveConnectorConfig(selected.id)} type="button" disabled={savingConfigId === selected.id}>
              {savingConfigId === selected.id ? "Saving..." : "Save settings"}
            </button>
            <button className="button primary" onClick={() => connectConnector(selected.id)} type="button">
              {selected.realOAuth ? `Start ${selected.name} OAuth` : selected.id === "n8n" ? "Link n8n workspace" : "Use selected connector"}
            </button>
          </div>
        </article>
      </div>
    );
  }

  return (
    <div className="console stack">
      <section className="hero hero-console">
        <div className="hero-copy stack">
          <span className="eyebrow">Nexian AI & Automation Control Centre</span>
          <h1 className="hero-title">Connect your MSP stack, control safe tools, and hand clients a single MCP endpoint.</h1>
          <p className="muted hero-text">
            HaloPSA now uses the real authorization-code route and exposes the expanded Nexian MCP surface for tickets,
            actions, projects, contacts, knowledge, assets, invoices, and guarded writes. The other connectors remain
            scaffolded until we wire their provider-specific token exchange and storage paths. n8n is included for
            workflow boxes, execution history, and webhook-triggered automation runs.
          </p>
          <div className="stats-grid">
            <div className="stat-card">
              <strong>{connectedCount}</strong>
              <span>Connected services</span>
            </div>
            <div className="stat-card">
              <strong>{state.permissions.filter((item) => item.enabled).length}</strong>
              <span>Enabled tools</span>
            </div>
            <div className="stat-card">
              <strong>{session?.tenants.length ?? 1}</strong>
              <span>Accessible tenants</span>
            </div>
          </div>
          {notice ? <div className="notice">{notice}</div> : null}
        </div>
        <aside className="hero-side stack">
          <div className="panel panel-dark stack">
            <span className="eyebrow">Workspace</span>
            <strong className="workspace-name">{state.workspaceName}</strong>
            <label className="stack">
              <span className="field-label">Tenant slug</span>
              <input value={state.workspaceSlug} readOnly />
            </label>
            <label className="stack">
              <span className="field-label">Tenant ID</span>
              <input value={state.tenantId} readOnly />
            </label>
            <label className="stack">
              <span className="field-label">User ID</span>
              <input value={state.userId} readOnly />
            </label>
            <div className="stack">
              <span className="field-label">Active tenants</span>
              <div className="chip-row">
                {(session?.tenants ?? []).map((tenant) => (
                  <button
                    key={tenant.id}
                    className={`chip tenant-chip ${tenant.id === state.tenantId ? "active" : ""}`}
                    onClick={() => void switchTenant(tenant.id)}
                    type="button"
                    disabled={switchingTenant}
                  >
                    {tenant.name} · {tenant.role}
                  </button>
                ))}
              </div>
            </div>
            {canManageTenants ? (
              <>
                <label className="stack">
                  <span className="field-label">Create tenant</span>
                  <input
                    value={newTenantName}
                    onChange={(event) => setNewTenantName(event.target.value)}
                    placeholder="Add a new customer workspace"
                  />
                </label>
                <div className="row">
                  <button className="button primary" onClick={() => void createTenant()} type="button" disabled={creatingTenant}>
                    {creatingTenant ? "Creating..." : "Create tenant"}
                  </button>
                  <button className="button secondary" onClick={signOut} type="button">
                    Sign out
                  </button>
                </div>
              </>
            ) : (
              <div className="row">
                <button className="button secondary" onClick={signOut} type="button">
                  Sign out
                </button>
              </div>
            )}
          </div>
        </aside>
      </section>

      <section className="dashboard-grid">
        <article className="panel stack connector-catalog-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Connectors</span>
              <h2>Service connections</h2>
            </div>
            <span className="badge">{connectedCount} live</span>
          </div>
          <div className="connector-grid">
            {visibleConnectors.map((connector) => (
              <div
                key={connector.id}
                className={`connector-card connector-card-${connector.accent} ${selectedConnector === connector.id ? "selected" : ""}`}
                onClick={() => {
                  setSelectedConnector(connector.id);
                  if (mode === "catalog") {
                    router.push(`/dashboard/connectors/${connector.id}`);
                  }
                }}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelectedConnector(connector.id);
                    if (mode === "catalog") {
                      router.push(`/dashboard/connectors/${connector.id}`);
                    }
                  }
                }}
              >
                <div className="row row-spread">
                  <div>
                    <div className="connector-brand-row">
                      <span className={`connector-logo connector-logo-${connector.accent}`}>
                        <img src={connector.logoUrl} alt={`${connector.name} logo`} className="connector-logo-image" />
                      </span>
                      <div>
                        <strong>{connector.name}</strong>
                        <p className="muted connector-meta">
                          {connector.category} · {connector.auth}
                        </p>
                      </div>
                    </div>
                  </div>
                  <span className={`status-pill ${connector.status.toLowerCase().replace(/\s+/g, "-")}`}>{connector.status}</span>
                </div>
                <p className="muted">{connector.description}</p>
                <p className="connector-meta">Last activity: {connector.lastSync}</p>
                {connector.lastError ? <p className="danger-text">{connector.lastError}</p> : null}
                <div className="chip-row">
                  {connector.tools.slice(0, connector.id === "halopsa" ? 6 : 3).map((tool) => (
                    <span key={tool} className="chip">
                      {tool}
                    </span>
                  ))}
                </div>
                <p className="connector-meta">{connector.tools.length} MCP tools available</p>
                <div className="row">
                  <button
                    className="button primary"
                    onClick={(event) => {
                      event.stopPropagation();
                      if (mode === "catalog") {
                        router.push(`/dashboard/connectors/${connector.id}`);
                        return;
                      }
                      void connectConnector(connector.id);
                    }}
                    type="button"
                  >
                    Configure
                  </button>
                  <button
                    className="button secondary"
                    onClick={(event) => {
                      event.stopPropagation();
                      void disconnectConnector(connector.id);
                    }}
                    type="button"
                  >
                    Disconnect
                  </button>
                </div>
              </div>
            ))}
          </div>
        </article>
      </section>
    </div>
  );
}
