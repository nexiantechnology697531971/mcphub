"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { readPlatformSession, type PlatformSession } from "../lib/platform-auth";

type AgentConfig = {
  azureAgentResponsesUrl: string;
  azureAgentActivityUrl: string;
  azureAgentPrincipalId: string;
  azureAgentTenantId: string;
  azureAgentApiKey: string;
  hasAzureAgentApiKey: boolean;
};

const emptyConfig: AgentConfig = {
  azureAgentResponsesUrl: "",
  azureAgentActivityUrl: "",
  azureAgentPrincipalId: "",
  azureAgentTenantId: "",
  azureAgentApiKey: "",
  hasAzureAgentApiKey: false
};

export function AgentSettingsPanel() {
  const router = useRouter();
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [config, setConfig] = useState<AgentConfig>(emptyConfig);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");

  const apiOrigin = useMemo(() => {
    if (typeof window === "undefined") {
      return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
    }
    return process.env.NEXT_PUBLIC_API_URL ?? window.location.origin.replace(":3000", ":4000");
  }, []);

  useEffect(() => {
    const stored = readPlatformSession();
    if (!stored) {
      router.replace("/auth/login");
      return;
    }
    setSession(stored);
  }, [router]);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        const response = await fetch(`${apiOrigin}/connector-config/actionstep`, {
          headers: { authorization: `Bearer ${session!.token}` }
        });
        if (!response.ok) throw new Error(`Failed to load agent settings (${response.status})`);
        const payload = (await response.json()) as { config: Partial<AgentConfig> };
        if (!cancelled) {
          setConfig({
            azureAgentResponsesUrl: payload.config.azureAgentResponsesUrl ?? "",
            azureAgentActivityUrl: payload.config.azureAgentActivityUrl ?? "",
            azureAgentPrincipalId: payload.config.azureAgentPrincipalId ?? "",
            azureAgentTenantId: payload.config.azureAgentTenantId ?? "",
            azureAgentApiKey: "",
            hasAzureAgentApiKey: Boolean(payload.config.hasAzureAgentApiKey)
          });
        }
      } catch (error) {
        if (!cancelled) {
          setNotice(error instanceof Error ? error.message : "Could not load agent settings.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [session, apiOrigin]);

  async function save() {
    if (!session) return;
    setSaving(true);
    setNotice("");
    try {
      const response = await fetch(`${apiOrigin}/connector-config/actionstep`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          azureAgentResponsesUrl: config.azureAgentResponsesUrl,
          azureAgentActivityUrl: config.azureAgentActivityUrl,
          azureAgentPrincipalId: config.azureAgentPrincipalId,
          azureAgentTenantId: config.azureAgentTenantId,
          azureAgentApiKey: config.azureAgentApiKey
        })
      });
      const payload = (await response.json()) as {
        config?: Partial<AgentConfig>;
        error?: string;
        message?: string;
      };
      if (!response.ok) {
        throw new Error(payload.message ?? payload.error ?? "Failed to save agent settings.");
      }
      setConfig((current) => ({
        ...current,
        azureAgentResponsesUrl: payload.config?.azureAgentResponsesUrl ?? current.azureAgentResponsesUrl,
        azureAgentActivityUrl: payload.config?.azureAgentActivityUrl ?? current.azureAgentActivityUrl,
        azureAgentPrincipalId: payload.config?.azureAgentPrincipalId ?? current.azureAgentPrincipalId,
        azureAgentTenantId: payload.config?.azureAgentTenantId ?? current.azureAgentTenantId,
        azureAgentApiKey: "",
        hasAzureAgentApiKey: Boolean(payload.config?.hasAzureAgentApiKey)
      }));
      setNotice("Agent settings saved.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not save agent settings.");
    } finally {
      setSaving(false);
    }
  }

  function update(patch: Partial<AgentConfig>) {
    setConfig((current) => ({ ...current, ...patch }));
  }

  if (loading) {
    return <div className="muted">Loading agent settings…</div>;
  }

  return (
    <div className="stack">
      {notice ? <div className="notice">{notice}</div> : null}
      <p className="muted">
        These settings power the Chat tab. Get the endpoints and key from the Agent application details page in Azure AI Foundry.
      </p>
      <div className="field-grid">
        <label className="stack">
          <span className="field-label">Responses endpoint</span>
          <input
            value={config.azureAgentResponsesUrl}
            onChange={(event) => update({ azureAgentResponsesUrl: event.target.value })}
            placeholder="https://…/protocols/openai/responses?api-version=…"
          />
        </label>
        <label className="stack">
          <span className="field-label">Activity protocol endpoint</span>
          <input
            value={config.azureAgentActivityUrl}
            onChange={(event) => update({ azureAgentActivityUrl: event.target.value })}
            placeholder="https://…/protocols/activityprotocol?api-version=…"
          />
        </label>
        <label className="stack">
          <span className="field-label">Principal ID</span>
          <input
            value={config.azureAgentPrincipalId}
            onChange={(event) => update({ azureAgentPrincipalId: event.target.value })}
            placeholder="Agent principal (object) ID"
          />
        </label>
        <label className="stack">
          <span className="field-label">Azure tenant ID</span>
          <input
            value={config.azureAgentTenantId}
            onChange={(event) => update({ azureAgentTenantId: event.target.value })}
            placeholder="Entra tenant ID"
          />
        </label>
      </div>
      <label className="stack">
        <span className="field-label">API key or access token</span>
        <input
          type="password"
          value={config.azureAgentApiKey}
          onChange={(event) => update({ azureAgentApiKey: event.target.value })}
          placeholder={
            config.hasAzureAgentApiKey
              ? "Saved already. Enter a new key to replace it."
              : "API key or bearer token for the Responses endpoint"
          }
        />
        <span className="connector-meta">
          {config.hasAzureAgentApiKey ? "A key is already saved." : "No key saved yet."}
        </span>
      </label>
      <div className="row">
        <button className="button primary" type="button" onClick={() => void save()} disabled={saving}>
          {saving ? "Saving…" : "Save agent settings"}
        </button>
      </div>
    </div>
  );
}
