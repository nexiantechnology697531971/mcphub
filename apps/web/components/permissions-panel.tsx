"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { PageHeader } from "./page-header";
import { readPlatformSession, type PlatformSession } from "../lib/platform-auth";

const productionGuardrails = [
  "Connector access is scoped per user and tenant.",
  "Provider tokens stay encrypted server-side and are never exposed to MCP clients.",
  "MCP tools are gated by the connected account, tenant membership, and role.",
  "Write actions remain explicitly constrained to guarded tools such as draft ticket creation and internal notes."
];

type ToolRow = {
  provider: string;
  name: string;
  description: string;
  enabled: boolean;
  isOverride: boolean;
  updatedAt?: string;
};

export function PermissionsPanel() {
  const router = useRouter();
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingTool, setSavingTool] = useState<string>("");
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

    async function loadPolicies() {
      setLoading(true);
      setNotice("");
      try {
        const response = await fetch(`${apiOrigin}/tool-policies`, {
          headers: { authorization: `Bearer ${session!.token}` }
        });
        if (!response.ok) {
          throw new Error(`Failed to load tool policies (${response.status})`);
        }
        const payload = (await response.json()) as { tools: ToolRow[] };
        if (!cancelled) setTools(payload.tools);
      } catch (error) {
        if (!cancelled) {
          setNotice(error instanceof Error ? error.message : "Could not load tool policies.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void loadPolicies();
    return () => {
      cancelled = true;
    };
  }, [session, apiOrigin]);

  async function togglePolicy(tool: ToolRow) {
    if (!session) return;
    const nextEnabled = !tool.enabled;
    setSavingTool(tool.name);
    setNotice("");

    setTools((current) =>
      current.map((row) => (row.name === tool.name ? { ...row, enabled: nextEnabled, isOverride: true } : row))
    );

    try {
      const response = await fetch(`${apiOrigin}/tool-policies/${encodeURIComponent(tool.name)}`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ enabled: nextEnabled })
      });
      if (!response.ok) {
        throw new Error(`Failed to update ${tool.name} (${response.status})`);
      }
    } catch (error) {
      setTools((current) =>
        current.map((row) => (row.name === tool.name ? { ...row, enabled: tool.enabled, isOverride: tool.isOverride } : row))
      );
      setNotice(error instanceof Error ? error.message : `Could not update ${tool.name}.`);
    } finally {
      setSavingTool("");
    }
  }

  async function resetPolicy(tool: ToolRow) {
    if (!session || !tool.isOverride) return;
    setSavingTool(tool.name);
    setNotice("");

    try {
      const response = await fetch(`${apiOrigin}/tool-policies/${encodeURIComponent(tool.name)}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${session.token}` }
      });
      if (!response.ok && response.status !== 204) {
        throw new Error(`Failed to reset ${tool.name} (${response.status})`);
      }
      setTools((current) =>
        current.map((row) => (row.name === tool.name ? { ...row, enabled: true, isOverride: false, updatedAt: undefined } : row))
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : `Could not reset ${tool.name}.`);
    } finally {
      setSavingTool("");
    }
  }

  const grouped = useMemo(() => {
    const map = new Map<string, ToolRow[]>();
    for (const tool of tools) {
      const list = map.get(tool.provider) ?? [];
      list.push(tool);
      map.set(tool.provider, list);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [tools]);

  return (
    <div className="stack">
      <div className="permission-list">
        {productionGuardrails.map((rule) => (
          <article key={rule} className="permission-item">
            <div>
              <strong>Enforced policy</strong>
              <p>{rule}</p>
            </div>
            <span className="status-pill connected">Active</span>
          </article>
        ))}
      </div>

      {notice ? <div className="notice">{notice}</div> : null}

      {loading ? (
        <div className="muted">Loading tool catalog…</div>
      ) : grouped.length === 0 ? (
        <div className="muted">No tools available for this tenant. Enable a module on the connectors page first.</div>
      ) : (
        grouped.map(([provider, providerTools]) => (
          <div key={provider} className="stack">
            <PageHeader
              eyebrow={provider}
              title={`${provider} tools`}
              description={`Toggle which ${provider} tools are exposed to MCP clients for this workspace.`}
            />
            <div className="permission-list">
              {providerTools.map((tool) => (
                <label key={tool.name} className="permission-item">
                  <div>
                    <strong>{tool.name}</strong>
                    <p>{tool.description}</p>
                    {tool.isOverride ? (
                      <p className="muted">
                        Override active{tool.updatedAt ? ` · ${new Date(tool.updatedAt).toLocaleString()}` : ""}
                        {" — "}
                        <button
                          type="button"
                          className="link"
                          onClick={() => void resetPolicy(tool)}
                          disabled={savingTool === tool.name}
                        >
                          reset to default
                        </button>
                      </p>
                    ) : null}
                  </div>
                  <button
                    className={`toggle ${tool.enabled ? "enabled" : ""}`}
                    onClick={() => void togglePolicy(tool)}
                    type="button"
                    aria-pressed={tool.enabled}
                    disabled={savingTool === tool.name}
                  >
                    <span />
                  </button>
                </label>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
