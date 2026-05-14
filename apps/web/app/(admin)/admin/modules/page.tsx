"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { PageHeader } from "../../../../components/page-header";
import { readPlatformSession, type PlatformSession } from "../../../../lib/platform-auth";
import {
  createPlatformModule,
  deletePlatformModule,
  fetchPlatformModules,
  setModuleConnectors,
  updatePlatformModule,
  type PlatformModule
} from "../../../../lib/platform-api";

const KNOWN_PROVIDERS = [
  "halopsa",
  "ninjaone",
  "cipp",
  "itglue",
  "microsoft365",
  "hubspot",
  "n8n",
  "actionstep"
];

export default function AdminModulesPage() {
  const router = useRouter();
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [modules, setModules] = useState<PlatformModule[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newEnabledByDefault, setNewEnabledByDefault] = useState(true);

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
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  async function reload() {
    if (!session) return;
    setLoading(true);
    try {
      const payload = await fetchPlatformModules(session);
      setModules(payload.modules);
      if (!selectedId && payload.modules.length > 0) {
        setSelectedId(payload.modules[0].id);
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not load modules.");
    } finally {
      setLoading(false);
    }
  }

  const selected = useMemo(
    () => modules.find((module) => module.id === selectedId) ?? modules[0],
    [modules, selectedId]
  );

  const claimedProviders = useMemo(() => {
    const map = new Map<string, string>();
    for (const module of modules) {
      for (const provider of module.connectors) {
        map.set(provider, module.id);
      }
    }
    return map;
  }, [modules]);

  async function handleCreate() {
    if (!session || !newName.trim()) return;
    setNotice("");
    try {
      const payload = await createPlatformModule(
        {
          name: newName.trim(),
          description: newDescription.trim() || undefined,
          enabledByDefault: newEnabledByDefault
        },
        session
      );
      setNewName("");
      setNewDescription("");
      setNewEnabledByDefault(true);
      await reload();
      setSelectedId(payload.module.id);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not create module.");
    }
  }

  async function handleDelete(id: string) {
    if (!session) return;
    if (!confirm("Delete this module? Connector assignments will be removed.")) return;
    setNotice("");
    try {
      await deletePlatformModule(id, session);
      if (selectedId === id) setSelectedId(null);
      await reload();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not delete module.");
    }
  }

  async function handleToggleConnector(provider: string, isMember: boolean) {
    if (!session || !selected) return;
    setNotice("");
    try {
      const next = isMember
        ? selected.connectors.filter((p) => p !== provider)
        : [...selected.connectors, provider];
      await setModuleConnectors(selected.id, next, session);
      await reload();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not update connector assignment.");
    }
  }

  async function handleUpdateModule(patch: Partial<{ name: string; description: string | null; enabledByDefault: boolean }>) {
    if (!session || !selected) return;
    setNotice("");
    try {
      await updatePlatformModule(selected.id, patch, session);
      await reload();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not update module.");
    }
  }

  return (
    <div className="stack">
      <PageHeader
        eyebrow="Modules"
        title="Module catalog"
        description="Group connectors into modules (e.g. MSP, Legal). Disable a module per tenant to hide its connectors entirely."
      />

      {notice ? <div className="notice">{notice}</div> : null}

      <article className="panel stack">
        <h3>Create a new module</h3>
        <div className="field-grid">
          <label className="stack">
            <span className="field-label">Name</span>
            <input
              value={newName}
              onChange={(event) => setNewName(event.target.value)}
              placeholder="e.g. Sales"
            />
          </label>
          <label className="stack">
            <span className="field-label">Description (optional)</span>
            <input
              value={newDescription}
              onChange={(event) => setNewDescription(event.target.value)}
              placeholder="What sits inside this module?"
            />
          </label>
          <label className="stack">
            <span className="field-label">Enabled by default</span>
            <select
              value={newEnabledByDefault ? "true" : "false"}
              onChange={(event) => setNewEnabledByDefault(event.target.value === "true")}
            >
              <option value="true">On for new tenants</option>
              <option value="false">Off — admin must enable per tenant</option>
            </select>
          </label>
        </div>
        <div className="row">
          <button className="button" onClick={() => void handleCreate()} disabled={!newName.trim()}>
            Create module
          </button>
        </div>
      </article>

      <div className="split-panel">
        <article className="panel stack">
          <h3>Modules</h3>
          {loading ? (
            <p className="muted">Loading…</p>
          ) : modules.length === 0 ? (
            <p className="muted">No modules yet.</p>
          ) : (
            <ul className="module-list">
              {modules.map((module) => (
                <li key={module.id}>
                  <button
                    type="button"
                    className={`module-row ${module.id === selected?.id ? "is-active" : ""}`}
                    onClick={() => setSelectedId(module.id)}
                  >
                    <strong>{module.name}</strong>
                    <span className="muted">
                      {module.connectors.length} connector{module.connectors.length === 1 ? "" : "s"} ·{" "}
                      {module.enabledByDefault ? "default on" : "default off"}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </article>

        {selected ? (
          <article className="panel stack">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Module</span>
                <h2>{selected.name}</h2>
              </div>
              <button className="button secondary" onClick={() => void handleDelete(selected.id)}>
                Delete module
              </button>
            </div>

            <div className="field-grid">
              <label className="stack">
                <span className="field-label">Name</span>
                <input
                  defaultValue={selected.name}
                  key={`name-${selected.id}`}
                  onBlur={(event) =>
                    event.target.value.trim() && event.target.value !== selected.name
                      ? void handleUpdateModule({ name: event.target.value.trim() })
                      : undefined
                  }
                />
              </label>
              <label className="stack">
                <span className="field-label">Description</span>
                <input
                  defaultValue={selected.description ?? ""}
                  key={`desc-${selected.id}`}
                  onBlur={(event) =>
                    void handleUpdateModule({ description: event.target.value.trim() || null })
                  }
                />
              </label>
              <label className="stack">
                <span className="field-label">Default for new tenants</span>
                <select
                  value={selected.enabledByDefault ? "true" : "false"}
                  onChange={(event) =>
                    void handleUpdateModule({ enabledByDefault: event.target.value === "true" })
                  }
                >
                  <option value="true">On for new tenants</option>
                  <option value="false">Off — admin must enable per tenant</option>
                </select>
              </label>
            </div>

            <h3>Connectors in this module</h3>
            <p className="muted">
              A connector can belong to at most one module. Toggling it here moves it from any other
              module it was in.
            </p>
            <ul className="module-connectors">
              {KNOWN_PROVIDERS.map((provider) => {
                const owningModuleId = claimedProviders.get(provider);
                const isMember = selected.connectors.includes(provider);
                const conflict = owningModuleId && owningModuleId !== selected.id;
                return (
                  <li key={provider}>
                    <label className="module-connector-row">
                      <input
                        type="checkbox"
                        checked={isMember}
                        onChange={() => void handleToggleConnector(provider, isMember)}
                      />
                      <span>
                        <strong>{provider}</strong>
                        {conflict ? (
                          <span className="muted"> — currently in {modules.find((m) => m.id === owningModuleId)?.name}</span>
                        ) : null}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
          </article>
        ) : null}
      </div>
    </div>
  );
}
