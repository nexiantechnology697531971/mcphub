"use client";

import { useState } from "react";

import { PageHeader } from "../../../components/page-header";
import { McpAccessPanel } from "../../../components/mcp-access-panel";
import { PermissionsPanel } from "../../../components/permissions-panel";
import { AuditPanel } from "../../../components/audit-panel";
import { AgentSettingsPanel } from "../../../components/agent-settings-panel";

type SettingsTab = "permissions" | "audit" | "mcp" | "agent";

const tabs: Array<{ id: SettingsTab; label: string; description: string }> = [
  { id: "permissions", label: "Permissions", description: "Tool guardrails" },
  { id: "audit", label: "Audit", description: "Operational trail" },
  { id: "mcp", label: "MCP URL", description: "Endpoint and bearer access" },
  { id: "agent", label: "Agent", description: "Azure Foundry connection" }
];

export default function SettingsPage() {
  const [active, setActive] = useState<SettingsTab>("permissions");
  const current = tabs.find((tab) => tab.id === active) ?? tabs[0];

  return (
    <div className="stack">
      <PageHeader
        eyebrow="Settings"
        title="Workspace settings"
        description="Manage guardrails, audit trail, the MCP endpoint, and the agent that powers chat."
      />

      <div className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab ${active === tab.id ? "active" : ""}`}
            onClick={() => setActive(tab.id)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      <PageHeader eyebrow={current.label} title={current.label} description={current.description} />

      {active === "permissions" ? <PermissionsPanel /> : null}
      {active === "audit" ? <AuditPanel /> : null}
      {active === "mcp" ? <McpAccessPanel /> : null}
      {active === "agent" ? <AgentSettingsPanel /> : null}
    </div>
  );
}
