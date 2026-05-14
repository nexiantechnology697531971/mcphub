import { PageHeader } from "../../../components/page-header";
import { PermissionsPanel } from "../../../components/permissions-panel";

export default function PermissionsPage() {
  return (
    <div className="stack">
      <PageHeader
        eyebrow="Guardrails"
        title="Tool permissions"
        description="Toggle which tools are exposed to MCP clients for this workspace. Disabled tools are hidden from tools/list and rejected at execution."
      />
      <PermissionsPanel />
    </div>
  );
}
