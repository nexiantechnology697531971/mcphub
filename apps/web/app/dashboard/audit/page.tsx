import { PageHeader } from "../../../components/page-header";
import { AuditPanel } from "../../../components/audit-panel";

export default function AuditPage() {
  return (
    <div className="stack">
      <PageHeader
        eyebrow="Workspace Audit"
        title="Operational activity"
        description="Review connector changes, token issuance, and policy events for this managed workspace."
      />
      <AuditPanel />
    </div>
  );
}
