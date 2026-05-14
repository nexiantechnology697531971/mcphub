import { PageHeader } from "../../../components/page-header";
import { AgentChat } from "../../../components/agent-chat";

export default function ChatPage() {
  return (
    <div className="stack">
      <PageHeader
        eyebrow="Chat"
        title="Talk to the Nexian agent"
        description="The agent can reach any tool wired into this workspace — matters, tickets, contacts, workflows, and more."
      />
      <AgentChat />
    </div>
  );
}
