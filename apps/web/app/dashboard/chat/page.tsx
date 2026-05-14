import { PageHeader } from "../../../components/page-header";
import { AgentChat } from "../../../components/agent-chat";

export default function ChatPage() {
  return (
    <div className="stack">
      <PageHeader
        eyebrow="Chat"
        title="Talk to the Nexian AI agent"
        description="The agent is connected to your tools so can assist with anything you need"
      />
      <AgentChat />
    </div>
  );
}
