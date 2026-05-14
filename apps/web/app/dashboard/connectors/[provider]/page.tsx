import { notFound } from "next/navigation";

import { WorkspaceConsole } from "../../../../components/workspace-console";

const providers = new Set([
  "halopsa",
  "microsoft365",
  "ninjaone",
  "cipp",
  "n8n",
  "actionstep",
  "hubspot",
  "itglue"
]);

export default async function ConnectorDetailPage(props: {
  params: Promise<{ provider: string }>;
}) {
  const params = await props.params;
  if (!providers.has(params.provider)) {
    notFound();
  }

  return <WorkspaceConsole mode="detail" initialSelectedConnector={params.provider} />;
}
