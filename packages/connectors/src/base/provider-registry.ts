import type { ProviderAdapter } from "@nexian/core/connectors/contracts";

import { actionStepAdapter } from "../actionstep/adapter";
import { cippAdapter } from "../cipp/adapter";
import { haloPsaAdapter } from "../halopsa/adapter";
import { hubspotAdapter } from "../hubspot/adapter";
import { itGlueAdapter } from "../itglue/adapter";
import { microsoft365Adapter } from "../microsoft365/adapter";
import { n8nAdapter } from "../n8n/adapter";
import { ninjaOneAdapter } from "../ninjaone/adapter";

const providers = [haloPsaAdapter, microsoft365Adapter, hubspotAdapter, itGlueAdapter, ninjaOneAdapter, cippAdapter, n8nAdapter, actionStepAdapter];

export function getProviderRegistry(): Map<string, ProviderAdapter> {
  return new Map(providers.map((provider) => [provider.provider, provider]));
}
