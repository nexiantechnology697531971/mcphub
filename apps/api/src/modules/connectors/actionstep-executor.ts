import type { ConnectedAccountRecord } from "@nexian/core/domain/models";
import { TokenEncryptionService } from "@nexian/core/security/encryption";
import type { NormalizedToolResponse } from "@nexian/core/mcp/tools";

export interface ActionStepExecutorDeps {
  encryption: TokenEncryptionService;
  ensureFresh: (account: ConnectedAccountRecord) => Promise<ConnectedAccountRecord>;
}

const SOURCE = "actionstep";

function getApiEndpoint(account: ConnectedAccountRecord): string {
  const metadata = (account.metadataJson ?? {}) as { apiEndpoint?: string };
  const endpoint = metadata.apiEndpoint?.replace(/\/$/, "");
  if (!endpoint) {
    throw new Error(
      "ActionStep account is missing the api_endpoint metadata — reconnect the account to capture it."
    );
  }
  return endpoint;
}

function readString(input: Record<string, unknown>, key: string): string | undefined {
  const value = input[key];
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function readNumber(input: Record<string, unknown>, key: string): number | undefined {
  const value = input[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0 && !Number.isNaN(Number(value))) {
    return Number(value);
  }
  return undefined;
}

function buildUrl(endpoint: string, path: string, query: Record<string, string | number | undefined>) {
  const url = new URL(`${endpoint}${path}`);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url;
}

async function fetchWithRefresh(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  url: URL,
  init: RequestInit = {}
): Promise<{ payload: unknown; status: number }> {
  const callOnce = async (currentAccount: ConnectedAccountRecord) => {
    const token = deps.encryption.decrypt(currentAccount.accessTokenEncrypted);
    return fetch(url.toString(), {
      ...init,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        ...(init.headers ?? {})
      }
    });
  };

  let response = await callOnce(account);

  if (response.status === 401) {
    const refreshed = await deps.ensureFresh(account);
    response = await callOnce(refreshed);
  }

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`ActionStep ${url.pathname} failed (${response.status}): ${text.slice(0, 500)}`);
  }

  if (!text) {
    return { payload: {}, status: response.status };
  }

  try {
    return { payload: JSON.parse(text), status: response.status };
  } catch {
    throw new Error(`ActionStep returned non-JSON response (${response.status})`);
  }
}

function pickCollection(payload: unknown, key: string): Record<string, unknown>[] {
  if (!payload || typeof payload !== "object") return [];
  const obj = payload as Record<string, unknown>;
  const direct = obj[key];
  if (Array.isArray(direct)) return direct.filter((item): item is Record<string, unknown> => !!item && typeof item === "object");
  if (direct && typeof direct === "object" && !Array.isArray(direct)) {
    return [direct as Record<string, unknown>];
  }
  return [];
}

function pickSingle(payload: unknown, key: string): Record<string, unknown> | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const obj = payload as Record<string, unknown>;
  const direct = obj[key];
  if (direct && typeof direct === "object" && !Array.isArray(direct)) return direct as Record<string, unknown>;
  if (Array.isArray(direct) && direct.length > 0 && typeof direct[0] === "object") {
    return direct[0] as Record<string, unknown>;
  }
  return undefined;
}

function pagination(input: Record<string, unknown>) {
  return {
    page: readNumber(input, "page"),
    pageSize: readNumber(input, "pageSize") ?? 25
  };
}

async function listActions(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const { page, pageSize } = pagination(input);
  const url = buildUrl(endpoint, "/api/rest/actions", {
    page,
    pageSize,
    name: readString(input, "query"),
    status: readString(input, "status"),
    assignedTo: readNumber(input, "assigned_to_participant_id"),
    primaryParticipant: readNumber(input, "client_participant_id")
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const actions = pickCollection(payload, "actions");
  return {
    summary: `Found ${actions.length} matter${actions.length === 1 ? "" : "s"} in ActionStep.`,
    data: actions,
    source: SOURCE
  };
}

async function getAction(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  if (!matterId) {
    throw new Error("matter_id is required");
  }
  const url = buildUrl(endpoint, `/api/rest/actions/${matterId}`, {});
  const { payload } = await fetchWithRefresh(deps, account, url);
  const action = pickSingle(payload, "actions");
  return {
    summary: action ? `Loaded matter ${matterId}.` : `No matter found with ID ${matterId}.`,
    data: action ? [action] : [],
    source: SOURCE
  };
}

async function listParticipants(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const { page, pageSize } = pagination(input);
  const url = buildUrl(endpoint, "/api/rest/participants", {
    page,
    pageSize,
    name: readString(input, "query"),
    email: readString(input, "email"),
    participantType: readString(input, "type")
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const participants = pickCollection(payload, "participants");
  return {
    summary: `Found ${participants.length} participant${participants.length === 1 ? "" : "s"} in ActionStep.`,
    data: participants,
    source: SOURCE
  };
}

async function getParticipant(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const participantId = readNumber(input, "participant_id");
  if (!participantId) {
    throw new Error("participant_id is required");
  }
  const url = buildUrl(endpoint, `/api/rest/participants/${participantId}`, {});
  const { payload } = await fetchWithRefresh(deps, account, url);
  const participant = pickSingle(payload, "participants");
  return {
    summary: participant ? `Loaded participant ${participantId}.` : `No participant found with ID ${participantId}.`,
    data: participant ? [participant] : [],
    source: SOURCE
  };
}

async function listTasks(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const { page, pageSize } = pagination(input);
  const url = buildUrl(endpoint, "/api/rest/tasks", {
    page,
    pageSize,
    action: readNumber(input, "matter_id"),
    assignee: readNumber(input, "assigned_to_participant_id"),
    status: readString(input, "status")
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const tasks = pickCollection(payload, "tasks");
  return {
    summary: `Found ${tasks.length} task${tasks.length === 1 ? "" : "s"} in ActionStep.`,
    data: tasks,
    source: SOURCE
  };
}

async function listTimeEntries(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const { page, pageSize } = pagination(input);
  const url = buildUrl(endpoint, "/api/rest/timerecords", {
    page,
    pageSize,
    action: readNumber(input, "matter_id"),
    participant: readNumber(input, "participant_id"),
    dateFrom: readString(input, "date_from"),
    dateTo: readString(input, "date_to")
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const entries = pickCollection(payload, "timerecords");
  return {
    summary: `Found ${entries.length} time entr${entries.length === 1 ? "y" : "ies"} in ActionStep.`,
    data: entries,
    source: SOURCE
  };
}

export async function executeActionStepTool(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  toolName: string,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  switch (toolName) {
    case "list_matters":
    case "search_matters":
      return listActions(deps, account, input);
    case "get_matter":
      return getAction(deps, account, input);
    case "list_participants":
    case "search_participants":
      return listParticipants(deps, account, input);
    case "get_participant":
      return getParticipant(deps, account, input);
    case "list_tasks_for_matter":
      return listTasks(deps, account, input);
    case "list_time_entries":
      return listTimeEntries(deps, account, input);
    default:
      throw new Error(`Unknown ActionStep tool: ${toolName}`);
  }
}
