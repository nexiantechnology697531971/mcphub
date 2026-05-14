import type { ConnectedAccountRecord } from "@nexian/core/domain/models";
import { TokenEncryptionService } from "@nexian/core/security/encryption";
import type { NormalizedToolResponse } from "@nexian/core/mcp/tools";

export interface ActionStepExecutorDeps {
  encryption: TokenEncryptionService;
  ensureFresh: (account: ConnectedAccountRecord) => Promise<ConnectedAccountRecord>;
  forceRefresh: (account: ConnectedAccountRecord) => Promise<ConnectedAccountRecord>;
}

const SOURCE = "actionstep";

function getApiEndpoint(account: ConnectedAccountRecord): string {
  const metadata = (account.metadataJson ?? {}) as { apiEndpoint?: string };
  const raw = metadata.apiEndpoint?.trim();
  if (!raw) {
    throw new Error(
      "ActionStep account is missing the api_endpoint metadata — reconnect the account to capture it."
    );
  }
  return raw.replace(/\/+$/, "").replace(/\/api(?:\/rest)?$/i, "");
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
        accept: "application/vnd.api+json",
        authorization: `Bearer ${token}`,
        ...(init.headers ?? {})
      }
    });
  };

  let response = await callOnce(account);

  if (response.status === 401) {
    const refreshed = await deps.forceRefresh(account);
    if (refreshed.status !== "ACTIVE") {
      throw new Error(
        `ActionStep token refresh failed after 401: ${refreshed.lastError ?? "no refresh token available"}`
      );
    }
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

type PagingMeta = {
  recordCount?: number;
  pageCount?: number;
  page?: number;
  pageSize?: number;
};

function extractPaging(payload: unknown): PagingMeta {
  if (!payload || typeof payload !== "object") return {};
  const meta = (payload as Record<string, unknown>).meta;
  if (!meta || typeof meta !== "object") return {};
  const paging = (meta as Record<string, unknown>).paging;
  if (!paging || typeof paging !== "object") return {};
  const p = paging as Record<string, unknown>;
  const records = (p.records ?? {}) as Record<string, unknown>;
  return {
    recordCount: typeof records.recordCount === "number"
      ? records.recordCount
      : typeof p.totalRecords === "number"
        ? (p.totalRecords as number)
        : undefined,
    pageCount: typeof records.pageCount === "number"
      ? records.pageCount
      : typeof p.totalPages === "number"
        ? (p.totalPages as number)
        : undefined,
    page: typeof p.page === "number" ? (p.page as number) : undefined,
    pageSize: typeof p.resultsPerPage === "number"
      ? (p.resultsPerPage as number)
      : typeof p.pageSize === "number"
        ? (p.pageSize as number)
        : undefined
  };
}

const AUTO_PAGE_HARD_CAP = 5; // pages × pageSize (200) = 1000 records max
const AUTO_PAGE_SIZE = 200;

async function fetchAllPages(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  endpoint: string,
  path: string,
  baseQuery: Record<string, string | number | undefined>,
  collectionKey: string
): Promise<{ records: Record<string, unknown>[]; paging: PagingMeta; pagesFetched: number }> {
  const records: Record<string, unknown>[] = [];
  let pagesFetched = 0;
  let lastPaging: PagingMeta = {};

  for (let page = 1; page <= AUTO_PAGE_HARD_CAP; page++) {
    const url = buildUrl(endpoint, path, { ...baseQuery, page, pageSize: AUTO_PAGE_SIZE });
    const { payload } = await fetchWithRefresh(deps, account, url);
    const slice = pickCollection(payload, collectionKey);
    records.push(...slice);
    pagesFetched++;
    lastPaging = extractPaging(payload);

    const totalPages = lastPaging.pageCount;
    if (slice.length < AUTO_PAGE_SIZE) break;
    if (typeof totalPages === "number" && page >= totalPages) break;
  }

  return { records, paging: lastPaging, pagesFetched };
}

function isFullPayload(input: Record<string, unknown>): boolean {
  const value = input["include_full"];
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.toLowerCase() === "true";
  return false;
}

function pickFields(record: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const value = record[key];
    if (value === null || value === undefined || value === "") continue;
    out[key] = value;
  }
  return out;
}

function pickLinkFields(record: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const links = record.links;
  if (!links || typeof links !== "object" || Array.isArray(links)) return {};
  return pickFields(links as Record<string, unknown>, keys);
}

function truncate(value: unknown, max = 500): unknown {
  if (typeof value !== "string") return value;
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…(truncated)`;
}

function wrapWildcard(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  return trimmed.includes("*") ? trimmed : `*${trimmed}*`;
}

function normalizeDigits(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value !== "string" && typeof value !== "number") return "";
  return String(value).replace(/\D/g, "");
}

function participantMatchesPhone(participant: Record<string, unknown>, queryDigits: string): boolean {
  if (!queryDigits) return true;
  for (let slot = 1; slot <= 4; slot++) {
    const country = normalizeDigits(participant[`phone${slot}Country`]);
    const area = normalizeDigits(participant[`phone${slot}Area`]);
    const number = normalizeDigits(participant[`phone${slot}Number`]);
    if (!number && !area && !country) continue;
    const combined = `${country}${area}${number}`;
    if (combined.includes(queryDigits)) return true;
    if (number && number.includes(queryDigits)) return true;
  }
  return false;
}

const MATTER_FIELDS = [
  "id",
  "name",
  "reference",
  "status",
  "priority",
  "isBillable",
  "dueTimestamp",
  "lastActivityTimestamp",
  "createdTimestamp",
  "modifiedTimestamp"
] as const;

const MATTER_LINK_FIELDS = ["actionType", "assignedTo", "primaryParticipants", "step"] as const;

function slimMatter(record: Record<string, unknown>): Record<string, unknown> {
  return {
    ...pickFields(record, MATTER_FIELDS),
    links: pickLinkFields(record, MATTER_LINK_FIELDS)
  };
}

const PARTICIPANT_FIELDS = [
  "id",
  "displayName",
  "firstName",
  "lastName",
  "companyName",
  "isCompany",
  "email",
  "salutation",
  "phone1Label",
  "phone1Country",
  "phone1Area",
  "phone1Number",
  "phone2Label",
  "phone2Country",
  "phone2Area",
  "phone2Number",
  "phone3Label",
  "phone3Country",
  "phone3Area",
  "phone3Number",
  "phone4Label",
  "phone4Country",
  "phone4Area",
  "phone4Number"
] as const;

const PARTICIPANT_LINK_FIELDS = ["participantType"] as const;

function slimParticipant(record: Record<string, unknown>): Record<string, unknown> {
  return {
    ...pickFields(record, PARTICIPANT_FIELDS),
    links: pickLinkFields(record, PARTICIPANT_LINK_FIELDS)
  };
}

const TASK_FIELDS = [
  "id",
  "name",
  "description",
  "status",
  "priority",
  "dueTimestamp",
  "completedTimestamp",
  "createdTimestamp"
] as const;

const TASK_LINK_FIELDS = ["action", "assignee", "createdBy"] as const;

function slimTask(record: Record<string, unknown>): Record<string, unknown> {
  return {
    ...pickFields(record, TASK_FIELDS),
    description: truncate(record.description, 400),
    links: pickLinkFields(record, TASK_LINK_FIELDS)
  };
}

const TIMERECORD_FIELDS = [
  "id",
  "date",
  "start",
  "end",
  "duration",
  "units",
  "actualUnits",
  "actualMinutes",
  "chargeableUnits",
  "chargeableMinutes",
  "chargeableValue",
  "billableValue",
  "billable",
  "billed",
  "chargeable",
  "rate",
  "total",
  "notes",
  "narrative",
  "description",
  "createdTimestamp",
  "modifiedTimestamp"
] as const;

const TIMERECORD_LINK_FIELDS = ["action", "participant", "activity", "user", "feeEarner", "timekeeper"] as const;

function slimTimeRecord(record: Record<string, unknown>): Record<string, unknown> {
  const base = pickFields(record, TIMERECORD_FIELDS);
  return {
    ...base,
    notes: truncate(base.notes, 400),
    narrative: truncate(base.narrative, 400),
    description: truncate(base.description, 400),
    links: pickLinkFields(record, TIMERECORD_LINK_FIELDS)
  };
}

const FILENOTE_FIELDS = [
  "id",
  "text",
  "note",
  "subject",
  "enteredTimestamp",
  "noteTimestamp",
  "createdTimestamp"
] as const;

const FILENOTE_LINK_FIELDS = ["action", "enteredBy", "participant"] as const;

function slimFileNote(record: Record<string, unknown>): Record<string, unknown> {
  const base = pickFields(record, FILENOTE_FIELDS);
  return {
    ...base,
    text: truncate(base.text, 800),
    note: truncate(base.note, 800),
    links: pickLinkFields(record, FILENOTE_LINK_FIELDS)
  };
}

const EMAIL_FIELDS = [
  "id",
  "subject",
  "fromAddress",
  "fromName",
  "toAddresses",
  "ccAddresses",
  "sentTimestamp",
  "receivedTimestamp",
  "direction",
  "summary",
  "body",
  "textBody"
] as const;

const EMAIL_LINK_FIELDS = ["action", "fromParticipant", "toParticipants"] as const;

function slimEmail(record: Record<string, unknown>): Record<string, unknown> {
  const base = pickFields(record, EMAIL_FIELDS);
  return {
    ...base,
    body: truncate(base.body, 600),
    textBody: truncate(base.textBody, 600),
    summary: truncate(base.summary, 600),
    links: pickLinkFields(record, EMAIL_LINK_FIELDS)
  };
}

async function listActions(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const { page, pageSize } = pagination(input);
  const rawQuery = readString(input, "query");
  const rawDescription = readString(input, "description");
  const rawReference = readString(input, "reference");
  const sharedFilters = {
    status: readString(input, "status"),
    assignedTo: readNumber(input, "assigned_to_participant_id"),
    primaryParticipant: readNumber(input, "client_participant_id")
  };

  let actions: Record<string, unknown>[];

  if (rawQuery && !rawDescription && !rawReference) {
    const wildcardQuery = wrapWildcard(rawQuery);
    const fanOutFields = ["name", "reference", "description"] as const;
    const slotResponses = await Promise.allSettled(
      fanOutFields.map((field) =>
        fetchWithRefresh(
          deps,
          account,
          buildUrl(endpoint, "/api/rest/actions", {
            pageSize,
            [field]: wildcardQuery,
            ...sharedFilters
          })
        )
      )
    );

    const merged = new Map<string, Record<string, unknown>>();
    for (const result of slotResponses) {
      if (result.status !== "fulfilled") continue;
      for (const action of pickCollection(result.value.payload, "actions")) {
        const id = action.id !== undefined ? String(action.id) : JSON.stringify(action);
        if (!merged.has(id)) merged.set(id, action);
      }
    }
    actions = [...merged.values()];
  } else {
    const url = buildUrl(endpoint, "/api/rest/actions", {
      page,
      pageSize,
      name: rawQuery ? wrapWildcard(rawQuery) : undefined,
      description: rawDescription ? wrapWildcard(rawDescription) : undefined,
      reference: rawReference ? wrapWildcard(rawReference) : undefined,
      ...sharedFilters
    });
    const { payload } = await fetchWithRefresh(deps, account, url);
    actions = pickCollection(payload, "actions");
  }

  const summary = rawQuery && !rawDescription && !rawReference
    ? `Found ${actions.length} matter${actions.length === 1 ? "" : "s"} in ActionStep matching "${rawQuery}" across name / reference / description.`
    : `Found ${actions.length} matter${actions.length === 1 ? "" : "s"} in ActionStep.`;

  return {
    summary,
    data: isFullPayload(input) ? actions : actions.map(slimMatter),
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
    data: action ? [isFullPayload(input) ? action : slimMatter(action)] : [],
    source: SOURCE
  };
}

async function listParticipants(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const phoneQuery = readString(input, "phone");
  const phoneDigits = normalizeDigits(phoneQuery);
  const isPhoneSearch = Boolean(phoneDigits);

  const { page, pageSize: requestedPageSize } = pagination(input);
  // For phone searches we filter client-side across slots 1-4, so widen the
  // page size to the API maximum to reduce the chance of missing matches.
  const pageSize = isPhoneSearch && requestedPageSize < 200 ? 200 : requestedPageSize;

  const rawQuery = readString(input, "query");
  const url = buildUrl(endpoint, "/api/rest/participants", {
    page,
    pageSize,
    displayName: rawQuery ? wrapWildcard(rawQuery) : undefined,
    email: readString(input, "email"),
    participantType: readString(input, "type")
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const fetched = pickCollection(payload, "participants");
  const filtered = isPhoneSearch
    ? fetched.filter((participant) => participantMatchesPhone(participant, phoneDigits))
    : fetched;

  const summaryBase = `Found ${filtered.length} participant${filtered.length === 1 ? "" : "s"} in ActionStep`;
  const summary = isPhoneSearch
    ? `${summaryBase} matching phone "${phoneQuery}" (out of ${fetched.length} on this page).`
    : `${summaryBase}.`;

  return {
    summary,
    data: isFullPayload(input) ? filtered : filtered.map(slimParticipant),
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
    data: participant ? [isFullPayload(input) ? participant : slimParticipant(participant)] : [],
    source: SOURCE
  };
}

async function listTasks(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  const baseQuery = {
    action: matterId,
    assignee: readNumber(input, "assigned_to_participant_id"),
    status: readString(input, "status")
  };

  let tasks: Record<string, unknown>[];
  let paging: PagingMeta = {};
  let pagesFetched = 0;

  if (matterId !== undefined) {
    const result = await fetchAllPages(deps, account, endpoint, "/api/rest/tasks", baseQuery, "tasks");
    tasks = result.records;
    paging = result.paging;
    pagesFetched = result.pagesFetched;
  } else {
    const { page, pageSize } = pagination(input);
    const url = buildUrl(endpoint, "/api/rest/tasks", { ...baseQuery, page, pageSize });
    const { payload } = await fetchWithRefresh(deps, account, url);
    tasks = pickCollection(payload, "tasks");
    paging = extractPaging(payload);
    pagesFetched = 1;
  }

  const totalKnown = paging.recordCount;
  const truncatedNote =
    typeof totalKnown === "number" && tasks.length < totalKnown
      ? ` (ActionStep reports ${totalKnown} total; fetched ${pagesFetched} page(s)).`
      : "";

  return {
    summary: `Found ${tasks.length} task${tasks.length === 1 ? "" : "s"}${matterId ? ` on matter ${matterId}` : ""} in ActionStep.${truncatedNote}`,
    data: isFullPayload(input) ? tasks : tasks.map(slimTask),
    source: SOURCE
  };
}

async function listTimeEntries(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  const participantId = readNumber(input, "participant_id");
  const dateFrom = readString(input, "date_from");
  const dateTo = readString(input, "date_to");

  const baseQuery = {
    action: matterId,
    participant: participantId,
    dateFrom,
    dateTo
  };

  let entries: Record<string, unknown>[];
  let paging: PagingMeta = {};
  let pagesFetched = 0;

  if (matterId !== undefined) {
    const result = await fetchAllPages(deps, account, endpoint, "/api/rest/timerecords", baseQuery, "timerecords");
    entries = result.records;
    paging = result.paging;
    pagesFetched = result.pagesFetched;
  } else {
    const { page, pageSize } = pagination(input);
    const url = buildUrl(endpoint, "/api/rest/timerecords", { ...baseQuery, page, pageSize });
    const { payload } = await fetchWithRefresh(deps, account, url);
    entries = pickCollection(payload, "timerecords");
    paging = extractPaging(payload);
    pagesFetched = 1;
  }

  const totalKnown = paging.recordCount;
  const pageCount = paging.pageCount;
  const truncatedNote =
    typeof totalKnown === "number" && entries.length < totalKnown
      ? ` (ActionStep reports ${totalKnown} total across ${pageCount ?? "?"} page(s); fetched ${pagesFetched} page(s)).`
      : "";

  return {
    summary: `Found ${entries.length} time entr${entries.length === 1 ? "y" : "ies"}${matterId ? ` on matter ${matterId}` : ""} in ActionStep.${truncatedNote}`,
    data: isFullPayload(input) ? entries : entries.map(slimTimeRecord),
    source: SOURCE
  };
}

async function listFileNotes(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  const baseQuery = {
    action: matterId,
    enteredBy: readNumber(input, "entered_by_participant_id"),
    dateFrom: readString(input, "date_from"),
    dateTo: readString(input, "date_to")
  };

  let notes: Record<string, unknown>[];
  let paging: PagingMeta = {};
  let pagesFetched = 0;

  if (matterId !== undefined) {
    const result = await fetchAllPages(deps, account, endpoint, "/api/rest/filenotes", baseQuery, "filenotes");
    notes = result.records;
    paging = result.paging;
    pagesFetched = result.pagesFetched;
  } else {
    const { page, pageSize } = pagination(input);
    const url = buildUrl(endpoint, "/api/rest/filenotes", { ...baseQuery, page, pageSize });
    const { payload } = await fetchWithRefresh(deps, account, url);
    notes = pickCollection(payload, "filenotes");
    paging = extractPaging(payload);
    pagesFetched = 1;
  }

  const totalKnown = paging.recordCount;
  const truncatedNote =
    typeof totalKnown === "number" && notes.length < totalKnown
      ? ` (ActionStep reports ${totalKnown} total; fetched ${pagesFetched} page(s)).`
      : "";

  return {
    summary: `Found ${notes.length} file note${notes.length === 1 ? "" : "s"}${matterId ? ` on matter ${matterId}` : ""} in ActionStep.${truncatedNote}`,
    data: isFullPayload(input) ? notes : notes.map(slimFileNote),
    source: SOURCE
  };
}

async function listEmails(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  const baseQuery = {
    action: matterId,
    participant: readNumber(input, "participant_id"),
    dateFrom: readString(input, "date_from"),
    dateTo: readString(input, "date_to")
  };

  let emails: Record<string, unknown>[];
  let paging: PagingMeta = {};
  let pagesFetched = 0;

  if (matterId !== undefined) {
    const result = await fetchAllPages(deps, account, endpoint, "/api/rest/emails", baseQuery, "emails");
    emails = result.records;
    paging = result.paging;
    pagesFetched = result.pagesFetched;
  } else {
    const { page, pageSize } = pagination(input);
    const url = buildUrl(endpoint, "/api/rest/emails", { ...baseQuery, page, pageSize });
    const { payload } = await fetchWithRefresh(deps, account, url);
    emails = pickCollection(payload, "emails");
    paging = extractPaging(payload);
    pagesFetched = 1;
  }

  const totalKnown = paging.recordCount;
  const truncatedNote =
    typeof totalKnown === "number" && emails.length < totalKnown
      ? ` (ActionStep reports ${totalKnown} total; fetched ${pagesFetched} page(s)).`
      : "";

  return {
    summary: `Found ${emails.length} email${emails.length === 1 ? "" : "s"}${matterId ? ` on matter ${matterId}` : ""} in ActionStep.${truncatedNote}`,
    data: isFullPayload(input) ? emails : emails.map(slimEmail),
    source: SOURCE
  };
}

async function getMatterSummary(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const endpoint = getApiEndpoint(account);
  const matterId = readNumber(input, "matter_id");
  if (!matterId) {
    throw new Error("matter_id is required");
  }

  const notesPageSize = readNumber(input, "notes_page_size") ?? 25;
  const tasksPageSize = readNumber(input, "tasks_page_size") ?? 25;
  const timePageSize = readNumber(input, "time_page_size") ?? 25;
  const emailsPageSize = readNumber(input, "emails_page_size") ?? 25;

  const matterUrl = buildUrl(endpoint, `/api/rest/actions/${matterId}`, {});
  const notesUrl = buildUrl(endpoint, "/api/rest/filenotes", {
    action: matterId,
    pageSize: notesPageSize,
    sort: "-enteredTimestamp"
  });
  const tasksUrl = buildUrl(endpoint, "/api/rest/tasks", {
    action: matterId,
    pageSize: tasksPageSize
  });
  const timeUrl = buildUrl(endpoint, "/api/rest/timerecords", {
    action: matterId,
    pageSize: timePageSize,
    sort: "-date"
  });
  const emailsUrl = buildUrl(endpoint, "/api/rest/emails", {
    action: matterId,
    pageSize: emailsPageSize,
    sort: "-sentTimestamp"
  });

  const [matterRes, notesRes, tasksRes, timeRes, emailsRes] = await Promise.allSettled([
    fetchWithRefresh(deps, account, matterUrl),
    fetchWithRefresh(deps, account, notesUrl),
    fetchWithRefresh(deps, account, tasksUrl),
    fetchWithRefresh(deps, account, timeUrl),
    fetchWithRefresh(deps, account, emailsUrl)
  ]);

  const full = isFullPayload(input);
  const rawMatter = matterRes.status === "fulfilled" ? pickSingle(matterRes.value.payload, "actions") : undefined;
  const rawFileNotes = notesRes.status === "fulfilled" ? pickCollection(notesRes.value.payload, "filenotes") : [];
  const rawTasks = tasksRes.status === "fulfilled" ? pickCollection(tasksRes.value.payload, "tasks") : [];
  const rawTimeRecords = timeRes.status === "fulfilled" ? pickCollection(timeRes.value.payload, "timerecords") : [];
  const rawEmails = emailsRes.status === "fulfilled" ? pickCollection(emailsRes.value.payload, "emails") : [];

  const matter = rawMatter ? (full ? rawMatter : slimMatter(rawMatter)) : undefined;
  const fileNotes = full ? rawFileNotes : rawFileNotes.map(slimFileNote);
  const tasks = full ? rawTasks : rawTasks.map(slimTask);
  const timeRecords = full ? rawTimeRecords : rawTimeRecords.map(slimTimeRecord);
  const emails = full ? rawEmails : rawEmails.map(slimEmail);

  const errors: string[] = [];
  if (matterRes.status === "rejected") errors.push(`matter: ${matterRes.reason instanceof Error ? matterRes.reason.message : String(matterRes.reason)}`);
  if (notesRes.status === "rejected") errors.push(`file notes: ${notesRes.reason instanceof Error ? notesRes.reason.message : String(notesRes.reason)}`);
  if (tasksRes.status === "rejected") errors.push(`tasks: ${tasksRes.reason instanceof Error ? tasksRes.reason.message : String(tasksRes.reason)}`);
  if (timeRes.status === "rejected") errors.push(`time records: ${timeRes.reason instanceof Error ? timeRes.reason.message : String(timeRes.reason)}`);
  if (emailsRes.status === "rejected") errors.push(`emails: ${emailsRes.reason instanceof Error ? emailsRes.reason.message : String(emailsRes.reason)}`);

  if (!matter && errors.length > 0) {
    throw new Error(`Failed to load matter ${matterId}: ${errors.join("; ")}`);
  }

  const summaryParts = [
    matter ? `Matter ${matterId} loaded.` : `Matter ${matterId} not found.`,
    `${fileNotes.length} file note${fileNotes.length === 1 ? "" : "s"}`,
    `${tasks.length} task${tasks.length === 1 ? "" : "s"}`,
    `${timeRecords.length} time record${timeRecords.length === 1 ? "" : "s"}`,
    `${emails.length} email${emails.length === 1 ? "" : "s"}`
  ];
  if (errors.length > 0) {
    summaryParts.push(`(partial: ${errors.join("; ")})`);
  }

  return {
    summary: summaryParts.join(" "),
    data: [
      {
        matter: matter ?? null,
        fileNotes,
        tasks,
        timeRecords,
        emails
      }
    ],
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
    case "get_matter_summary":
      return getMatterSummary(deps, account, input);
    case "list_participants":
    case "search_participants":
      return listParticipants(deps, account, input);
    case "get_participant":
      return getParticipant(deps, account, input);
    case "list_tasks_for_matter":
      return listTasks(deps, account, input);
    case "list_time_entries":
      return listTimeEntries(deps, account, input);
    case "list_file_notes":
      return listFileNotes(deps, account, input);
    case "list_matter_emails":
      return listEmails(deps, account, input);
    default:
      throw new Error(`Unknown ActionStep tool: ${toolName}`);
  }
}
