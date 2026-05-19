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

function readBoolean(input: Record<string, unknown>, key: string): boolean | undefined {
  const value = input[key];
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "true") return true;
    if (trimmed === "false") return false;
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
  const email = readString(input, "email");
  const participantType = readString(input, "type");

  const sharedFilters = {
    email,
    participantType
  };

  // ActionStep's participants endpoint does substring matching by default;
  // wrapping with `*` makes it search for literal asterisks and returns 0.
  const url = buildUrl(endpoint, "/api/rest/participants", {
    page,
    pageSize,
    displayName: rawQuery,
    ...sharedFilters
  });
  const { payload } = await fetchWithRefresh(deps, account, url);
  const fetched = pickCollection(payload, "participants");

  const filtered = isPhoneSearch
    ? fetched.filter((participant) => participantMatchesPhone(participant, phoneDigits))
    : fetched;

  const summaryBase = `Found ${filtered.length} participant${filtered.length === 1 ? "" : "s"} in ActionStep`;
  const summary = isPhoneSearch
    ? `${summaryBase} matching phone "${phoneQuery}" (out of ${fetched.length} on this page).`
    : `${summaryBase}${rawQuery ? ` matching displayName containing "${rawQuery}"` : ""}.`;

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
  if (!matterId) {
    throw new Error(
      "matter_id is required for list_matter_emails — ActionStep emails must be scoped to a matter. Use search_matters first if you only have a matter name."
    );
  }
  const baseQuery = {
    action: matterId,
    participant: readNumber(input, "participant_id"),
    dateFrom: readString(input, "date_from"),
    dateTo: readString(input, "date_to")
  };

  const { records: emails, paging, pagesFetched } = await fetchAllPages(
    deps,
    account,
    endpoint,
    "/api/rest/emails",
    baseQuery,
    "emails"
  );

  const totalKnown = paging.recordCount;
  const truncatedNote =
    typeof totalKnown === "number" && emails.length < totalKnown
      ? ` (ActionStep reports ${totalKnown} total; fetched ${pagesFetched} page(s)).`
      : "";

  return {
    summary: `Found ${emails.length} email${emails.length === 1 ? "" : "s"} on matter ${matterId} in ActionStep.${truncatedNote}`,
    data: isFullPayload(input) ? emails : emails.map(slimEmail),
    source: SOURCE
  };
}

function extractLinkedId(record: Record<string, unknown>, key: string): string | undefined {
  const links = record.links;
  if (!links || typeof links !== "object" || Array.isArray(links)) return undefined;
  const value = (links as Record<string, unknown>)[key];
  if (typeof value === "string" && value.trim().length > 0) return value.trim();
  if (typeof value === "number") return String(value);
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const id = (value as Record<string, unknown>).id;
    if (typeof id === "string" && id.trim().length > 0) return id.trim();
    if (typeof id === "number") return String(id);
  }
  return undefined;
}

function pickTimestamp(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) return value;
  }
  return undefined;
}

const TIME_DATE_FIELDS = ["date", "modifiedTimestamp", "createdTimestamp"] as const;
const FILENOTE_DATE_FIELDS = ["enteredTimestamp", "noteTimestamp", "createdTimestamp"] as const;
const EMAIL_DATE_FIELDS = ["sentTimestamp", "receivedTimestamp", "createdTimestamp"] as const;

type ActivitySignal = "time" | "file_notes" | "emails";

type MatterActivity = {
  lastTimeEntry?: string;
  lastFileNote?: string;
  lastEmail?: string;
  timeEntryCount: number;
  fileNoteCount: number;
  emailCount: number;
};

type ActivityFetchOutcome = {
  records: Record<string, unknown>[];
  paging: PagingMeta;
  pagesFetched: number;
};

type ActivityIndex = {
  matters: Record<string, unknown>[];
  activityByMatterId: Map<string, MatterActivity>;
  windowStart: string;
  signalsFetched: ReadonlyArray<ActivitySignal>;
  matterFetch: ActivityFetchOutcome;
  timeFetch: ActivityFetchOutcome;
  noteFetch: ActivityFetchOutcome;
  emailFetch: ActivityFetchOutcome;
};

function emptyFetchOutcome(): ActivityFetchOutcome {
  return { records: [], paging: {}, pagesFetched: 0 };
}

function isTruncated(outcome: ActivityFetchOutcome): boolean {
  const total = outcome.paging.recordCount;
  if (typeof total !== "number") return false;
  return outcome.records.length < total;
}

function buildTruncationNote(index: ActivityIndex): string {
  const warnings: string[] = [];
  if (isTruncated(index.matterFetch)) {
    warnings.push(
      `matter list truncated (${index.matterFetch.records.length} of ${index.matterFetch.paging.recordCount})`
    );
  }
  if (index.signalsFetched.includes("time") && isTruncated(index.timeFetch)) {
    warnings.push(
      `time entries truncated (${index.timeFetch.records.length} of ${index.timeFetch.paging.recordCount}) — some matters may be falsely flagged as inactive`
    );
  }
  if (index.signalsFetched.includes("file_notes") && isTruncated(index.noteFetch)) {
    warnings.push(
      `file notes truncated (${index.noteFetch.records.length} of ${index.noteFetch.paging.recordCount})`
    );
  }
  if (index.signalsFetched.includes("emails") && isTruncated(index.emailFetch)) {
    warnings.push(
      `emails truncated (${index.emailFetch.records.length} of ${index.emailFetch.paging.recordCount})`
    );
  }
  return warnings.length > 0 ? ` WARNING: ${warnings.join("; ")}.` : "";
}

function maxTimestamp(values: ReadonlyArray<string | undefined>): string | undefined {
  let best: string | undefined;
  for (const value of values) {
    if (!value) continue;
    if (!best || value > best) best = value;
  }
  return best;
}

function daysBetween(fromIso: string | undefined, nowMs: number): number | undefined {
  if (!fromIso) return undefined;
  const ts = Date.parse(fromIso);
  if (!Number.isFinite(ts)) return undefined;
  const diffMs = nowMs - ts;
  if (diffMs < 0) return 0;
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

async function buildMatterActivityIndex(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  options: {
    days: number;
    status: string;
    assignedTo?: number;
    signals: ReadonlyArray<ActivitySignal>;
  }
): Promise<ActivityIndex> {
  const endpoint = getApiEndpoint(account);
  const windowStart = new Date(Date.now() - options.days * 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10);

  const matterQuery = {
    status: options.status,
    assignedTo: options.assignedTo
  };

  const wantTime = options.signals.includes("time");
  const wantNotes = options.signals.includes("file_notes");
  const wantEmails = options.signals.includes("emails");

  const [matterFetch, timeFetch, noteFetch, emailFetch] = await Promise.all([
    fetchAllPages(deps, account, endpoint, "/api/rest/actions", matterQuery, "actions"),
    wantTime
      ? fetchAllPages(deps, account, endpoint, "/api/rest/timerecords", { dateFrom: windowStart }, "timerecords")
      : Promise.resolve(emptyFetchOutcome()),
    wantNotes
      ? fetchAllPages(deps, account, endpoint, "/api/rest/filenotes", { dateFrom: windowStart }, "filenotes")
      : Promise.resolve(emptyFetchOutcome()),
    wantEmails
      ? fetchAllPages(deps, account, endpoint, "/api/rest/emails", { dateFrom: windowStart }, "emails")
      : Promise.resolve(emptyFetchOutcome())
  ]);

  const activityByMatterId = new Map<string, MatterActivity>();
  const ensure = (id: string): MatterActivity => {
    let entry = activityByMatterId.get(id);
    if (!entry) {
      entry = { timeEntryCount: 0, fileNoteCount: 0, emailCount: 0 };
      activityByMatterId.set(id, entry);
    }
    return entry;
  };

  for (const record of timeFetch.records) {
    const matterId = extractLinkedId(record, "action");
    if (!matterId) continue;
    const entry = ensure(matterId);
    entry.timeEntryCount += 1;
    const ts = pickTimestamp(record, TIME_DATE_FIELDS);
    if (ts && (!entry.lastTimeEntry || ts > entry.lastTimeEntry)) entry.lastTimeEntry = ts;
  }

  for (const record of noteFetch.records) {
    const matterId = extractLinkedId(record, "action");
    if (!matterId) continue;
    const entry = ensure(matterId);
    entry.fileNoteCount += 1;
    const ts = pickTimestamp(record, FILENOTE_DATE_FIELDS);
    if (ts && (!entry.lastFileNote || ts > entry.lastFileNote)) entry.lastFileNote = ts;
  }

  for (const record of emailFetch.records) {
    const matterId = extractLinkedId(record, "action");
    if (!matterId) continue;
    const entry = ensure(matterId);
    entry.emailCount += 1;
    const ts = pickTimestamp(record, EMAIL_DATE_FIELDS);
    if (ts && (!entry.lastEmail || ts > entry.lastEmail)) entry.lastEmail = ts;
  }

  return {
    matters: matterFetch.records,
    activityByMatterId,
    windowStart,
    signalsFetched: options.signals,
    matterFetch,
    timeFetch,
    noteFetch,
    emailFetch
  };
}

function decorateMatterWithActivity(
  matter: Record<string, unknown>,
  activity: MatterActivity | undefined,
  signals: ReadonlyArray<ActivitySignal>,
  nowMs: number,
  full: boolean
): Record<string, unknown> {
  const base = full ? matter : slimMatter(matter);
  const lastAny = maxTimestamp([activity?.lastTimeEntry, activity?.lastFileNote, activity?.lastEmail]);
  return {
    ...base,
    activityInWindow: {
      signals,
      timeEntryCount: activity?.timeEntryCount ?? 0,
      fileNoteCount: activity?.fileNoteCount ?? 0,
      emailCount: activity?.emailCount ?? 0,
      lastTimeEntry: activity?.lastTimeEntry,
      lastFileNote: activity?.lastFileNote,
      lastEmail: activity?.lastEmail,
      lastAnyActivity: lastAny,
      daysSinceLastActivity: daysBetween(lastAny, nowMs)
    }
  };
}

async function listDormantMatters(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const days = readNumber(input, "days") ?? 14;
  const status = readString(input, "status") ?? "Active";
  const assignedTo = readNumber(input, "assigned_to_participant_id");
  const requireRecentActivity = readBoolean(input, "require_recent_activity") ?? false;

  const index = await buildMatterActivityIndex(deps, account, {
    days,
    status,
    assignedTo,
    signals: ["time"]
  });

  const nowMs = Date.now();
  const windowStartMs = Date.parse(index.windowStart);
  const full = isFullPayload(input);
  const dormant = index.matters
    .filter((matter) => {
      const id = matter.id !== undefined ? String(matter.id) : "";
      if (!id) return false;
      const activity = index.activityByMatterId.get(id);
      const noTime = !activity || activity.timeEntryCount === 0;
      if (!noTime) return false;
      if (requireRecentActivity) {
        const lastTouched = pickTimestamp(matter, ["lastActivityTimestamp", "modifiedTimestamp"]);
        if (!lastTouched) return false;
        const ts = Date.parse(lastTouched);
        if (!Number.isFinite(ts) || ts < windowStartMs) return false;
      }
      return true;
    })
    .map((matter) => {
      const id = String(matter.id);
      return decorateMatterWithActivity(matter, index.activityByMatterId.get(id), ["time"], nowMs, full);
    });

  const scope = assignedTo ? ` assigned to participant ${assignedTo}` : "";
  const qualifier = requireRecentActivity ? " (worked on per lastActivityTimestamp, but no time recorded)" : "";
  return {
    summary:
      `Found ${dormant.length} ${status} matter${dormant.length === 1 ? "" : "s"}${scope}${qualifier} ` +
      `since ${index.windowStart} (scanned ${index.matters.length} matter${index.matters.length === 1 ? "" : "s"}).` +
      buildTruncationNote(index),
    data: dormant,
    source: SOURCE
  };
}

async function listQuietMatters(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const days = readNumber(input, "days") ?? 14;
  const status = readString(input, "status") ?? "Active";
  const assignedTo = readNumber(input, "assigned_to_participant_id");

  const rawSignals = input["signals"];
  const allowed: ActivitySignal[] = ["time", "file_notes", "emails"];
  const signals: ActivitySignal[] = Array.isArray(rawSignals)
    ? (rawSignals.filter((s): s is ActivitySignal => typeof s === "string" && (allowed as string[]).includes(s)))
    : allowed;
  const effectiveSignals: ActivitySignal[] = signals.length > 0 ? signals : allowed;

  const index = await buildMatterActivityIndex(deps, account, {
    days,
    status,
    assignedTo,
    signals: effectiveSignals
  });

  const nowMs = Date.now();
  const full = isFullPayload(input);
  const quiet = index.matters
    .filter((matter) => {
      const id = matter.id !== undefined ? String(matter.id) : "";
      if (!id) return false;
      const activity = index.activityByMatterId.get(id);
      if (!activity) return true;
      if (effectiveSignals.includes("time") && activity.timeEntryCount > 0) return false;
      if (effectiveSignals.includes("file_notes") && activity.fileNoteCount > 0) return false;
      if (effectiveSignals.includes("emails") && activity.emailCount > 0) return false;
      return true;
    })
    .map((matter) => {
      const id = String(matter.id);
      return decorateMatterWithActivity(matter, index.activityByMatterId.get(id), effectiveSignals, nowMs, full);
    });

  const scope = assignedTo ? ` assigned to participant ${assignedTo}` : "";
  return {
    summary:
      `Found ${quiet.length} ${status} matter${quiet.length === 1 ? "" : "s"}${scope} with no activity across ` +
      `[${effectiveSignals.join(", ")}] since ${index.windowStart} (scanned ${index.matters.length} matter${index.matters.length === 1 ? "" : "s"}).` +
      buildTruncationNote(index),
    data: quiet,
    source: SOURCE
  };
}

async function getMatterActivitySummary(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const days = readNumber(input, "days") ?? 14;
  const status = readString(input, "status") ?? "Active";
  const assignedTo = readNumber(input, "assigned_to_participant_id");
  const signals: ActivitySignal[] = ["time", "file_notes", "emails"];

  const index = await buildMatterActivityIndex(deps, account, {
    days,
    status,
    assignedTo,
    signals
  });

  const nowMs = Date.now();
  const full = isFullPayload(input);
  const decorated = index.matters
    .map((matter) => {
      const id = matter.id !== undefined ? String(matter.id) : "";
      const activity = id ? index.activityByMatterId.get(id) : undefined;
      return decorateMatterWithActivity(matter, activity, signals, nowMs, full);
    })
    .sort((a, b) => {
      const aLast =
        ((a.activityInWindow as Record<string, unknown> | undefined)?.lastAnyActivity as string | undefined) ?? "";
      const bLast =
        ((b.activityInWindow as Record<string, unknown> | undefined)?.lastAnyActivity as string | undefined) ?? "";
      return bLast.localeCompare(aLast);
    });

  const scope = assignedTo ? ` for participant ${assignedTo}` : "";
  return {
    summary:
      `Activity summary${scope}: ${decorated.length} ${status} matter${decorated.length === 1 ? "" : "s"} ` +
      `with counts since ${index.windowStart}, sorted by most-recent activity first.` +
      buildTruncationNote(index),
    data: decorated,
    source: SOURCE
  };
}

type ParticipantMatters = {
  matters: Record<string, unknown>[];
  roleByMatterId: Map<string, string[]>;
  linkRecordCount: number;
  linkPagesFetched: number;
  matterFetchErrors: string[];
};

async function fetchMattersForParticipant(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  participantId: number,
  status: string | undefined
): Promise<ParticipantMatters> {
  const endpoint = getApiEndpoint(account);

  const linksFetch = await fetchAllPages(
    deps,
    account,
    endpoint,
    "/api/rest/actionparticipants",
    { participant: participantId },
    "actionparticipants"
  );

  const roleByMatterId = new Map<string, string[]>();
  for (const record of linksFetch.records) {
    const matterId = extractLinkedId(record, "action");
    if (!matterId) continue;
    const role = extractLinkedId(record, "participantType") ?? "participant";
    const roles = roleByMatterId.get(matterId) ?? [];
    if (!roles.includes(role)) roles.push(role);
    roleByMatterId.set(matterId, roles);
  }

  const matterIds = [...roleByMatterId.keys()];
  const responses = await Promise.allSettled(
    matterIds.map((id) =>
      fetchWithRefresh(deps, account, buildUrl(endpoint, `/api/rest/actions/${id}`, {}))
    )
  );

  const matters: Record<string, unknown>[] = [];
  const matterFetchErrors: string[] = [];
  const statusLower = status?.toLowerCase();

  responses.forEach((result, index) => {
    const id = matterIds[index];
    if (result.status === "rejected") {
      matterFetchErrors.push(`${id}: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
      return;
    }
    const matter = pickSingle(result.value.payload, "actions");
    if (!matter) return;
    if (statusLower) {
      const matterStatus = typeof matter.status === "string" ? matter.status.toLowerCase() : undefined;
      if (matterStatus !== statusLower) return;
    }
    matters.push(matter);
  });

  return {
    matters,
    roleByMatterId,
    linkRecordCount: linksFetch.records.length,
    linkPagesFetched: linksFetch.pagesFetched,
    matterFetchErrors
  };
}

async function listMattersForParticipant(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const participantId = readNumber(input, "participant_id");
  if (!participantId) {
    throw new Error("participant_id is required");
  }
  const status = readString(input, "status");
  const full = isFullPayload(input);

  const { matters, roleByMatterId, linkRecordCount, matterFetchErrors } = await fetchMattersForParticipant(
    deps,
    account,
    participantId,
    status
  );

  const decorated = matters.map((matter) => {
    const id = matter.id !== undefined ? String(matter.id) : "";
    const base = full ? matter : slimMatter(matter);
    return {
      ...base,
      participantRoles: roleByMatterId.get(id) ?? []
    };
  });

  const statusNote = status ? ` (filtered to status='${status}')` : "";
  const errorNote = matterFetchErrors.length > 0
    ? ` WARNING: ${matterFetchErrors.length} matter fetch${matterFetchErrors.length === 1 ? "" : "es"} failed: ${matterFetchErrors.slice(0, 3).join("; ")}${matterFetchErrors.length > 3 ? "…" : ""}.`
    : "";

  return {
    summary:
      `Participant ${participantId} is linked to ${linkRecordCount} actionparticipant record${linkRecordCount === 1 ? "" : "s"} ` +
      `→ ${decorated.length} matter${decorated.length === 1 ? "" : "s"}${statusNote}.${errorNote}`,
    data: decorated,
    source: SOURCE
  };
}

function totalMinutes(record: Record<string, unknown>): number {
  const chargeable = readNumber(record, "chargeableMinutes");
  if (typeof chargeable === "number") return chargeable;
  const actual = readNumber(record, "actualMinutes");
  if (typeof actual === "number") return actual;
  return 0;
}

async function getClientBrief(
  deps: ActionStepExecutorDeps,
  account: ConnectedAccountRecord,
  input: Record<string, unknown>
): Promise<NormalizedToolResponse> {
  const participantId = readNumber(input, "participant_id");
  if (!participantId) {
    throw new Error("participant_id is required");
  }
  const days = readNumber(input, "days") ?? 730;
  const status = readString(input, "status");
  const full = isFullPayload(input);

  const allowedInclude = ["file_notes", "time_entries", "emails"] as const;
  type IncludeOption = (typeof allowedInclude)[number];
  const rawInclude = input["include"];
  const include: IncludeOption[] = Array.isArray(rawInclude)
    ? rawInclude.filter((value): value is IncludeOption =>
        typeof value === "string" && (allowedInclude as readonly string[]).includes(value)
      )
    : ["file_notes", "time_entries", "emails"];
  const effectiveInclude: IncludeOption[] = include.length > 0 ? include : ["file_notes", "time_entries", "emails"];

  const wantNotes = effectiveInclude.includes("file_notes");
  const wantTime = effectiveInclude.includes("time_entries");
  const wantEmails = effectiveInclude.includes("emails");

  const windowStart = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10);

  const { matters, roleByMatterId, linkRecordCount, matterFetchErrors } = await fetchMattersForParticipant(
    deps,
    account,
    participantId,
    status
  );

  if (matters.length === 0) {
    return {
      summary:
        `Participant ${participantId} has no${status ? ` ${status}` : ""} matters linked via actionparticipants ` +
        `(${linkRecordCount} link record${linkRecordCount === 1 ? "" : "s"} scanned).`,
      data: [],
      source: SOURCE
    };
  }

  const endpoint = getApiEndpoint(account);

  const bundles = await Promise.all(
    matters.map(async (matter) => {
      const id = matter.id !== undefined ? String(matter.id) : "";
      const matterIdNumeric = Number(id);

      const noResult: ActivityFetchOutcome = { records: [], paging: {}, pagesFetched: 0 };

      const [notesRes, timeRes, emailsRes] = await Promise.allSettled([
        wantNotes && Number.isFinite(matterIdNumeric)
          ? fetchAllPages(deps, account, endpoint, "/api/rest/filenotes", { action: matterIdNumeric, dateFrom: windowStart }, "filenotes")
          : Promise.resolve(noResult),
        wantTime && Number.isFinite(matterIdNumeric)
          ? fetchAllPages(deps, account, endpoint, "/api/rest/timerecords", { action: matterIdNumeric, dateFrom: windowStart }, "timerecords")
          : Promise.resolve(noResult),
        wantEmails && Number.isFinite(matterIdNumeric)
          ? fetchAllPages(deps, account, endpoint, "/api/rest/emails", { action: matterIdNumeric, dateFrom: windowStart }, "emails")
          : Promise.resolve(noResult)
      ]);

      const rawNotes = notesRes.status === "fulfilled" ? notesRes.value.records : [];
      const rawTime = timeRes.status === "fulfilled" ? timeRes.value.records : [];
      const rawEmails = emailsRes.status === "fulfilled" ? emailsRes.value.records : [];

      const billableMinutes = rawTime.reduce((sum, record) => sum + totalMinutes(record), 0);

      const fetchErrors: string[] = [];
      if (notesRes.status === "rejected") fetchErrors.push(`notes: ${notesRes.reason instanceof Error ? notesRes.reason.message : String(notesRes.reason)}`);
      if (timeRes.status === "rejected") fetchErrors.push(`time: ${timeRes.reason instanceof Error ? timeRes.reason.message : String(timeRes.reason)}`);
      if (emailsRes.status === "rejected") fetchErrors.push(`emails: ${emailsRes.reason instanceof Error ? emailsRes.reason.message : String(emailsRes.reason)}`);

      const bundle: Record<string, unknown> = {
        matter: full ? matter : slimMatter(matter),
        participantRoles: roleByMatterId.get(id) ?? [],
        totals: {
          fileNoteCount: rawNotes.length,
          timeEntryCount: rawTime.length,
          emailCount: rawEmails.length,
          billableHours: Math.round((billableMinutes / 60) * 100) / 100
        }
      };

      if (wantNotes) bundle.fileNotes = full ? rawNotes : rawNotes.map(slimFileNote);
      if (wantTime) bundle.timeRecords = full ? rawTime : rawTime.map(slimTimeRecord);
      if (wantEmails) bundle.emails = full ? rawEmails : rawEmails.map(slimEmail);
      if (fetchErrors.length > 0) bundle.errors = fetchErrors;

      return bundle;
    })
  );

  type BundleTotals = { fileNoteCount: number; timeEntryCount: number; emailCount: number; billableHours: number };
  const grandTotals: BundleTotals = bundles.reduce<BundleTotals>(
    (acc, bundle) => {
      const t = bundle.totals as BundleTotals;
      acc.fileNoteCount += t.fileNoteCount;
      acc.timeEntryCount += t.timeEntryCount;
      acc.emailCount += t.emailCount;
      acc.billableHours += t.billableHours;
      return acc;
    },
    { fileNoteCount: 0, timeEntryCount: 0, emailCount: 0, billableHours: 0 }
  );
  grandTotals.billableHours = Math.round(grandTotals.billableHours * 100) / 100;

  const errorNote = matterFetchErrors.length > 0
    ? ` WARNING: ${matterFetchErrors.length} matter record${matterFetchErrors.length === 1 ? "" : "s"} failed to load.`
    : "";

  return {
    summary:
      `Brief for participant ${participantId}: ${matters.length} matter${matters.length === 1 ? "" : "s"}, ` +
      `${grandTotals.fileNoteCount} file note${grandTotals.fileNoteCount === 1 ? "" : "s"}, ` +
      `${grandTotals.timeEntryCount} time entr${grandTotals.timeEntryCount === 1 ? "y" : "ies"} ` +
      `(${grandTotals.billableHours}h billable), ` +
      `${grandTotals.emailCount} email${grandTotals.emailCount === 1 ? "" : "s"} since ${windowStart}.${errorNote}`,
    data: bundles,
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
    case "list_dormant_matters":
      return listDormantMatters(deps, account, input);
    case "list_quiet_matters":
      return listQuietMatters(deps, account, input);
    case "get_matter_activity_summary":
      return getMatterActivitySummary(deps, account, input);
    case "list_matters_for_participant":
      return listMattersForParticipant(deps, account, input);
    case "get_client_brief":
      return getClientBrief(deps, account, input);
    default:
      throw new Error(`Unknown ActionStep tool: ${toolName}`);
  }
}
