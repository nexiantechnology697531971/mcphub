import { z } from "zod";

import { createStubTool } from "../base/tool-factory";

import type { ConnectorToolDefinition, ProviderAdapter } from "@nexian/core/connectors/contracts";
import type { TokenPair } from "@nexian/core/domain/models";
import type { NormalizedToolResponse } from "@nexian/core/mcp/tools";

const PROD_AUTHORIZE_URL = "https://go.actionstep.com/api/oauth/authorize";
const PROD_TOKEN_URL = "https://api.actionstep.com/api/oauth/token";
const STAGING_AUTHORIZE_URL = "https://go.actionstepstaging.com/api/oauth/authorize";
const STAGING_TOKEN_URL = "https://api.actionstepstaging.com/api/oauth/token";

const DEFAULT_SCOPES = ["actions", "participants", "tasks", "timeentries"];

function isStaging() {
  return (process.env.ACTIONSTEP_ENV ?? "production").toLowerCase() === "staging";
}

function getAuthorizationUrlBase() {
  return isStaging() ? STAGING_AUTHORIZE_URL : PROD_AUTHORIZE_URL;
}

function getTokenUrl() {
  return isStaging() ? STAGING_TOKEN_URL : PROD_TOKEN_URL;
}

function getActionStepScopes() {
  const raw = process.env.ACTIONSTEP_SCOPES;
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/\s+/).filter(Boolean);
}

function getRedirectUri() {
  return process.env.ACTIONSTEP_REDIRECT_URI ?? "http://localhost:4000/oauth/actionstep/callback";
}

type ActionStepTokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  api_endpoint?: string;
  token_type?: string;
};

async function exchangeActionStepToken(params: URLSearchParams): Promise<TokenPair> {
  const response = await fetch(getTokenUrl(), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params.toString()
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`ActionStep token exchange failed (${response.status}): ${body}`);
  }

  const payload = (await response.json()) as ActionStepTokenResponse;

  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: payload.expires_in ? new Date(Date.now() + payload.expires_in * 1000) : undefined,
    scopes: payload.scope?.split(/\s+/).filter(Boolean)
  };
}

const includeFullDescription =
  "Set true to return the raw ActionStep records (all fields). Default is a slim projection of the most useful fields — keep it false unless you specifically need fields that have been omitted.";

const matterFiltersSchema = z.object({
  query: z
    .string()
    .min(1)
    .describe(
      "Free-text search across matter name, reference, AND description. Wildcards are added automatically (`Rochester` → `*Rochester*`). Internally fans out three parallel queries and merges results — so phrases like 'Purchase of 27 High Street, Rochester' will match whichever field the matter actually uses. Prefer this over the field-specific filters below for general searches."
    )
    .optional(),
  description: z
    .string()
    .min(1)
    .describe(
      "Filter strictly by matter description / summary text. Wildcards added automatically. Use only when you need to constrain to the description field — otherwise use `query`."
    )
    .optional(),
  reference: z
    .string()
    .min(1)
    .describe(
      "Filter strictly by matter reference / file number. Wildcards added automatically. Use only when searching for a known reference — otherwise use `query`."
    )
    .optional(),
  status: z.string().describe("Filter by matter status (e.g. 'active', 'closed').").optional(),
  assigned_to_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Filter to matters where the given participant is the assigned owner.")
    .optional(),
  client_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Filter to matters whose client is this participant id.")
    .optional(),
  page: z.number().int().positive().describe("1-indexed page number.").optional(),
  pageSize: z
    .number()
    .int()
    .positive()
    .max(200)
    .describe("Page size, ActionStep maximum is 200. Defaults to 25 if omitted.")
    .optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const matterIdSchema = z.object({
  matter_id: z.number().int().positive().describe("The ActionStep matter (action) ID."),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const matterSummarySchema = z.object({
  matter_id: z.number().int().positive().describe("The ActionStep matter (action) ID to summarise."),
  notes_page_size: z
    .number()
    .int()
    .positive()
    .max(200)
    .describe("How many recent file notes to pull (defaults to 25).")
    .optional(),
  tasks_page_size: z
    .number()
    .int()
    .positive()
    .max(200)
    .describe("How many tasks to pull (defaults to 25).")
    .optional(),
  time_page_size: z
    .number()
    .int()
    .positive()
    .max(200)
    .describe("How many recent time records to pull (defaults to 25).")
    .optional(),
  emails_page_size: z
    .number()
    .int()
    .positive()
    .max(200)
    .describe("How many recent matter emails to pull (defaults to 25).")
    .optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const fileNotesFiltersSchema = z.object({
  matter_id: z
    .number()
    .int()
    .positive()
    .describe("Limit file notes to the given matter (action) ID.")
    .optional(),
  entered_by_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Limit to file notes entered by a specific participant (fee earner) ID.")
    .optional(),
  date_from: z.string().describe("ISO-8601 date (YYYY-MM-DD) lower bound on the note date.").optional(),
  date_to: z.string().describe("ISO-8601 date (YYYY-MM-DD) upper bound on the note date.").optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const emailsFiltersSchema = z.object({
  matter_id: z
    .number()
    .int()
    .positive()
    .describe("Required. The ActionStep matter (action) ID to list emails for. Emails must be scoped to a matter — call search_matters first if you only have a name."),
  participant_id: z
    .number()
    .int()
    .positive()
    .describe("Limit to emails sent to or from a specific participant ID.")
    .optional(),
  date_from: z.string().describe("ISO-8601 date (YYYY-MM-DD) lower bound on the sent date.").optional(),
  date_to: z.string().describe("ISO-8601 date (YYYY-MM-DD) upper bound on the sent date.").optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const participantFiltersSchema = z.object({
  query: z
    .string()
    .min(1)
    .describe(
      "Filter by participant name. Single tokens search displayName with wildcards. Multi-word queries (e.g. 'John Smith') fan out in parallel across displayName, reversed 'Last, First' displayName, and firstName+lastName field filters — handles ActionStep's varying name formats."
    )
    .optional(),
  email: z.string().email().describe("Exact-match email filter.").optional(),
  phone: z
    .string()
    .min(3)
    .describe(
      "Search by phone number. ActionStep stores phones split across slots 1–4 (each with country/area/number/label). Pass any digits — formatting like '+44 7700 900 123' or '07700900123' both work. The match is digit-only across all 4 slots on the returned page (use other filters to narrow first if your tenant has many participants)."
    )
    .optional(),
  type: z
    .string()
    .describe("Optional participant type filter (e.g. 'individual', 'company').")
    .optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const participantIdSchema = z.object({
  participant_id: z.number().int().positive().describe("The ActionStep participant ID."),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const tasksFiltersSchema = z.object({
  matter_id: z
    .number()
    .int()
    .positive()
    .describe("Limit tasks to the given matter ID. Required unless filtering by assignee.")
    .optional(),
  assigned_to_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Limit to tasks assigned to a specific participant.")
    .optional(),
  status: z
    .string()
    .describe("Filter by task status (e.g. 'open', 'complete').")
    .optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const timeEntriesFiltersSchema = z.object({
  matter_id: z
    .number()
    .int()
    .positive()
    .describe("Limit time entries to the given matter ID.")
    .optional(),
  participant_id: z
    .number()
    .int()
    .positive()
    .describe("Limit to time entries recorded by a specific participant (fee earner).")
    .optional(),
  date_from: z
    .string()
    .describe("ISO-8601 date (YYYY-MM-DD) lower bound on the entry date.")
    .optional(),
  date_to: z
    .string()
    .describe("ISO-8601 date (YYYY-MM-DD) upper bound on the entry date.")
    .optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const dormantMattersSchema = z.object({
  days: z
    .number()
    .int()
    .positive()
    .max(365)
    .describe("Lookback window in days. A matter is dormant if it has zero time entries in the last N days. Defaults to 14.")
    .optional(),
  status: z
    .string()
    .describe("Matter status to scan. Defaults to 'active' — pass 'closed' or another status to widen.")
    .optional(),
  assigned_to_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Restrict the scan to matters assigned to this participant (fee earner). Optional.")
    .optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const quietMattersSchema = z.object({
  days: z
    .number()
    .int()
    .positive()
    .max(365)
    .describe("Lookback window in days. Defaults to 14.")
    .optional(),
  status: z
    .string()
    .describe("Matter status to scan. Defaults to 'active'.")
    .optional(),
  assigned_to_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Restrict the scan to matters assigned to this participant. Optional.")
    .optional(),
  signals: z
    .array(z.enum(["time", "file_notes", "emails"]))
    .min(1)
    .describe("Activity signals that count as 'a sign of life'. A matter is quiet only if ALL chosen signals are absent in the window. Defaults to all three.")
    .optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

const matterActivitySummarySchema = z.object({
  days: z
    .number()
    .int()
    .positive()
    .max(365)
    .describe("Lookback window in days for activity counts and last-touched timestamps. Defaults to 14.")
    .optional(),
  status: z
    .string()
    .describe("Matter status to scan. Defaults to 'active'.")
    .optional(),
  assigned_to_participant_id: z
    .number()
    .int()
    .positive()
    .describe("Restrict to matters assigned to this participant. Strongly recommended unless you want every active matter in the firm.")
    .optional(),
  include_full: z.boolean().describe(includeFullDescription).optional()
});

function scaffold<TInput>(
  name: string,
  description: string,
  inputSchema: z.ZodType<TInput>
): ConnectorToolDefinition<TInput, NormalizedToolResponse> {
  return {
    name,
    description,
    inputSchema,
    async execute(context, input) {
      return {
        summary: `${name} is scaffolded for tenant ${context.tenantId}.`,
        data: [
          {
            status: "not_implemented",
            filters: input,
            accountId: context.accountId
          }
        ],
        source: "actionstep-scaffold"
      };
    }
  };
}

export const actionStepAdapter: ProviderAdapter = {
  provider: "actionstep",
  displayName: "ActionStep",
  supportsOAuth: true,
  oauthConfig: {
    authorizationUrl: getAuthorizationUrlBase(),
    tokenUrl: getTokenUrl(),
    scopes: getActionStepScopes(),
    redirectUri: getRedirectUri()
  },
  getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: process.env.ACTIONSTEP_CLIENT_ID ?? "",
      redirect_uri: getRedirectUri(),
      scope: getActionStepScopes().join(" "),
      state
    });
    return `${getAuthorizationUrlBase()}?${params.toString()}`;
  },
  async exchangeCode(code) {
    return exchangeActionStepToken(
      new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.ACTIONSTEP_CLIENT_ID ?? "",
        client_secret: process.env.ACTIONSTEP_CLIENT_SECRET ?? "",
        code,
        redirect_uri: getRedirectUri()
      })
    );
  },
  async refreshToken(_account, refreshToken) {
    return exchangeActionStepToken(
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: process.env.ACTIONSTEP_CLIENT_ID ?? "",
        client_secret: process.env.ACTIONSTEP_CLIENT_SECRET ?? "",
        refresh_token: refreshToken
      })
    );
  },
  getTools() {
    return [
      scaffold(
        "list_matters",
        "List ActionStep matters (actions). Use when the user asks for an overview of cases, files, files-in-progress, or matters for a client. Supports filtering by status, assignee, and client participant. Paginated via `page` and `pageSize` (max 200).",
        matterFiltersSchema
      ),
      scaffold(
        "search_matters",
        "Search ActionStep matters. Default behaviour: pass `query` and we fan out across name, reference, AND description in parallel and merge — so descriptive phrases like 'Purchase of 27 High Street, Rochester' will match wherever they actually live on the matter record. Use the targeted `description` or `reference` parameters only when you specifically need to constrain to one field. Also supports status, assignee, and client participant filters. ActionStep wildcards (`*foo*`) are added automatically.",
        matterFiltersSchema
      ),
      scaffold(
        "get_matter",
        "Retrieve a single ActionStep matter (action) by ID. Use when the user has a known matter ID or after `search_matters` returns a candidate. Returns matter name, status, client participant, assigned owner, key dates and references. For a fuller picture that also pulls file notes, tasks, and recent time records, prefer `get_matter_summary`.",
        matterIdSchema
      ),
      scaffold(
        "get_matter_summary",
        "Use when the user asks for a summary or overview of an ActionStep matter — anything like 'summarise matter X', 'what's happening on this file', 'give me a rundown'. Returns the matter record plus its recent file notes, open tasks, recent time records, and recent emails in one consolidated response so you can produce a narrative summary without further tool calls.",
        matterSummarySchema
      ),
      scaffold(
        "list_participants",
        "List ActionStep participants (clients, contacts, related parties). Use when the user wants a directory-style view of contacts. Supports type filtering and pagination.",
        participantFiltersSchema
      ),
      scaffold(
        "search_participants",
        "Search ActionStep participants by name (`query`), email, participant `type`, or phone number. Full names work — pass 'John Smith' and we fan out in parallel across displayName ('John Smith'), reversed displayName ('Smith, John' — ActionStep's common format), and firstName+lastName field filters, then merge by ID. Use `phone` when the user gives a number like '07700 900 123' or '+44 7700 900 123' — the match runs digit-only across all four ActionStep phone slots (phone1Number through phone4Number, plus their country/area parts).",
        participantFiltersSchema
      ),
      scaffold(
        "get_participant",
        "Retrieve a single ActionStep participant by ID. Use when the user has a known participant ID or after `search_participants` returns a candidate. Returns name, contact details, type and linked role.",
        participantIdSchema
      ),
      scaffold(
        "list_tasks_for_matter",
        "List ActionStep tasks. Use when the user asks about outstanding work items, to-do steps, or task lists for a matter or assignee. Filter by matter_id (preferred) or assigned_to_participant_id.",
        tasksFiltersSchema
      ),
      scaffold(
        "list_time_entries",
        "List ActionStep time entries (timerecords). Use when the user asks about recorded time, fee earner activity, or time spent on a matter. Filter by matter_id, participant_id and date range. Returns date, duration, fee earner, narrative and matter linkage.",
        timeEntriesFiltersSchema
      ),
      scaffold(
        "list_file_notes",
        "List ActionStep file notes for a matter. Use when the user asks about file notes, attendance notes, case notes, narrative history, or 'what's been happening on this file'. Filter by matter_id (preferred), entered_by_participant_id, and date range. Returns each note's text, who entered it, and when.",
        fileNotesFiltersSchema
      ),
      scaffold(
        "list_matter_emails",
        "List ActionStep emails recorded against a matter. Use when the user asks about correspondence, email history, sent/received emails, or 'who's been emailing on this file'. `matter_id` is REQUIRED — emails must be scoped to a specific matter; call search_matters first if you only have a name. Also supports optional participant_id and date_from/date_to filters. Returns each email's subject, from/to, sent timestamp and body summary.",
        emailsFiltersSchema
      ),
      scaffold(
        "list_dormant_matters",
        "Find ActionStep matters with NO TIME RECORDED in the last N days. Use when the user asks about dormant matters, files with no recent time, 'which matters haven't been worked on', 'matters with zero time this fortnight', or wants to chase fee earners about untracked work. Defaults: 14 days, status='active'. Optionally narrow to a single fee earner via assigned_to_participant_id. Returns each dormant matter with its slim record plus activity counters in the window.",
        dormantMattersSchema
      ),
      scaffold(
        "list_quiet_matters",
        "Find ActionStep matters with no sign of life across selected signals (time / file_notes / emails) in the last N days. Broader than `list_dormant_matters` — catches matters where no time was recorded AND no notes were entered AND no emails came in. Use when the user asks about truly dormant files, closure candidates, or matters that have 'gone quiet'. Defaults: 14 days, status='active', signals=all three. Use `signals` to scope (e.g. `[\"time\",\"file_notes\"]` ignores email activity).",
        quietMattersSchema
      ),
      scaffold(
        "get_matter_activity_summary",
        "List matters with per-matter activity counters and last-touched timestamps across time entries, file notes and emails for the last N days. Use when the user wants a portfolio view ('show me my book sorted by activity', 'which of my matters has the most going on', 'when did I last touch each file'). Strongly prefer passing `assigned_to_participant_id` to scope to a fee earner — otherwise this scans every active matter in the firm.",
        matterActivitySummarySchema
      )
    ];
  }
};
