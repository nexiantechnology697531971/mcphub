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

const matterFiltersSchema = z.object({
  query: z.string().min(1).describe("Free text to search across matter names/references.").optional(),
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
    .optional()
});

const matterIdSchema = z.object({
  matter_id: z.number().int().positive().describe("The ActionStep matter (action) ID.")
});

const participantFiltersSchema = z.object({
  query: z
    .string()
    .min(1)
    .describe("Free text — searches participant names, emails and organisations.")
    .optional(),
  email: z.string().email().describe("Exact-match email filter.").optional(),
  type: z
    .string()
    .describe("Optional participant type filter (e.g. 'individual', 'company').")
    .optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(200).optional()
});

const participantIdSchema = z.object({
  participant_id: z.number().int().positive().describe("The ActionStep participant ID.")
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
  pageSize: z.number().int().positive().max(200).optional()
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
  pageSize: z.number().int().positive().max(200).optional()
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
        "Search ActionStep matters by free-text name or reference. Use when the user names a specific matter, file reference, or case title and wants to find the matching matter record.",
        matterFiltersSchema
      ),
      scaffold(
        "get_matter",
        "Retrieve a single ActionStep matter (action) by ID. Use when the user has a known matter ID or after `search_matters` returns a candidate. Returns matter name, status, client participant, assigned owner, key dates and references.",
        matterIdSchema
      ),
      scaffold(
        "list_participants",
        "List ActionStep participants (clients, contacts, related parties). Use when the user wants a directory-style view of contacts. Supports type filtering and pagination.",
        participantFiltersSchema
      ),
      scaffold(
        "search_participants",
        "Search ActionStep participants by name, email or organisation. Use when the user names a client, contact, or related party and wants to find the matching participant record.",
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
      )
    ];
  }
};
