import { z } from "zod";

import { createStubTool } from "../base/tool-factory";

import type { ConnectorToolDefinition, ProviderAdapter } from "@nexian/core/connectors/contracts";
import type { TokenPair } from "@nexian/core/domain/models";
import type { NormalizedToolResponse } from "@nexian/core/mcp/tools";

const haloTicketFiltersSchema = z.object({
  query: z.string().optional(),
  paginate: z.boolean().optional(),
  page_size: z.number().int().positive().max(200).optional(),
  page_no: z.number().int().positive().optional(),
  order: z.string().optional(),
  orderdesc: z.boolean().optional(),
  ticketidonly: z.boolean().optional(),
  view_id: z.number().int().optional(),
  columns_id: z.number().int().optional(),
  includecolumns: z.boolean().optional(),
  includeslaactiondate: z.boolean().optional(),
  includeslatimer: z.boolean().optional(),
  includetimetaken: z.boolean().optional(),
  includesupplier: z.boolean().optional(),
  includerelease1: z.boolean().optional(),
  includerelease2: z.boolean().optional(),
  includerelease3: z.boolean().optional(),
  includechildids: z.boolean().optional(),
  includenextactivitydate: z.boolean().optional(),
  list_id: z.number().int().optional(),
  agent_id: z.number().int().optional(),
  status_id: z.number().int().optional(),
  requesttype_id: z.number().int().optional(),
  supplier_id: z.number().int().optional(),
  client_id: z.number().int().optional(),
  site: z.number().int().optional(),
  username: z.string().optional(),
  user_id: z.number().int().optional(),
  release_id: z.number().int().optional(),
  asset_id: z.number().int().optional(),
  itil_requesttype_id: z.number().int().optional(),
  open_only: z.boolean().optional(),
  closed_only: z.boolean().optional(),
  unlinked_only: z.boolean().optional(),
  contract_id: z.number().int().optional(),
  withattachments: z.boolean().optional(),
  team: z.array(z.number().int()).optional(),
  agent: z.array(z.number().int()).optional(),
  status: z.array(z.number().int()).optional(),
  requesttype: z.array(z.number().int()).optional(),
  itil_requesttype: z.array(z.number().int()).optional(),
  category_1: z.array(z.number().int()).optional(),
  category_2: z.array(z.number().int()).optional(),
  category_3: z.array(z.number().int()).optional(),
  category_4: z.array(z.number().int()).optional(),
  sla: z.array(z.number().int()).optional(),
  priority: z.array(z.number().int()).optional(),
  products: z.array(z.number().int()).optional(),
  flagged: z.array(z.number().int()).optional(),
  excludethese: z.array(z.number().int()).optional(),
  search: z.string().optional(),
  searchactions: z.boolean().optional(),
  datesearch: z.string().optional(),
  startdate: z.string().optional(),
  enddate: z.string().optional(),
  search_user_name: z.string().optional(),
  search_summary: z.string().optional(),
  search_details: z.string().optional(),
  search_reportedby: z.string().optional(),
  search_version: z.string().optional(),
  search_release1: z.string().optional(),
  search_release2: z.string().optional(),
  search_release3: z.string().optional(),
  search_releasenote: z.string().optional(),
  search_invenotry_number: z.string().optional(),
  search_oppcontactname: z.string().optional(),
  search_oppcompanyname: z.string().optional(),
  limit: z.number().int().positive().max(250).optional(),
  count: z.number().int().positive().max(250).optional(),
  top: z.number().int().positive().max(250).optional(),
  includeClosed: z.boolean().optional(),
  clientId: z.number().int().optional(),
  customerId: z.number().int().optional(),
  organisationId: z.number().int().optional()
});

const haloUserFiltersSchema = z.object({
  query: z
    .string()
    .min(1)
    .describe("Free text — searches name, email, phone, username. Required unless filtering by an ID below.")
    .optional(),
  client_id: z
    .number()
    .int()
    .positive()
    .describe("Only set if you already have the customer/client ID. Omit otherwise — do not pass 0.")
    .optional(),
  site_id: z
    .number()
    .int()
    .positive()
    .describe("Only set if filtering to a known site ID. Omit otherwise — do not pass 0.")
    .optional(),
  department_id: z
    .number()
    .int()
    .positive()
    .describe("Only set if filtering to a known department ID. Omit otherwise — do not pass 0.")
    .optional(),
  asset_id: z
    .number()
    .int()
    .positive()
    .describe("Only set if filtering to a known asset ID. Omit otherwise — do not pass 0.")
    .optional(),
  includeinactive: z.boolean().describe("Set true to also return inactive users.").optional(),
  count: z
    .number()
    .int()
    .positive()
    .max(100)
    .describe("Max results to return (defaults to 25).")
    .optional()
});

const haloListOpenTicketsTool: ConnectorToolDefinition<z.infer<typeof haloTicketFiltersSchema>, NormalizedToolResponse> = {
  name: "list_open_tickets",
  description:
    "Use when the user wants a queue-style view of active tickets, open incidents, or tickets for a customer. Also use for counting tickets, reporting on ticket volumes, or querying tickets by date range (e.g. 'last quarter', 'this month', 'last 30 days', 'Q1 2025', 'YTD'). Supports natural language date ranges, text search across summaries and categories, client_id, site, status arrays, category filters (category_1 through category_4 as numeric ID arrays — call list_halo_categories first to discover category IDs), pagination, ordering, and search fields. For counting or historical queries, pass the full natural language question as the query parameter.",
  inputSchema: haloTicketFiltersSchema,
  async execute(context, input) {
    return {
      summary: `list_open_tickets is scaffolded for tenant ${context.tenantId}.`,
      data: [
        {
          status: "not_implemented",
          query: input.query ?? null,
          filters: input,
          accountId: context.accountId
        }
      ],
      source: "connector-scaffold"
    };
  }
};

const haloFindContactTool: ConnectorToolDefinition<z.infer<typeof haloUserFiltersSchema>, NormalizedToolResponse> = {
  name: "find_contact",
  description:
    "Find a HaloPSA end user / requester / contact by name, email, phone, or username. Pass the user's name (or email) as `query` — DO NOT fill optional ID filters (client_id, site_id, department_id, asset_id) with 0 or placeholder values; omit them entirely unless you already know the real ID. Returns id, name, email, phone, customer, site, and active status.",
  inputSchema: haloUserFiltersSchema,
  async execute(context, input) {
    return {
      summary: `find_contact is scaffolded for tenant ${context.tenantId}.`,
      data: [
        {
          status: "not_implemented",
          query: input.query ?? null,
          filters: input,
          accountId: context.accountId
        }
      ],
      source: "connector-scaffold"
    };
  }
};

function getHaloBaseUrl() {
  const value = process.env.HALOPSA_BASE_URL ?? process.env.HALOPSA_URL;
  if (!value) {
    throw new Error("Set HALOPSA_BASE_URL in your environment to your HaloPSA instance URL");
  }

  return value.replace(/\/$/, "");
}

function getHaloScopes() {
  return (process.env.HALOPSA_SCOPES ?? "read:tickets read:customers read:actions offline_access")
    .split(/\s+/)
    .filter(Boolean);
}

async function exchangeHaloToken(params: URLSearchParams): Promise<TokenPair> {
  const response = await fetch(`${getHaloBaseUrl()}/auth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`HaloPSA token exchange failed (${response.status}): ${body}`);
  }

  const payload = (await response.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
  };

  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: payload.expires_in ? new Date(Date.now() + payload.expires_in * 1000) : undefined,
    scopes: payload.scope?.split(" ").filter(Boolean)
  };
}

export const haloPsaAdapter: ProviderAdapter = {
  provider: "halopsa",
  displayName: "HaloPSA",
  supportsOAuth: true,
  oauthConfig: {
    authorizationUrl: "http://localhost/placeholder",
    tokenUrl: "http://localhost/placeholder",
    scopes: getHaloScopes(),
    redirectUri: process.env.HALOPSA_REDIRECT_URI ?? "http://localhost:4000/oauth/halopsa/callback"
  },
  getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      client_id: process.env.HALOPSA_CLIENT_ID ?? "",
      redirect_uri: process.env.HALOPSA_REDIRECT_URI ?? "http://localhost:4000/oauth/halopsa/callback",
      response_type: "code",
      scope: getHaloScopes().join(" "),
      state
    });
    return `${getHaloBaseUrl()}/auth/authorize?${params.toString()}`;
  },
  async exchangeCode(code) {
    return exchangeHaloToken(
      new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.HALOPSA_CLIENT_ID ?? "",
        client_secret: process.env.HALOPSA_CLIENT_SECRET ?? "",
        code,
        redirect_uri: process.env.HALOPSA_REDIRECT_URI ?? "http://localhost:4000/oauth/halopsa/callback"
      })
    );
  },
  async refreshToken(_account, refreshToken) {
    return exchangeHaloToken(
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: process.env.HALOPSA_CLIENT_ID ?? "",
        client_secret: process.env.HALOPSA_CLIENT_SECRET ?? "",
        refresh_token: refreshToken
      })
    );
  },
  getTools() {
    return [
      createStubTool(
        "find_customer",
        "Use when the user wants to identify an organisation, customer account, or client record in HaloPSA by name, reference, or partial account text."
      ),
      createStubTool(
        "get_customer_overview",
        "Use when the user wants a combined HaloPSA view of a customer with their core account details plus recent open ticket activity."
      ),
      haloListOpenTicketsTool,
      createStubTool(
        "get_ticket",
        "Use when the user gives a specific HaloPSA ticket number, id, or visible ticket reference and wants the full details for one ticket."
      ),
      createStubTool(
        "get_ticket_with_actions",
        "Use when the user wants a single HaloPSA ticket together with its recent actions, notes, or engineer updates in one result."
      ),
      createStubTool(
        "list_ticket_actions",
        "Use when the user wants the notes, updates, engineer actions, or activity history recorded against a specific HaloPSA ticket."
      ),
      createStubTool(
        "search_projects",
        "Use when the user asks about projects, project tickets, project status, or project work in HaloPSA."
      ),
      haloFindContactTool,
      createStubTool(
        "search_documents",
        "Use when the user wants knowledge base articles, SOP-style documentation, or HaloPSA knowledge records."
      ),
      createStubTool(
        "list_devices_for_site",
        "Use when the user asks what devices, assets, or inventory items are recorded for a HaloPSA site or location."
      ),
      createStubTool(
        "list_halo_categories",
        "Use when the user wants to discover HaloPSA ticket categories, look up category IDs for filtering, or understand the category hierarchy. Returns all 4 tiers with numeric IDs, names, and parent relationships. Call this before list_open_tickets when filtering by category."
      ),
      createStubTool(
        "get_recent_invoices",
        "Use when the user wants recent invoice, billing, or finance records from HaloPSA in a read-only way."
      ),
      createStubTool(
        "create_draft_ticket",
        "Use only for safe ticket creation when the user explicitly wants a new ticket created. This should create a draft-style service ticket with minimal fields."
      ),
      createStubTool(
        "add_internal_note",
        "Use when the user explicitly wants to add an internal, non-customer-visible update or engineer note to an existing HaloPSA ticket."
      )
    ];
  }
};
