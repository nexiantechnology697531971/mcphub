import crypto from "node:crypto";

import Redis from "ioredis";
import jwt from "jsonwebtoken";

import { getProviderRegistry } from "@nexian/connectors";
import type { ConnectedAccountRecord, ProviderName } from "@nexian/core/domain/models";
import { TokenEncryptionService } from "@nexian/core/security/encryption";

import { buildAppConfig } from "../../common/config/env";
import { createOAuthState, verifyOAuthState } from "../../common/security/oauth-state";
import { ConnectorConfigStore } from "../../common/store/connector-config.store";
import { ConnectedAccountStore } from "../../common/store/connected-account.store";
import type { AuditService } from "../audit/audit.service";
import type { ModuleService } from "../modules/module.service";

import { executeActionStepTool } from "./actionstep-executor";
import { TokenRefreshService } from "./token-refresh.service";

const config = buildAppConfig();

type HaloTicketRecord = Record<string, unknown>;
type HaloClientRecord = Record<string, unknown>;
type HaloGenericRecord = Record<string, unknown>;
type ConnectorConfigInput = Record<string, unknown>;
type StoredConnectorConfig = {
  apiUrl?: string;
  authUrl?: string;
  clientId?: string;
  clientSecretEncrypted?: string;
  redirectUri?: string;
  scopes?: string[];
  tenantId?: string;
  appId?: string;
  webhookBaseUrl?: string;
  apiEndpoint?: string;
  environment?: string;
};

type N8nWorkflowRecord = Record<string, unknown>;
type N8nExecutionRecord = Record<string, unknown>;
type HaloStatusRecord = Record<string, unknown>;
type HaloCategoryRecord = Record<string, unknown>;

function pickString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
  }

  return undefined;
}

function pickNumber(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number") {
      return value;
    }
    if (typeof value === "string" && value.trim().length > 0 && !Number.isNaN(Number(value))) {
      return Number(value);
    }
  }

  return undefined;
}

function pickNestedString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const nested = pickString(value as Record<string, unknown>, ["name", "label", "displayName", "value", "text"]);
      if (nested) {
        return nested;
      }
    }
  }

  return undefined;
}

function pickNestedNumber(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const nested = pickNumber(value as Record<string, unknown>, ["id", "value", "statusId"]);
      if (nested !== undefined) {
        return nested;
      }
    }
  }

  return undefined;
}

function getHaloTicketStatus(record: HaloTicketRecord) {
  return (
    pickString(record, ["status_name", "status", "ticketstatus", "statusName", "ticket_status", "workflow_status"]) ??
    pickNestedString(record, ["status", "ticketstatus", "workflow_status", "ticket_status", "status_detail"])
  );
}

function extractHaloTickets(payload: unknown) {
  return normalizeCollectionPayload(payload, ["tickets", "results", "data", "records"]);
}

function buildSearchAliases(query: string, names: string[] = []) {
  const rawCandidates = [query, ...names]
    .flatMap((value) => [value, ...value.split(/[()/,-]/)])
    .map((value) => normalizeWhitespace(value))
    .filter(Boolean);

  const aliases = new Set<string>();
  for (const candidate of rawCandidates) {
    aliases.add(candidate);
    const words = candidate.split(/\s+/).filter((word) => word.length >= 4);
    for (const word of words) {
      aliases.add(word);
    }
  }

  return [...aliases].filter((value) => value.length >= 3);
}

function appendQueryValue(url: URL, key: string, value: unknown) {
  if (value === undefined || value === null) {
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return;
    }
    url.searchParams.set(key, value.join(","));
    return;
  }

  if (typeof value === "boolean") {
    url.searchParams.set(key, value ? "true" : "false");
    return;
  }

  const normalized = String(value).trim();
  if (!normalized) {
    return;
  }

  url.searchParams.set(key, normalized);
}

function pickPositiveInt(record: Record<string, unknown>, keys: string[]): number | undefined {
  for (const key of keys) {
    const value = record[key];
    const n = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
    if (Number.isFinite(n) && n > 0) {
      return Math.floor(n);
    }
  }
  return undefined;
}

function buildHaloOpenRuleFields(ticket: HaloTicketRecord, resolvedStatus: string | undefined) {
  return {
    statusResolvedFromHalo: resolvedStatus ?? "Unknown",
    isOpenByRule: (resolvedStatus ?? "").trim().toLowerCase() !== "closed",
    openRule: "A ticket is considered open unless its resolved status is exactly 'Closed'.",
    holdFlag: typeof ticket.onhold === "boolean" ? ticket.onhold : pickString(ticket, ["onhold", "on_hold", "holdstatus", "hold_status"])
  };
}

function buildHaloCategoryPath(ticket: HaloTicketRecord) {
  const parts = [
    pickString(ticket, ["category_1_name", "category1_name", "category_1", "category1"]),
    pickString(ticket, ["category_2_name", "category2_name", "category_2", "category2"]),
    pickString(ticket, ["category_3_name", "category3_name", "category_3", "category3"]),
    pickString(ticket, ["category_4_name", "category4_name", "category_4", "category4"])
  ].filter((value): value is string => Boolean(value && value.trim()));

  return parts.length > 0 ? parts.join(" > ") : undefined;
}

function stripHtmlToText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<\/(p|div|li|tr|h\d|br)>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function truncateText(value: string | undefined, max: number): string | undefined {
  if (!value) return value;
  if (value.length <= max) return value;
  return `${value.slice(0, max).trimEnd()}…`;
}

function isTruthyFlag(input: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = input[key];
    if (value === true) return true;
    if (typeof value === "string" && /^(1|true|yes|on)$/i.test(value.trim())) return true;
  }
  return false;
}

type NormalizedHaloTicketOptions = { includeRaw?: boolean };

function buildNormalizedHaloTicket(
  ticket: HaloTicketRecord,
  resolvedStatus: string | undefined,
  options: NormalizedHaloTicketOptions = {}
) {
  const openFields = buildHaloOpenRuleFields(ticket, resolvedStatus);
  const requestTypeName =
    pickString(ticket, [
      "requesttype_name",
      "request_type_name",
      "requesttype",
      "request_type",
      "itil_requesttype_name",
      "itil_requesttype"
    ]) ?? pickNestedString(ticket, ["requesttype", "request_type", "itil_requesttype"]);
  const ticketTypeName =
    pickString(ticket, ["tickettype_name", "ticket_type_name", "tickettype", "ticket_type", "type_name", "type"]) ??
    pickNestedString(ticket, ["tickettype", "ticket_type", "type"]);
  const workflowStepName =
    pickString(ticket, ["workflow_step_name", "workflowstep_name", "step_name", "workflow_status", "ticket_status"]) ??
    pickNestedString(ticket, ["workflow_step", "workflowstep", "workflow_status", "ticket_status"]);

  return {
    id: pickNumber(ticket, ["id", "ticket_id", "TicketID"]),
    summary: pickString(ticket, ["summary", "subject", "title"]) ?? "Untitled ticket",
    status: resolvedStatus,
    customer: pickString(ticket, ["client_name", "customer_name", "organisation_name"]),
    priority: pickString(ticket, ["priority_name", "priority"]),
    lastActionAt: pickString(ticket, ["last_action_date", "lastupdated", "dateupdated"]),
    category_1:
      pickString(ticket, ["category_1_name", "category1_name", "category_1", "category1"]) ?? undefined,
    category_2:
      pickString(ticket, ["category_2_name", "category2_name", "category_2", "category2"]) ?? undefined,
    category_3:
      pickString(ticket, ["category_3_name", "category3_name", "category_3", "category3"]) ?? undefined,
    category_4:
      pickString(ticket, ["category_4_name", "category4_name", "category_4", "category4"]) ?? undefined,
    category_path: buildHaloCategoryPath(ticket),
    request_type_name: requestTypeName,
    ticket_type_name: ticketTypeName,
    workflow_step_name: workflowStepName,
    is_closed: !openFields.isOpenByRule,
    resolved_status: resolvedStatus ?? "Unknown",
    ...openFields,
    ...(options.includeRaw ? { raw: ticket } : {})
  };
}

function buildDetailedHaloTicket(
  ticket: HaloTicketRecord,
  resolvedStatus: string | undefined,
  options: NormalizedHaloTicketOptions = {}
) {
  const base = buildNormalizedHaloTicket(ticket, resolvedStatus, options);

  const description =
    truncateText(stripHtmlToText(ticket.details ?? ticket.details_html), 4000) ??
    truncateText(stripHtmlToText(ticket.userdetails ?? ticket.user_details), 4000) ??
    truncateText(pickString(ticket, ["summary_text", "description", "body"]), 4000);

  const requesterName =
    pickString(ticket, ["user_name", "username", "reportedby", "reported_by", "contact_name"]) ??
    pickNestedString(ticket, ["user", "contact", "reportedby"]);
  const requesterEmail =
    pickString(ticket, ["user_email", "useremail", "contact_email", "reportedby_email"]) ??
    pickNestedString(ticket, ["user", "contact"]);

  const agentName =
    pickString(ticket, ["agent_name", "assigned_agent_name", "owner_name"]) ??
    pickNestedString(ticket, ["agent", "assigned_agent", "owner"]);

  const dateLogged = pickString(ticket, ["datecreated", "date_created", "datelogged", "date_logged", "created_at"]);
  const targetDate = pickString(ticket, ["targetdate", "target_date", "fix_by", "fixby", "deadlinedate", "deadline_date"]);
  const dateClosed = pickString(ticket, ["dateclosed", "date_closed", "closed_at"]);

  return {
    ...base,
    description,
    requester_name: requesterName,
    requester_email: requesterEmail,
    agent_name: agentName,
    date_logged: dateLogged,
    target_date: targetDate,
    date_closed: dateClosed
  };
}

function isProjectStyleTicket(ticket: HaloTicketRecord) {
  const requestType =
    pickString(ticket, [
      "requesttype_name",
      "request_type",
      "requesttype",
      "request_type_name",
      "itil_requesttype_name",
      "itil_requesttype"
    ]) ??
    pickNestedString(ticket, ["requesttype", "request_type", "itil_requesttype"]);
  const team =
    pickString(ticket, ["team_name", "team"]) ??
    pickNestedString(ticket, ["team", "team_name", "queue", "department"]);
  const normalizedRequestType = requestType?.trim().toLowerCase();
  const normalizedTeam = team?.trim().toLowerCase();

  const projectRequestTypes = new Set([
    "project (internal)",
    "project (internal task)",
    "project task",
    "project scoping",
    "project"
  ]);
  const projectQueues = new Set(["projects (internal)", "project engineers", "project enmgineers"]);

  return (
    (normalizedRequestType ? projectRequestTypes.has(normalizedRequestType) : false) ||
    (normalizedTeam ? projectQueues.has(normalizedTeam) : false)
  );
}

function dedupeTicketsById(tickets: HaloTicketRecord[]) {
  const seen = new Set<string>();
  const deduped: HaloTicketRecord[] = [];

  for (const ticket of tickets) {
    const key = String(
      pickNumber(ticket, ["id", "ticket_id", "TicketID", "ticketnumber", "ticket_number"]) ??
        pickString(ticket, ["id", "ticket_id", "TicketID", "ticketnumber", "ticket_number"]) ??
        JSON.stringify(ticket)
    );

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(ticket);
  }

  return deduped;
}

function isTicketOpen(record: HaloTicketRecord) {
  const closedCandidates = [
    record.closed,
    record.isclosed,
    record.isClosed,
    record.inactive,
    record.isinactive,
    record.dateclosed,
    record.closed_date,
    record.closedDate,
    record.datecompleted,
    record.completed_date,
    record.completedDate
  ];
  for (const candidate of closedCandidates) {
    if (typeof candidate === "boolean") {
      if (candidate) {
        return false;
      }
    }
    if (typeof candidate === "number") {
      if (candidate === 1) {
        return false;
      }
    }
    if (typeof candidate === "string") {
      const normalized = candidate.trim().toLowerCase();
      if (!normalized) {
        continue;
      }
      if (
        ["true", "1", "yes", "closed", "resolved", "completed", "cancelled", "canceled"].includes(normalized) ||
        /^\d{4}-\d{2}-\d{2}/.test(normalized)
      ) {
        return false;
      }
    }
  }

  const statusId =
    pickNumber(record, ["status_id", "ticketstatus_id", "ticketStatusId"]) ??
    pickNestedNumber(record, ["status", "ticketstatus", "workflow_status", "ticket_status"]);
  if (typeof statusId === "number" && statusId < 0) {
    return false;
  }

  const statusName = getHaloTicketStatus(record);
  if (!statusName) {
    return true;
  }

  return statusName.trim().toLowerCase() !== "closed";
}

function buildHaloHeaders(accessToken: string) {
  return {
    accept: "application/json",
    authorization: `Bearer ${accessToken}`
  };
}

function buildHaloJsonHeaders(accessToken: string) {
  return {
    ...buildHaloHeaders(accessToken),
    "content-type": "application/json"
  };
}

function ticketMatchesIdentifier(ticket: HaloTicketRecord, identifier: string) {
  const normalized = identifier.replace(/^0+/, "");
  const candidates = [
    pickString(ticket, ["id", "ticket_id", "TicketID", "ticketnumber", "ticket_number", "number"]),
    String(pickNumber(ticket, ["id", "ticket_id", "TicketID", "ticketnumber", "ticket_number", "number"]) ?? "")
  ]
    .map((value) => value?.trim())
    .filter(Boolean) as string[];

  return candidates.some((candidate) => candidate === identifier || candidate.replace(/^0+/, "") === normalized);
}

function normalizeCollectionPayload(payload: unknown, keys: string[]) {
  if (Array.isArray(payload)) {
    return payload as HaloGenericRecord[];
  }

  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    for (const key of keys) {
      const value = record[key];
      if (Array.isArray(value)) {
        return value as HaloGenericRecord[];
      }
    }
  }

  return [];
}

function payloadIsRecord(payload: unknown): payload is Record<string, unknown> {
  return Boolean(payload) && typeof payload === "object" && !Array.isArray(payload);
}

function extractHaloAssetRecords(payload: unknown): HaloGenericRecord[] {
  if (Array.isArray(payload)) {
    return payload.flatMap((entry) => extractHaloAssetRecords(entry));
  }

  if (!payload || typeof payload !== "object") {
    return [] as HaloGenericRecord[];
  }

  const record = payload as Record<string, unknown>;
  const nestedUser =
    record.user && typeof record.user === "object" && !Array.isArray(record.user)
      ? (record.user as Record<string, unknown>)
      : undefined;
  const nestedSite =
    record.site && typeof record.site === "object" && !Array.isArray(record.site)
      ? (record.site as Record<string, unknown>)
      : undefined;

  return [
    ...(Array.isArray(record.assets) ? (record.assets as HaloGenericRecord[]) : []),
    ...(Array.isArray(record.userassets) ? (record.userassets as HaloGenericRecord[]) : []),
    ...(Array.isArray(record.devices) ? (record.devices as HaloGenericRecord[]) : []),
    ...(nestedUser && Array.isArray(nestedUser.assets) ? (nestedUser.assets as HaloGenericRecord[]) : []),
    ...(nestedUser && Array.isArray(nestedUser.userassets) ? (nestedUser.userassets as HaloGenericRecord[]) : []),
    ...(nestedSite && Array.isArray(nestedSite.assets) ? (nestedSite.assets as HaloGenericRecord[]) : []),
    ...normalizeCollectionPayload(record, ["assets", "userassets", "devices", "results", "data"]),
    ...(nestedUser ? normalizeCollectionPayload(nestedUser, ["assets", "userassets", "devices", "results", "data"]) : []),
    ...(nestedSite ? normalizeCollectionPayload(nestedSite, ["assets", "userassets", "devices", "results", "data"]) : [])
  ];
}

function extractHaloAssetIdentifiers(asset: HaloGenericRecord) {
  const fieldValues = Array.isArray(asset.fields)
    ? (asset.fields as HaloGenericRecord[])
        .flatMap((field) => [pickString(field, ["value", "display", "name"])].filter(Boolean))
        .filter(Boolean)
    : [];

  return [
    pickString(asset, ["inventory_number", "inventoryNumber", "device_name", "deviceName"]),
    pickString(asset, ["name", "hostname", "systemName", "key_field", "keyfield"]),
    pickString(asset, ["serial_number", "serialno", "serial", "key_field2", "keyfield2"]),
    pickString(asset, ["username", "business_owner_name", "technical_owner_name"]),
    ...fieldValues
  ].filter(Boolean) as string[];
}

function extractHaloAssetSystemNames(asset: HaloGenericRecord) {
  return [
    pickString(asset, ["key_field", "keyfield", "name", "hostname", "systemName"]),
    pickString(asset, ["inventory_number", "inventoryNumber"])
  ]
    .filter((value): value is string => Boolean(value))
    .map((value) => normalizeWhitespace(value)) as string[];
}

function textMatches(value: string | undefined, query: string) {
  if (!value) {
    return false;
  }

  return value.toLowerCase().includes(query.toLowerCase());
}

function normalizeWhitespace(value: string) {
  return value.replace(/\s+/g, " ").trim();
}

function extractMeaningfulQuery(query: string | undefined, noisePatterns: RegExp[] = []) {
  if (!query) {
    return "";
  }

  let normalized = normalizeWhitespace(query.toLowerCase());
  for (const pattern of noisePatterns) {
    normalized = normalized.replace(pattern, " ");
  }

  normalized = normalized
    .replace(/\b(show|find|get|list|give me|tell me|search|lookup|for me|please|all|since|from)\b/g, " ")
    .replace(/[?.,]+/g, " ");

  return normalizeWhitespace(normalized);
}

function formatHaloDate(value: Date) {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, "0");
  const day = String(value.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function addDays(value: Date, days: number) {
  return new Date(value.getFullYear(), value.getMonth(), value.getDate() + days);
}

function extractNaturalHaloDateFilters(query: string | undefined): { datesearch?: string; startdate?: string; enddate?: string } {
  if (!query) {
    return {};
  }

  const normalized = query.toLowerCase();
  const now = new Date();

  const dateRange = (start: Date, end: Date) => ({
    datesearch: "dateoccurred",
    startdate: formatHaloDate(start),
    enddate: formatHaloDate(addDays(end, 1))
  });

  // YTD / year to date
  if (/\b(ytd|year to date|start of (the )?year|since january|since jan(?:uary)? 1(st)?)\b/.test(normalized)) {
    return dateRange(new Date(now.getFullYear(), 0, 1), now);
  }

  // Last quarter / previous quarter
  if (/\b(last quarter|previous quarter|prior quarter)\b/.test(normalized)) {
    const currentQuarter = Math.floor(now.getMonth() / 3);
    const lastQuarterStart = currentQuarter === 0
      ? new Date(now.getFullYear() - 1, 9, 1)
      : new Date(now.getFullYear(), (currentQuarter - 1) * 3, 1);
    const lastQuarterEnd = currentQuarter === 0
      ? new Date(now.getFullYear() - 1, 11, 31)
      : new Date(now.getFullYear(), currentQuarter * 3, 0);
    return dateRange(lastQuarterStart, lastQuarterEnd);
  }

  // This quarter / current quarter
  if (/\b(this quarter|current quarter)\b/.test(normalized)) {
    const quarterStart = Math.floor(now.getMonth() / 3) * 3;
    return dateRange(new Date(now.getFullYear(), quarterStart, 1), now);
  }

  // Explicit quarter names: Q1, Q2, Q3, Q4 (with optional year)
  const quarterMatch = normalized.match(/\bq([1-4])(?:\s+(\d{4}))?\b/);
  if (quarterMatch) {
    const q = parseInt(quarterMatch[1], 10);
    const year = quarterMatch[2] ? parseInt(quarterMatch[2], 10) : now.getFullYear();
    const qStart = new Date(year, (q - 1) * 3, 1);
    const qEnd = new Date(year, q * 3, 0);
    return dateRange(qStart, qEnd > now ? now : qEnd);
  }

  // This month / current month / MTD
  if (/\b(this month|current month|month to date|mtd)\b/.test(normalized)) {
    return dateRange(new Date(now.getFullYear(), now.getMonth(), 1), now);
  }

  // Last month / previous month
  if (/\b(last month|previous month|prior month)\b/.test(normalized)) {
    const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const lastMonthEnd = new Date(now.getFullYear(), now.getMonth(), 0);
    return dateRange(lastMonthStart, lastMonthEnd);
  }

  // This week / current week
  if (/\b(this week|current week)\b/.test(normalized)) {
    const dayOfWeek = now.getDay();
    const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - dayOfWeek);
    return dateRange(weekStart, now);
  }

  // Last week / previous week
  if (/\b(last week|previous week|prior week)\b/.test(normalized)) {
    const dayOfWeek = now.getDay();
    const lastWeekEnd = new Date(now.getFullYear(), now.getMonth(), now.getDate() - dayOfWeek - 1);
    const lastWeekStart = new Date(lastWeekEnd.getFullYear(), lastWeekEnd.getMonth(), lastWeekEnd.getDate() - 6);
    return dateRange(lastWeekStart, lastWeekEnd);
  }

  // Last N days/weeks/months
  const lastNMatch = normalized.match(/\b(?:last|past|previous)\s+(\d+)\s+(days?|weeks?|months?)\b/);
  if (lastNMatch) {
    const n = parseInt(lastNMatch[1], 10);
    const unit = lastNMatch[2].replace(/s$/, "");
    const start = new Date(now);
    if (unit === "day") {
      start.setDate(start.getDate() - n);
    } else if (unit === "week") {
      start.setDate(start.getDate() - n * 7);
    } else if (unit === "month") {
      start.setMonth(start.getMonth() - n);
    }
    return dateRange(start, now);
  }

  // Last year / previous year
  if (/\b(last year|previous year|prior year)\b/.test(normalized)) {
    return dateRange(new Date(now.getFullYear() - 1, 0, 1), new Date(now.getFullYear() - 1, 11, 31));
  }

  if (/\byesterday\b/.test(normalized)) {
    const yesterday = addDays(now, -1);
    return dateRange(yesterday, yesterday);
  }

  if (/\btoday\b/.test(normalized)) {
    return dateRange(now, now);
  }

  // Specific month names: "in January", "in Feb 2025", "January 2025"
  const monthNames = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
  const monthAbbrevs = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  const monthPattern = normalized.match(
    /\b(?:in\s+|during\s+|for\s+)?(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)(?:\s+(\d{4}))?\b/
  );
  if (monthPattern) {
    const monthName = monthPattern[1];
    const monthIndex = monthNames.indexOf(monthName) !== -1
      ? monthNames.indexOf(monthName)
      : monthAbbrevs.indexOf(monthName);
    if (monthIndex !== -1) {
      const year = monthPattern[2] ? parseInt(monthPattern[2], 10) : now.getFullYear();
      const monthStart = new Date(year, monthIndex, 1);
      const monthEnd = new Date(year, monthIndex + 1, 0);
      return dateRange(monthStart, monthEnd > now ? now : monthEnd);
    }
  }

  return {};
}

function inferHaloTicketDateSearch(query: string | undefined) {
  const normalized = query?.toLowerCase() ?? "";
  if (!normalized) {
    return "dateoccurred";
  }

  if (/\b(closed|cleared|resolved|completed|cancelled|canceled|archived)\b/.test(normalized)) {
    return "dateclosed";
  }

  if (/\b(updated|actioned|responded|last touched|worked on)\b/.test(normalized)) {
    return "lastactiondate";
  }

  return "dateoccurred";
}

function sanitizeHaloTicketDateFilters(filters: Record<string, unknown>, query: string | undefined) {
  const sanitized = { ...filters };
  const hasDateWindow =
    typeof sanitized.startdate === "string" ||
    typeof sanitized.enddate === "string";

  if (!hasDateWindow && typeof sanitized.datesearch !== "string") {
    return sanitized;
  }

  const rawDateSearch = typeof sanitized.datesearch === "string" ? sanitized.datesearch.trim().toLowerCase() : "";
  const normalizedDateSearch = rawDateSearch === "dateoccured" ? "dateoccurred" : rawDateSearch;
  const allowedLifecycleDateSearches = new Set(["dateoccurred", "dateclosed", "dateassigned", "responsedate", "lastactiondate", "last_update"]);

  if (!normalizedDateSearch || !allowedLifecycleDateSearches.has(normalizedDateSearch)) {
    sanitized.datesearch = inferHaloTicketDateSearch(query);
  } else {
    sanitized.datesearch = normalizedDateSearch;
  }

  return sanitized;
}

function isNinjaUnauthorizedError(error: unknown) {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("ninjaone request failed (401)") ||
    message.includes("\"not_authenticated\"") ||
    message.includes("invalid credentials")
  );
}

function wantsOpenItems(input: Record<string, unknown>, query: string | undefined) {
  if (typeof input.includeClosed === "boolean") {
    return !input.includeClosed;
  }

  const normalized = query?.toLowerCase() ?? "";
  if (!normalized) {
    return true;
  }

  if (/\b(all|closed|resolved|completed|cancelled|canceled|archived)\b/.test(normalized)) {
    return false;
  }

  return /\b(open|active|outstanding|recent|current|live|in progress|in-progress)\b/.test(normalized) || true;
}

function isProjectOpen(record: HaloGenericRecord) {
  const statusName = pickString(record, ["status_name", "status", "project_status", "projectStatus"])?.toLowerCase();
  if (!statusName) {
    return true;
  }

  return !["closed", "completed", "cancelled", "canceled", "resolved", "archived"].some((keyword) =>
    statusName.includes(keyword)
  );
}

function ticketMatchesHaloQuery(ticket: HaloTicketRecord, query: string) {
  const normalizedQuery = normalizeWhitespace(query).toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  const fields = [
    pickString(ticket, ["summary", "subject", "title"]),
    pickString(ticket, ["details", "description", "body"]),
    pickString(ticket, ["category_1_name", "category1_name", "category_1", "category1"]),
    pickString(ticket, ["category_2_name", "category2_name", "category_2", "category2"]),
    pickString(ticket, ["category_3_name", "category3_name", "category_3", "category3"]),
    pickString(ticket, ["category_4_name", "category4_name", "category_4", "category4"]),
    buildHaloCategoryPath(ticket),
    pickString(ticket, ["requesttype_name", "request_type_name", "requesttype", "request_type"]),
    pickString(ticket, ["tickettype_name", "ticket_type_name", "tickettype", "ticket_type"]),
    pickString(ticket, ["client_name", "customer_name", "organisation_name"]),
    pickString(ticket, ["site_name", "location_name"])
  ];

  // Match if the full query matches any field, or if every query word matches at least one field
  if (fields.some((value) => textMatches(value, normalizedQuery))) {
    return true;
  }

  const queryWords = normalizedQuery.split(/\s+/).filter((word) => word.length >= 2);
  if (queryWords.length > 1) {
    return queryWords.every((word) => fields.some((value) => textMatches(value, word)));
  }

  return false;
}

function normalizeIdentityToken(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function buildIdentityVariants(value: string) {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return [];
  }

  const pieces = normalized
    .split(/[\s@._\\/-]+/)
    .map((piece) => piece.trim())
    .filter(Boolean);

  const joined = pieces.join("");
  const dashed = pieces.join("-");
  const underscored = pieces.join("_");
  const emailLocalPart = normalized.includes("@") ? normalized.split("@")[0] : "";
  const baseCandidates = [
    pieces.length <= 2 ? normalized : "",
    pieces.length <= 2 ? normalized.replace(/\s+/g, "") : "",
    joined,
    dashed,
    underscored,
    emailLocalPart,
    normalized.replace(/^.*\\/, ""),
    normalized.replace(/^.*\//, "")
  ];

  const variants = new Set(
    baseCandidates
      .map((candidate) => candidate.trim())
      .filter(Boolean)
  );

  if (pieces.length >= 2) {
    variants.add(`${pieces[0]}${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0]}.${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0]}_${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0]}-${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[pieces.length - 1]}${pieces[0]}`);
    variants.add(`${pieces[0][0]}${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0][0]}.${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0][0]}_${pieces[pieces.length - 1]}`);
    variants.add(`${pieces[0][0]}-${pieces[pieces.length - 1]}`);
  }

  const baseVariants = [...variants];
  for (const variant of baseVariants) {
    variants.add(`AzureAD\\${variant}`);
    variants.add(`AzureAD/${variant}`);
  }

  return [...variants].filter((candidate) => candidate.length <= 64 && !/\s{2,}/.test(candidate));
}

function deviceMatchesUserHint(device: Record<string, unknown>, userHint: string) {
  if (!userHint) {
    return true;
  }

  const variants = buildIdentityVariants(userHint);
  const candidates = [
    pickString(device, [
      "lastLoggedInUser",
      "lastLogin",
      "last_login",
      "lastUser",
      "currentUser",
      "loggedInUser",
      "assignedUser",
      "userName",
      "username"
    ]),
    pickString(device, ["primaryUser", "owner", "contactName", "user", "displayName", "loggedInUsername"]),
    pickString(device, ["email", "emailAddress", "userEmail"]),
    pickString(device, ["organizationName", "organisationName", "customerName"])
  ].filter(Boolean) as string[];

  return candidates.some((candidate) => {
    const loweredCandidate = candidate.toLowerCase();
    const normalizedCandidate = normalizeIdentityToken(candidate);
    return variants.some((variant) => {
      const loweredVariant = variant.toLowerCase();
      const normalizedVariant = normalizeIdentityToken(variant);
      return loweredCandidate.includes(loweredVariant) || normalizedCandidate.includes(normalizedVariant);
    });
  });
}

function looksLikeDeviceIdentityQuery(query: string) {
  const normalized = normalizeWhitespace(query);
  if (!normalized) {
    return false;
  }

  if (/^[A-Z]{2,}\d{3,}$/i.test(normalized.replace(/\s+/g, ""))) {
    return true;
  }

  return /[\\/_-]/.test(normalized) || /\d/.test(normalized);
}

function scoreNinjaOneDevice(
  device: Record<string, unknown>,
  query: string,
  userHints: string[],
  organizationHints: string[],
  deviceHints: string[] = []
) {
  let score = 0;

  const nameCandidate = pickString(device, ["systemName", "displayName", "hostname", "name"]);
  const organizationCandidate = pickString(device, ["organizationName", "organisationName", "customerName", "siteName"]);
  const serialCandidate = pickString(device, ["serialNumber", "serial"]);

  if (query && textMatches(nameCandidate, query)) {
    score += 4;
  }

  for (const hint of deviceHints) {
    if (textMatches(nameCandidate, hint) || textMatches(serialCandidate, hint)) {
      score += 10;
    }
  }

  if (organizationHints.length > 0) {
    for (const hint of organizationHints) {
      if (textMatches(organizationCandidate, hint)) {
        score += 5;
      }
    }
  }

  if (userHints.length > 0) {
    for (const hint of userHints) {
      if (deviceMatchesUserHint(device, hint)) {
        score += 7;
      }
    }
  }

  return score;
}

function extractUserHint(query: string | undefined) {
  if (!query) {
    return "";
  }

  const match =
    query.match(/\bdevices?\s+(?:for|used by|belonging to|assigned to)\s+(.+)$/i) ??
    query.match(/\bfor\s+(.+)$/i);

  return normalizeWhitespace(match?.[1] ?? "");
}

type ResolvedEntityHints = {
  userHints: string[];
  organizationHints: string[];
  emailHints: string[];
  deviceHints: string[];
};

const haloDebugEnabled = process.env.HALO_DEBUG === "true";
const ninjaDebugEnabled = process.env.NINJA_DEBUG === "true";

function logHaloDebug(event: string, payload: Record<string, unknown>) {
  if (!haloDebugEnabled) {
    return;
  }

  console.info("[halo-debug]", JSON.stringify({ event, ...payload }));
}

function logNinjaDebug(event: string, payload: Record<string, unknown>) {
  if (!ninjaDebugEnabled) {
    return;
  }

  console.info("[ninja-debug]", JSON.stringify({ event, ...payload }));
}

type HaloFetchInit = RequestInit & {
  bodyPreview?: unknown;
  retries?: number;
  timeoutMs?: number;
};

const HALO_DEFAULT_TIMEOUT_MS = Number(process.env.HALO_TIMEOUT_MS) || 15_000;
const HALO_DEFAULT_RETRIES = Number(process.env.HALO_MAX_RETRIES) || 3;
const HALO_RETRY_BASE_MS = 300;

function isHaloRetryableStatus(status: number) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function isHaloIdempotentMethod(method?: string) {
  const upper = (method ?? "GET").toUpperCase();
  return upper === "GET" || upper === "HEAD" || upper === "OPTIONS";
}

function computeHaloBackoff(attempt: number) {
  const base = HALO_RETRY_BASE_MS * 2 ** (attempt - 1);
  const jitter = Math.floor(Math.random() * base);
  return base + jitter;
}

function parseHaloRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const trimmed = header.trim();
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(trimmed);
  if (!Number.isNaN(date)) {
    const diff = date - Date.now();
    return diff > 0 ? diff : 0;
  }
  return undefined;
}

function haloDelay(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

async function haloFetch(input: string | URL, init: HaloFetchInit = {}) {
  const url = typeof input === "string" ? input : input.toString();
  const { bodyPreview, retries, timeoutMs, ...requestInit } = init;
  const method = (requestInit.method ?? "GET").toUpperCase();
  const idempotent = isHaloIdempotentMethod(method);
  const maxAttempts = Math.max(1, retries ?? (idempotent ? HALO_DEFAULT_RETRIES : 1));
  const timeout = timeoutMs ?? HALO_DEFAULT_TIMEOUT_MS;

  logHaloDebug("request", {
    method,
    url,
    body: bodyPreview ?? (typeof requestInit.body === "string" ? requestInit.body : undefined),
    maxAttempts,
    timeoutMs: timeout
  });

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, { ...requestInit, signal: controller.signal });
      clearTimeout(timer);

      logHaloDebug("response", {
        method,
        url,
        status: response.status,
        ok: response.ok,
        attempt
      });

      if (!response.ok && isHaloRetryableStatus(response.status) && attempt < maxAttempts) {
        const retryAfterMs = parseHaloRetryAfter(response.headers.get("retry-after"));
        await haloDelay(retryAfterMs ?? computeHaloBackoff(attempt));
        continue;
      }

      return response;
    } catch (error) {
      clearTimeout(timer);
      lastError = error;

      logHaloDebug("error", {
        method,
        url,
        attempt,
        error: error instanceof Error ? error.message : String(error)
      });

      if (attempt < maxAttempts && idempotent) {
        await haloDelay(computeHaloBackoff(attempt));
        continue;
      }

      throw error;
    }
  }

  throw lastError ?? new Error("haloFetch exhausted retries without response");
}

class HaloRecordCache<T> {
  private readonly memory = new Map<string, { expiresAt: number; records: T[] }>();

  constructor(
    private readonly redis: Redis | undefined,
    private readonly namespace: string,
    private readonly ttlMs: number
  ) {}

  async get(key: string): Promise<T[] | undefined> {
    const memHit = this.memory.get(key);
    if (memHit && memHit.expiresAt > Date.now()) {
      return memHit.records;
    }

    if (this.redis) {
      try {
        const raw = await this.redis.get(this.redisKey(key));
        if (raw) {
          const records = JSON.parse(raw) as T[];
          this.memory.set(key, { expiresAt: Date.now() + this.ttlMs, records });
          return records;
        }
      } catch (error) {
        console.warn("[halo-cache]", `redis read failed (${this.namespace}):`, error instanceof Error ? error.message : error);
      }
    }

    return undefined;
  }

  async set(key: string, records: T[]) {
    this.memory.set(key, { expiresAt: Date.now() + this.ttlMs, records });

    if (this.redis) {
      try {
        await this.redis.set(this.redisKey(key), JSON.stringify(records), "PX", this.ttlMs);
      } catch (error) {
        console.warn("[halo-cache]", `redis write failed (${this.namespace}):`, error instanceof Error ? error.message : error);
      }
    }
  }

  private redisKey(key: string) {
    return `halo:cache:${this.namespace}:${key}`;
  }
}

function buildHaloCacheKey(baseUrl: string, accessToken: string) {
  const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex").slice(0, 16);
  return `${baseUrl}|${tokenHash}`;
}

export class ConnectorService {
  private readonly registry = getProviderRegistry();
  private readonly encryption = TokenEncryptionService.fromBase64(config.tokenEncryptionKeyBase64);
  private readonly redis = config.redisUrl
    ? new Redis(config.redisUrl, {
        lazyConnect: true,
        maxRetriesPerRequest: 1
      })
    : undefined;
  private readonly refreshService = new TokenRefreshService(this.redis, this.encryption);
  private readonly store = ConnectedAccountStore.createDefault();
  private readonly configStore = ConnectorConfigStore.createDefault();
  private readonly haloStatusCache = new HaloRecordCache<HaloStatusRecord>(this.redis, "status", 5 * 60 * 1000);
  private readonly haloCategoryCache = new HaloRecordCache<HaloCategoryRecord>(this.redis, "category", 10 * 60 * 1000);

  constructor(
    private readonly auditService: AuditService,
    private readonly moduleService: ModuleService
  ) {
    this.redis?.on("error", (error) => {
      console.warn("[redis]", error.message);
    });
  }

  private async getEnabledProvidersForTenant(tenantId: string | undefined) {
    if (!tenantId) return undefined;
    const { enabledProviders } = await this.moduleService.getEnabledProvidersForTenant(tenantId);
    return enabledProviders;
  }

  async getProviders(tenantId?: string, userId?: string) {
    const accounts = tenantId && userId ? await this.store.findByTenantUser(tenantId, userId) : [];
    const enabled = await this.getEnabledProvidersForTenant(tenantId);

    return [...this.registry.values()]
      .filter((adapter) => !enabled || enabled.has(adapter.provider))
      .map((adapter) => {
        const account = accounts.find((candidate) => candidate.provider === adapter.provider);
        return {
          provider: adapter.provider,
          displayName: adapter.displayName,
          supportsOAuth: adapter.supportsOAuth,
          status: account?.status ?? "DISCONNECTED",
          connected: Boolean(account),
          lastError: account?.lastError,
          toolNames: adapter.getTools().map((tool) => tool.name)
        };
      });
  }

  private async assertProviderEnabledForTenant(provider: ProviderName, tenantId: string) {
    const enabled = await this.getEnabledProvidersForTenant(tenantId);
    if (enabled && !enabled.has(provider)) {
      throw new Error(`Connector ${provider} is not enabled for this tenant`);
    }
  }

  async beginOAuth(provider: ProviderName, tenantId: string, userId: string, returnTo?: string) {
    await this.assertProviderEnabledForTenant(provider, tenantId);

    if (provider === "halopsa") {
      const haloConfig = await this.resolveHaloConfig(tenantId);
      const state = createOAuthState({ provider, tenantId, userId, returnTo }, config.oauthStateSigningSecret);
      const params = new URLSearchParams({
        client_id: haloConfig.clientId,
        redirect_uri: haloConfig.redirectUri,
        response_type: "code",
        scope: haloConfig.scopes.join(" "),
        state
      });

      return { authorizationUrl: `${haloConfig.authUrl}/auth/authorize?${params.toString()}` };
    }

    if (provider === "ninjaone") {
      const ninjaConfig = await this.resolveNinjaOneConfig(tenantId);
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      const state = createOAuthState({ provider, tenantId, userId, returnTo, codeVerifier }, config.oauthStateSigningSecret);
      const params = new URLSearchParams({
        client_id: ninjaConfig.clientId,
        redirect_uri: ninjaConfig.redirectUri,
        response_type: "code",
        scope: ninjaConfig.scopes.join(" "),
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state
      });

      return { authorizationUrl: `${ninjaConfig.authUrl}/ws/oauth/authorize?${params.toString()}` };
    }

    if (provider === "actionstep") {
      const asConfig = await this.resolveActionStepConfig(tenantId);
      const state = createOAuthState({ provider, tenantId, userId, returnTo }, config.oauthStateSigningSecret);
      const params = new URLSearchParams({
        response_type: "code",
        client_id: asConfig.clientId,
        redirect_uri: asConfig.redirectUri,
        scope: asConfig.scopes.join(" "),
        state
      });
      return { authorizationUrl: `${asConfig.authorizeUrl}?${params.toString()}` };
    }

    const adapter = this.registry.get(provider);
    if (!adapter?.supportsOAuth || !adapter.getAuthorizationUrl) {
      throw new Error(`Provider ${provider} does not support OAuth`);
    }

    const state = createOAuthState({ provider, tenantId, userId, returnTo }, config.oauthStateSigningSecret);
    return { authorizationUrl: adapter.getAuthorizationUrl(state) };
  }

  async finishOAuth(provider: ProviderName, code: string, state: string) {
    if (provider === "halopsa") {
      const payload = verifyOAuthState(state, config.oauthStateSigningSecret);
      const haloConfig = await this.resolveHaloConfig(payload.tenantId);
      const tokens = await this.exchangeHaloToken(
        haloConfig,
        new URLSearchParams({
          grant_type: "authorization_code",
          client_id: haloConfig.clientId,
          client_secret: haloConfig.clientSecret,
          code,
          redirect_uri: haloConfig.redirectUri
        })
      );
      const now = new Date();
      const account: ConnectedAccountRecord = {
        id: crypto.randomUUID(),
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        providerAccountId: payload.userId,
        accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
        refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : undefined,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? haloConfig.scopes,
        metadataJson: {
          connectedVia: "oauth_authorization_code",
          apiUrl: haloConfig.apiUrl,
          clientId: haloConfig.clientId,
          redirectUri: haloConfig.redirectUri,
          scopes: haloConfig.scopes
        },
        status: "ACTIVE",
        lastError: undefined,
        createdAt: now,
        updatedAt: now
      };

      await this.store.upsert(account);
      await this.auditService.log({
        tenantId: payload.tenantId,
        userId: payload.userId,
        action: "CONNECTOR_CONNECTED",
        targetType: "connected_account",
        metadata: { provider }
      });

      return {
        returnTo: payload.returnTo ?? `${config.appUrl}/dashboard/connectors`,
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? haloConfig.scopes
      };
    }

    if (provider === "ninjaone") {
      const payload = verifyOAuthState(state, config.oauthStateSigningSecret);
      const ninjaConfig = await this.resolveNinjaOneConfig(payload.tenantId);
      const tokenParams = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: ninjaConfig.clientId,
        code,
        redirect_uri: ninjaConfig.redirectUri
      });
      if (payload.codeVerifier) {
        tokenParams.set("code_verifier", payload.codeVerifier);
      }
      if (ninjaConfig.clientSecret) {
        tokenParams.set("client_secret", ninjaConfig.clientSecret);
      }
      const tokens = await this.exchangeNinjaOneToken(ninjaConfig, tokenParams);
      const now = new Date();
      const account: ConnectedAccountRecord = {
        id: crypto.randomUUID(),
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        providerAccountId: payload.userId,
        accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
        refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : undefined,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? ninjaConfig.scopes,
        metadataJson: {
          connectedVia: "oauth_authorization_code",
          apiUrl: ninjaConfig.apiUrl,
          authUrl: ninjaConfig.authUrl,
          clientId: ninjaConfig.clientId,
          redirectUri: ninjaConfig.redirectUri,
          scopes: ninjaConfig.scopes
        },
        status: "ACTIVE",
        lastError: undefined,
        createdAt: now,
        updatedAt: now
      };

      await this.store.upsert(account);
      await this.auditService.log({
        tenantId: payload.tenantId,
        userId: payload.userId,
        action: "CONNECTOR_CONNECTED",
        targetType: "connected_account",
        metadata: { provider }
      });

      return {
        returnTo: payload.returnTo ?? `${config.appUrl}/dashboard/connectors`,
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? ninjaConfig.scopes
      };
    }

    if (provider === "actionstep") {
      const payload = verifyOAuthState(state, config.oauthStateSigningSecret);
      const asConfig = await this.resolveActionStepConfig(payload.tenantId);
      const tokens = await this.exchangeActionStepToken(
        asConfig,
        new URLSearchParams({
          grant_type: "authorization_code",
          client_id: asConfig.clientId,
          client_secret: asConfig.clientSecret,
          code,
          redirect_uri: asConfig.redirectUri
        })
      );

      if (!tokens.apiEndpoint) {
        throw new Error(
          "ActionStep token response did not include api_endpoint — cannot determine the regional API base URL"
        );
      }

      const now = new Date();
      const account: ConnectedAccountRecord = {
        id: crypto.randomUUID(),
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        providerAccountId: payload.userId,
        accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
        refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : undefined,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? asConfig.scopes,
        metadataJson: {
          connectedVia: "oauth_authorization_code",
          apiEndpoint: tokens.apiEndpoint,
          environment: asConfig.environment,
          clientId: asConfig.clientId,
          redirectUri: asConfig.redirectUri,
          scopes: tokens.scopes ?? asConfig.scopes
        },
        status: "ACTIVE",
        lastError: undefined,
        createdAt: now,
        updatedAt: now
      };

      await this.store.upsert(account);
      await this.auditService.log({
        tenantId: payload.tenantId,
        userId: payload.userId,
        action: "CONNECTOR_CONNECTED",
        targetType: "connected_account",
        metadata: { provider, apiEndpoint: tokens.apiEndpoint }
      });

      return {
        returnTo: payload.returnTo ?? `${config.appUrl}/dashboard/connectors`,
        tenantId: payload.tenantId,
        userId: payload.userId,
        provider,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scopes ?? asConfig.scopes
      };
    }

    const adapter = this.registry.get(provider);
    if (!adapter?.exchangeCode) {
      throw new Error(`Provider ${provider} does not support token exchange`);
    }

    const payload = verifyOAuthState(state, config.oauthStateSigningSecret);
    const tokens = await adapter.exchangeCode(code);
    const now = new Date();
    const account: ConnectedAccountRecord = {
      id: crypto.randomUUID(),
      tenantId: payload.tenantId,
      userId: payload.userId,
      provider,
      providerAccountId: payload.userId,
      accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
      refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : undefined,
      expiresAt: tokens.expiresAt,
      scopes: tokens.scopes ?? adapter.oauthConfig?.scopes ?? [],
      metadataJson: { connectedVia: "oauth_authorization_code" },
      status: "ACTIVE",
      lastError: undefined,
      createdAt: now,
      updatedAt: now
    };

    await this.store.upsert(account);
    await this.auditService.log({
      tenantId: payload.tenantId,
      userId: payload.userId,
      action: "CONNECTOR_CONNECTED",
      targetType: "connected_account",
      metadata: { provider }
    });

    return {
      returnTo: payload.returnTo ?? `${config.appUrl}/dashboard/connectors`,
      tenantId: payload.tenantId,
      userId: payload.userId,
      provider,
      expiresAt: tokens.expiresAt,
      scopes: tokens.scopes ?? adapter.oauthConfig?.scopes ?? []
    };
  }

  async disconnect(provider: ProviderName, tenantId: string, userId: string) {
    await this.store.disconnect(tenantId, userId, provider);
    await this.auditService.log({
      tenantId,
      userId,
      action: "CONNECTOR_DISCONNECTED",
      targetType: "connected_account",
      metadata: { provider }
    });
  }

  async getConnectedAccounts(tenantId: string, userId: string) {
    const accounts = await this.store.findByTenantUser(tenantId, userId);
    return accounts.map((account) => ({
      provider: account.provider,
      status: account.status,
      scopes: account.scopes,
      expiresAt: account.expiresAt?.toISOString(),
      lastError: account.lastError
    }));
  }

  async getConnectorConfig(tenantId: string, provider: ProviderName) {
    const record = await this.configStore.get(tenantId, provider);
    const configJson = (record?.configJson ?? {}) as StoredConnectorConfig;

    switch (provider) {
      case "halopsa":
        return {
          provider,
          config: {
            apiUrl: configJson.apiUrl ?? "",
            authUrl: configJson.authUrl ?? "",
            clientId: configJson.clientId ?? "",
            redirectUri: configJson.redirectUri ?? process.env.HALOPSA_REDIRECT_URI ?? `${config.apiUrl}/oauth/halopsa/callback`,
            scopes: (configJson.scopes ?? this.getDefaultHaloScopes()).join(" "),
            hasClientSecret: Boolean(configJson.clientSecretEncrypted)
          }
        };
      case "ninjaone":
        return {
          provider,
          config: {
            apiUrl: configJson.apiUrl ?? "",
            authUrl: configJson.authUrl ?? "",
            clientId: configJson.clientId ?? "",
            redirectUri: configJson.redirectUri ?? "",
            scopes: (configJson.scopes ?? ["monitoring", "management", "control"]).join(" "),
            hasClientSecret: Boolean(configJson.clientSecretEncrypted)
          }
        };
      case "cipp":
        return {
          provider,
          config: {
            apiUrl: configJson.apiUrl ?? "",
            tenantId: configJson.tenantId ?? "",
            clientId: configJson.clientId ?? configJson.appId ?? "",
            hasClientSecret: Boolean(configJson.clientSecretEncrypted)
          }
        };
      case "n8n":
        return {
          provider,
          config: {
            apiUrl: configJson.apiUrl ?? "",
            clientId: configJson.clientId ?? "",
            redirectUri: configJson.webhookBaseUrl ?? "",
            hasClientSecret: Boolean(configJson.clientSecretEncrypted)
          }
        };
      case "actionstep":
        return {
          provider,
          config: {
            clientId: configJson.clientId ?? "",
            redirectUri:
              configJson.redirectUri
              ?? process.env.ACTIONSTEP_REDIRECT_URI
              ?? `${config.apiUrl}/oauth/actionstep/callback`,
            scopes: (configJson.scopes ?? this.getDefaultActionStepScopes()).join(" "),
            environment: configJson.environment ?? process.env.ACTIONSTEP_ENV ?? "production",
            hasClientSecret: Boolean(configJson.clientSecretEncrypted)
          }
        };
      default:
        return { provider, config: {} };
    }
  }

  async saveConnectorConfig(tenantId: string, userId: string, provider: ProviderName, input: ConnectorConfigInput) {
    const existing = (await this.configStore.get(tenantId, provider))?.configJson as StoredConnectorConfig | undefined;
    const nextConfig = this.buildConnectorConfig(provider, input, existing);
    const now = new Date();

    await this.configStore.upsert({
      tenantId,
      provider,
      configJson: nextConfig,
      createdAt: now,
      updatedAt: now
    });

    await this.auditService.log({
      tenantId,
      userId,
      action: "CONNECTOR_CONFIG_UPDATED",
      targetType: "connector_config",
      metadata: { provider }
    });

    return this.getConnectorConfig(tenantId, provider);
  }

  async listN8nWorkflows(tenantId: string) {
    const n8nConfig = await this.resolveN8nConfig(tenantId);
    const response = await fetch(`${n8nConfig.apiUrl}/workflows`, {
      headers: {
        accept: "application/json",
        "X-N8N-API-KEY": n8nConfig.apiKey
      }
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`n8n workflows request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as { data?: N8nWorkflowRecord[] } | N8nWorkflowRecord[];
    const records = Array.isArray(payload) ? payload : Array.isArray(payload.data) ? payload.data : [];

    return records.map((workflow) => ({
      id: String(pickString(workflow, ["id"]) ?? pickNumber(workflow, ["id"]) ?? ""),
      name: pickString(workflow, ["name"]) ?? "Untitled workflow",
      active: Boolean(workflow.active),
      updatedAt:
        pickString(workflow, ["updatedAt", "updated_at"]) ??
        pickString(workflow, ["createdAt", "created_at"]) ??
        new Date().toISOString(),
      tags: Array.isArray(workflow.tags)
        ? workflow.tags
            .map((tag) => {
              if (typeof tag === "string") {
                return tag;
              }

              if (tag && typeof tag === "object") {
                return pickString(tag as Record<string, unknown>, ["name"]);
              }

              return undefined;
            })
            .filter(Boolean)
        : []
    }));
  }

  async listN8nExecutions(tenantId: string, workflowId?: string) {
    const n8nConfig = await this.resolveN8nConfig(tenantId);
    const url = new URL(`${n8nConfig.apiUrl}/executions`);
    url.searchParams.set("limit", "25");
    if (workflowId) {
      url.searchParams.set("workflowId", workflowId);
    }

    const response = await fetch(url, {
      headers: {
        accept: "application/json",
        "X-N8N-API-KEY": n8nConfig.apiKey
      }
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`n8n executions request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as { data?: N8nExecutionRecord[] } | N8nExecutionRecord[];
    const records = Array.isArray(payload) ? payload : Array.isArray(payload.data) ? payload.data : [];

    return records.map((execution) => ({
      id: String(pickString(execution, ["id"]) ?? pickNumber(execution, ["id"]) ?? ""),
      workflowId: String(
        pickString(execution, ["workflowId", "workflow_id"]) ??
          pickNumber(execution, ["workflowId", "workflow_id"]) ??
          ""
      ),
      status:
        pickString(execution, ["status", "finished"]) ??
        (execution.finished === true ? "success" : execution.finished === false ? "running" : "unknown"),
      mode: pickString(execution, ["mode"]) ?? "manual",
      startedAt:
        pickString(execution, ["startedAt", "started_at"]) ??
        pickString(execution, ["createdAt", "created_at"]) ??
        new Date().toISOString(),
      stoppedAt: pickString(execution, ["stoppedAt", "stopped_at"]) ?? undefined
    }));
  }

  async ensureFreshAccount(account: ConnectedAccountRecord) {
    if (account.provider === "halopsa") {
      const refreshed = await this.refreshHaloAccountIfNeeded(account);
      if (
        refreshed.accessTokenEncrypted !== account.accessTokenEncrypted ||
        refreshed.refreshTokenEncrypted !== account.refreshTokenEncrypted ||
        refreshed.expiresAt?.toISOString() !== account.expiresAt?.toISOString() ||
        refreshed.status !== account.status
      ) {
        refreshed.updatedAt = new Date();
        await this.store.upsert(refreshed);
      }
      return refreshed;
    }

    if (account.provider === "ninjaone") {
      const refreshed = await this.refreshNinjaOneAccountIfNeeded(account);
      if (
        refreshed.accessTokenEncrypted !== account.accessTokenEncrypted ||
        refreshed.refreshTokenEncrypted !== account.refreshTokenEncrypted ||
        refreshed.expiresAt?.toISOString() !== account.expiresAt?.toISOString() ||
        refreshed.status !== account.status
      ) {
        refreshed.updatedAt = new Date();
        await this.store.upsert(refreshed);
      }
      return refreshed;
    }

    const adapter = this.registry.get(account.provider);
    if (!adapter) {
      throw new Error(`Unknown provider ${account.provider}`);
    }
    const refreshed = await this.refreshService.refreshIfNeeded(account, adapter);
    if (
      refreshed.accessTokenEncrypted !== account.accessTokenEncrypted ||
      refreshed.refreshTokenEncrypted !== account.refreshTokenEncrypted ||
      refreshed.expiresAt?.toISOString() !== account.expiresAt?.toISOString() ||
      refreshed.status !== account.status
    ) {
      refreshed.updatedAt = new Date();
      await this.store.upsert(refreshed);
    }
    return refreshed;
  }

  issueMcpToken(tenantId: string, userId: string, roles: string[] = ["ADMIN"]) {
    return jwt.sign({ tenantId, userId, roles }, config.sessionSecret, { expiresIn: "1h" });
  }

  async executeTool(tenantId: string, userId: string, roles: string[], toolName: string, input: Record<string, unknown>) {
    const provider = [...this.registry.values()].find((candidate) =>
      candidate.getTools().some((tool) => tool.name === toolName)
    );

    if (!provider) {
      throw new Error(`Unknown tool ${toolName}`);
    }

    await this.assertProviderEnabledForTenant(provider.provider, tenantId);

    if (provider.provider === "halopsa") {
      return this.executeHaloTool(tenantId, userId, roles, toolName, input);
    }

    if (provider.provider === "ninjaone") {
      return this.executeNinjaOneTool(tenantId, userId, roles, toolName, input);
    }

    if (provider.provider === "actionstep") {
      const account = (await this.store.findByTenantUser(tenantId, userId)).find(
        (candidate) => candidate.provider === "actionstep" && candidate.status === "ACTIVE"
      );

      if (!account) {
        throw new Error(`No active ActionStep account found for ${tenantId}/${userId}`);
      }

      const fresh = await this.ensureFreshAccount(account);
      return executeActionStepTool(
        {
          encryption: this.encryption,
          ensureFresh: (acc) => this.ensureFreshAccount(acc)
        },
        fresh,
        toolName,
        input
      );
    }

    const tool = provider.getTools().find((candidate) => candidate.name === toolName);
    if (!tool) {
      throw new Error(`Tool ${toolName} not found`);
    }

    return tool.execute(
      {
        tenantId,
        userId,
        roles,
        requestId: crypto.randomUUID(),
        accountId: "connected-account-placeholder"
      },
      input
    );
  }

  private async executeNinjaOneTool(tenantId: string, userId: string, roles: string[], toolName: string, input: Record<string, unknown>) {
    const account = (await this.store.findByTenantUser(tenantId, userId)).find(
      (candidate) => candidate.provider === "ninjaone" && candidate.status === "ACTIVE"
    );

    if (!account) {
      throw new Error(`No active NinjaOne account found for ${tenantId}/${userId}`);
    }

    const runWithAccount = async (currentAccount: ConnectedAccountRecord) => {
      const accessToken = this.encryption.decrypt(currentAccount.accessTokenEncrypted);
      const baseUrl = this.getNinjaOneBaseUrlForAccount(currentAccount);

      switch (toolName) {
        case "search_rmm_devices":
          return this.searchNinjaOneDevices(tenantId, userId, baseUrl, accessToken, input);
        case "list_rmm_organizations":
          return this.listNinjaOneOrganizations(baseUrl, accessToken, input);
        case "get_rmm_organization":
          return this.getNinjaOneOrganization(baseUrl, accessToken, input);
        case "list_rmm_devices_for_site":
          return this.listNinjaOneDevicesForOrganization(baseUrl, accessToken, input);
        case "get_user_devices":
          return this.getUserDevicesViaHaloAssets(tenantId, userId, baseUrl, accessToken, input);
        case "get_rmm_device_overview":
          return this.getNinjaOneDeviceOverview(baseUrl, accessToken, input);
        case "get_rmm_device_alerts":
          return this.getNinjaOneDeviceAlerts(baseUrl, accessToken, input);
        case "get_rmm_device_activities":
          return this.getNinjaOneDeviceActivities(baseUrl, accessToken, input);
        default: {
          const tool = this.registry.get("ninjaone")?.getTools().find((candidate) => candidate.name === toolName);
          if (!tool) {
            throw new Error(`NinjaOne tool ${toolName} not found`);
          }

          return tool.execute(
            {
              tenantId,
              userId,
              roles,
              requestId: crypto.randomUUID(),
              accountId: currentAccount.id
            },
            input
          );
        }
      }
    };

    const freshAccount = await this.ensureFreshAccount(account);

    try {
      return await runWithAccount(freshAccount);
    } catch (error) {
      if (!isNinjaUnauthorizedError(error) || !freshAccount.refreshTokenEncrypted) {
        throw error;
      }

      const refreshed = await this.forceRefreshNinjaOneAccount(freshAccount);
      if (
        refreshed.accessTokenEncrypted !== freshAccount.accessTokenEncrypted ||
        refreshed.refreshTokenEncrypted !== freshAccount.refreshTokenEncrypted ||
        refreshed.expiresAt?.toISOString() !== freshAccount.expiresAt?.toISOString() ||
        refreshed.status !== freshAccount.status
      ) {
        refreshed.updatedAt = new Date();
        await this.store.upsert(refreshed);
      }

      if (refreshed.status !== "ACTIVE") {
        throw error;
      }

      return runWithAccount(refreshed);
    }
  }

  private async executeHaloTool(tenantId: string, userId: string, roles: string[], toolName: string, input: Record<string, unknown>) {
    const account = (await this.store.findByTenantUser(tenantId, userId)).find(
      (candidate) => candidate.provider === "halopsa" && candidate.status === "ACTIVE"
    );

    if (!account) {
      throw new Error(`No active HaloPSA account found for ${tenantId}/${userId}`);
    }

    const freshAccount = await this.ensureFreshAccount(account);
    const accessToken = this.encryption.decrypt(freshAccount.accessTokenEncrypted);
    const baseUrl = this.getHaloBaseUrlForAccount(freshAccount);

    switch (toolName) {
      case "list_open_tickets":
        return this.listOpenHaloTickets(baseUrl, accessToken, input);
      case "get_customer_overview":
        return this.getHaloCustomerOverview(baseUrl, accessToken, input);
      case "get_ticket":
        return this.getHaloTicket(baseUrl, accessToken, input);
      case "get_ticket_with_actions":
        return this.getHaloTicketWithActions(baseUrl, accessToken, input);
      case "find_customer":
        return this.findHaloCustomer(baseUrl, accessToken, input);
      case "list_ticket_actions":
        return this.listHaloTicketActions(baseUrl, accessToken, input);
      case "search_projects":
        return this.searchHaloProjects(baseUrl, accessToken, input);
      case "find_contact":
        return this.findHaloContact(baseUrl, accessToken, input);
      case "search_documents":
        return this.searchHaloDocuments(baseUrl, accessToken, input);
      case "list_devices_for_site":
        return this.listHaloDevicesForSite(baseUrl, accessToken, input);
      case "list_halo_categories":
        return this.listHaloCategories(baseUrl, accessToken, input);
      case "get_recent_invoices":
        return this.getRecentHaloInvoices(baseUrl, accessToken, input);
      case "create_draft_ticket":
        return this.createDraftHaloTicket(baseUrl, accessToken, input);
      case "add_internal_note":
        return this.addHaloInternalNote(baseUrl, accessToken, input);
      default: {
        const tool = this.registry.get("halopsa")?.getTools().find((candidate) => candidate.name === toolName);
        if (!tool) {
          throw new Error(`HaloPSA tool ${toolName} not found`);
        }

        return tool.execute(
          {
            tenantId,
            userId,
            roles,
            requestId: crypto.randomUUID(),
            accountId: freshAccount.id
          },
          input
        );
      }
    }
  }

  private async listOpenHaloTickets(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawQuery = typeof input.query === "string" ? input.query.trim() : undefined;
    const asksForProjects = /\b(project|projects|project ticket|project work|release|implementation)\b/i.test(rawQuery ?? "");
    const detectedNaturalDateFilters = extractNaturalHaloDateFilters(rawQuery);
    const query = extractMeaningfulQuery(rawQuery, [
      /\bopen\b/g,
      /\brecent\b/g,
      /\btickets?\b/g,
      /\bincidents?\b/g,
      /\brequests?\b/g,
      /\bfor\b/g,
      /\bhow many\b/g,
      /\bcount\b/g,
      /\bnumber of\b/g,
      /\btotal\b/g,
      /\b(ytd|year to date|start of (the )?year|since january|since jan(?:uary)? 1(st)?)\b/g,
      /\b(this month|current month|month to date|mtd)\b/g,
      /\b(last quarter|previous quarter|prior quarter|this quarter|current quarter)\b/g,
      /\bq[1-4](?:\s+\d{4})?\b/g,
      /\b(last month|previous month|prior month)\b/g,
      /\b(this week|current week|last week|previous week|prior week)\b/g,
      /\b(?:last|past|previous)\s+\d+\s+(?:days?|weeks?|months?)\b/g,
      /\b(last year|previous year|prior year)\b/g,
      /\b(?:in|during)\s+(?:january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)(?:\s+\d{4})?\b/g,
      /\b(?:january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\s+\d{4}\b/g
    ]);
    const queryWantsOpenItems = wantsOpenItems(input, rawQuery);
    const shouldApplyNaturalDateFilters =
      !queryWantsOpenItems || typeof input.closed_only === "boolean" || typeof input.closedOnly === "boolean";
    const naturalDateFilters = shouldApplyNaturalDateFilters ? detectedNaturalDateFilters : {};
    const effectiveFilters = sanitizeHaloTicketDateFilters({
      ...naturalDateFilters,
      ...input
    }, rawQuery);
    const hasNaturalDateFilter =
      typeof naturalDateFilters.startdate === "string" ||
      typeof naturalDateFilters.enddate === "string" ||
      typeof naturalDateFilters.datesearch === "string";
    const explicitClientId =
      pickNumber(effectiveFilters, ["clientId", "client_id"]) ??
      pickNumber(effectiveFilters, ["customerId", "customer_id"]) ??
      pickNumber(effectiveFilters, ["organisationId", "organisation_id"]);
    const structuredOpenOnly = typeof effectiveFilters.open_only === "boolean" ? effectiveFilters.open_only : undefined;
    const structuredClosedOnly = typeof effectiveFilters.closed_only === "boolean" ? effectiveFilters.closed_only : undefined;
    const explicitUserId = pickNumber(effectiveFilters, ["user_id", "userId"]);
    const explicitUsername = pickString(effectiveFilters, ["username"]);

    let clientId = explicitClientId;
    let resolvedCustomerName: string | undefined;
    let matchedClientIds: number[] = explicitClientId ? [explicitClientId] : [];
    let matchedCustomerNames: string[] = [];
    let resolvedUserName: string | undefined;
    let matchedUserIds: number[] = explicitUserId ? [explicitUserId] : [];
    let matchedUserNames: string[] = explicitUsername ? [explicitUsername] : [];

    if (!clientId && query) {
      // Try the full query first, then try each individual word so that
      // "sftp cmutual" still resolves "CMutual" as a customer even though
      // "sftp" is a topic word, not a customer name.
      const searchTerms = [query, ...query.split(/\s+/).filter((word) => word.length >= 3)];
      const seen = new Set<number>();

      for (const term of searchTerms) {
        if (matchedClientIds.length > 0) {
          break;
        }

        const customerLookup = await this.lookupHaloCustomers(baseUrl, accessToken, term, 25);
        const matchingCustomers = customerLookup.filter((customer) => {
          const id = pickNumber(customer, ["id", "client_id"]);
          if (id && seen.has(id)) {
            return false;
          }
          if (id) {
            seen.add(id);
          }

          return [
            pickString(customer, ["name", "client_name"]),
            pickString(customer, ["reference", "client_reference", "ref"]),
            pickString(customer, ["organisation_name", "customer_name"])
          ].some((candidate) => textMatches(candidate, term));
        });

        if (matchingCustomers.length > 0) {
          matchedClientIds = matchingCustomers
            .map((customer) => pickNumber(customer, ["id", "client_id"]))
            .filter((value): value is number => typeof value === "number");
          matchedCustomerNames = matchingCustomers
            .map((customer) => pickString(customer, ["name", "client_name", "organisation_name", "customer_name"]))
            .filter((value): value is string => typeof value === "string");

          clientId = matchedClientIds[0];
          resolvedCustomerName = matchedCustomerNames[0];
        }
      }
    }

    const isCountingQuery = /\b(how many|count|number of|total|tally)\b/i.test(rawQuery ?? "");
    const isTemporalQuery = hasNaturalDateFilter || /\b(last|previous|prior|since|during|between)\b/i.test(rawQuery ?? "");
    const needsComprehensiveResults = isCountingQuery || isTemporalQuery;
    const limit = needsComprehensiveResults ? 250 : typeof rawQuery === "string" && /\b(all)\b/i.test(rawQuery) ? 250 : 100;
    const includeClosed =
      structuredClosedOnly === true
        ? true
        : structuredOpenOnly === true
          ? false
          : needsComprehensiveResults
            ? true
            : !queryWantsOpenItems;

    // Strip customer names from the query so the API search only contains the topic.
    // e.g. "sftp cmutual" → "sftp" when CMutual was resolved as a customer.
    const topicQuery = matchedCustomerNames.length > 0
      ? matchedCustomerNames
          .reduce(
            (q, name) => q.replace(new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), " "),
            query
          )
          .replace(/\s+/g, " ")
          .trim()
      : query;

    if ((matchedUserIds.length === 0 && matchedUserNames.length === 0) && topicQuery) {
      try {
        const users = await this.lookupHaloUsers(baseUrl, accessToken, {
          query: topicQuery,
          client_id: clientId,
          includeactive: true,
          includeinactive: false,
          count: 25
        });
        const matchingUsers = users.filter((user) =>
          [
            pickString(user, ["name", "display_name", "fullname", "full_name"]),
            pickString(user, ["email", "emailaddress", "email_address"]),
            pickString(user, ["username", "user_name"]),
            pickString(user, ["client_name", "organisation_name", "site_name"])
          ].some((candidate) => textMatches(candidate, topicQuery))
        );

        const selectedUsers = matchingUsers.length > 0 ? matchingUsers : [];
        matchedUserIds = selectedUsers
          .map((user) => pickNumber(user, ["id", "user_id", "contact_id"]))
          .filter((value): value is number => typeof value === "number");
        matchedUserNames = selectedUsers
          .flatMap((user) =>
            [
              pickString(user, ["name", "display_name", "fullname", "full_name"]),
              pickString(user, ["email", "emailaddress", "email_address"]),
              pickString(user, ["username", "user_name"])
            ].filter(Boolean)
          )
          .filter((value): value is string => typeof value === "string");
        resolvedUserName = matchedUserNames[0];
      } catch {
        // Optional user enrichment only.
      }
    }

    const refinedTopicQuery = matchedUserNames.length > 0
      ? matchedUserNames
          .reduce(
            (q, name) => q.replace(new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), " "),
            topicQuery
          )
          .replace(/\s+/g, " ")
          .trim()
      : topicQuery;

    // Resolve topic terms to Halo category IDs (grouped by tier) for server-side filtering.
    const resolvedCategories = refinedTopicQuery
      ? await this.resolveHaloCategoryFilters(baseUrl, accessToken, refinedTopicQuery)
      : {};
    const hasResolvedCategories =
      Boolean(resolvedCategories.category_1?.length) ||
      Boolean(resolvedCategories.category_2?.length) ||
      Boolean(resolvedCategories.category_3?.length) ||
      Boolean(resolvedCategories.category_4?.length);

    // Build filters for the API — strip any AI-supplied count/page_size/limit
    // so our comprehensive limit is respected.
    const apiFilters = { ...effectiveFilters };
    if (matchedUserIds[0] !== undefined && apiFilters.user_id === undefined && apiFilters.userId === undefined) {
      apiFilters.user_id = matchedUserIds[0];
    }
    if (matchedUserNames[0] && apiFilters.username === undefined) {
      apiFilters.username = matchedUserNames[0];
    }
    if (needsComprehensiveResults) {
      delete apiFilters.count;
      delete apiFilters.page_size;
      delete apiFilters.limit;
      delete apiFilters.top;
    }

    // Build a category-enriched filter set (applies each tier to its correct param)
    const categoryFilters = { ...apiFilters };
    if (resolvedCategories.category_1?.length && !categoryFilters.category_1) {
      categoryFilters.category_1 = resolvedCategories.category_1;
    }
    if (resolvedCategories.category_2?.length && !categoryFilters.category_2) {
      categoryFilters.category_2 = resolvedCategories.category_2;
    }
    if (resolvedCategories.category_3?.length && !categoryFilters.category_3) {
      categoryFilters.category_3 = resolvedCategories.category_3;
    }
    if (resolvedCategories.category_4?.length && !categoryFilters.category_4) {
      categoryFilters.category_4 = resolvedCategories.category_4;
    }

    // Fetch strategy: separate calls for text search vs category filter,
    // then merge and deduplicate. This OR approach avoids over-filtering.
    const fetchedTicketGroups = await Promise.all([
      // Primary fetch: by client + topic text search + date filters
      ...(matchedClientIds.length > 0
        ? matchedClientIds.map((matchedId) =>
            this.fetchHaloTickets(baseUrl, accessToken, {
              clientId: matchedId,
              query: refinedTopicQuery || undefined,
              includeClosed,
              limit,
              filters: apiFilters
            })
          )
        : []),
      // Category fetch: by client + resolved category tier filters (no text search)
      // catches tickets where the topic is in the category path, not the summarys
      ...(hasResolvedCategories && matchedClientIds.length > 0
        ? matchedClientIds.map((matchedId) =>
            this.fetchHaloTickets(baseUrl, accessToken, {
              clientId: matchedId,
              includeClosed,
              limit,
              filters: categoryFilters
            })
          )
        : []),
      // No customer matched — fall back to text search + category combined
      ...(matchedClientIds.length === 0
        ? [
              this.fetchHaloTickets(baseUrl, accessToken, {
                clientId,
                query: refinedTopicQuery || undefined,
                includeClosed,
                limit,
                filters: hasResolvedCategories ? categoryFilters : apiFilters
            })
          ]
        : [])
    ]);
    const tickets = dedupeTicketsById(fetchedTicketGroups.flat());

    const openTickets = tickets
      .filter((ticket) => {
        if (structuredClosedOnly === true) {
          return !isTicketOpen(ticket);
        }
        if (structuredOpenOnly === true) {
          return isTicketOpen(ticket);
        }
        if (needsComprehensiveResults) {
          return true;
        }
        if (queryWantsOpenItems) {
          return isTicketOpen(ticket);
        }
        return true;
      })
      .filter((ticket) => {
        if (!refinedTopicQuery) {
          return true;
        }

        return ticketMatchesHaloQuery(ticket, refinedTopicQuery);
      })
      .filter((ticket) => {
        if (matchedClientIds.length === 0) {
          return true;
        }

        const ticketClientId = pickNumber(ticket, ["client_id", "clientid", "organisation_id", "customer_id"]);
        if (ticketClientId && matchedClientIds.includes(ticketClientId)) {
          return true;
        }

        const ticketCustomerName = pickString(ticket, [
          "client_name",
          "customer_name",
          "organisation_name",
          "site_name",
          "location_name"
        ]);
        return Boolean(
          ticketCustomerName &&
            (matchedCustomerNames.some((name) => textMatches(ticketCustomerName, name) || textMatches(name, ticketCustomerName)) ||
              (query ? textMatches(ticketCustomerName, query) : false))
        );
      })
      .filter((ticket) => {
        if (asksForProjects || input.includeProjectTickets === true) {
          return true;
        }

        return !isProjectStyleTicket(ticket);
      })
      .slice(0, limit);

    const normalizedStatuses = await Promise.all(
      openTickets.map(async (ticket) => ({
        ticket,
        status: await this.resolveHaloTicketStatusName(baseUrl, accessToken, ticket)
      }))
    );

    const statusLabel = structuredClosedOnly
      ? "closed "
      : structuredOpenOnly
        ? "open "
        : needsComprehensiveResults
          ? ""
          : wantsOpenItems(effectiveFilters, rawQuery)
            ? "open "
            : "";
    const dateLabel = hasNaturalDateFilter
      ? ` (date range: ${naturalDateFilters.startdate} to ${naturalDateFilters.enddate})`
      : "";
    const categoryLabel = hasResolvedCategories
      ? ` matching category filter`
      : "";

    return {
      summary:
        normalizedStatuses.length > 0
          ? `Found ${normalizedStatuses.length} ${statusLabel}HaloPSA tickets${resolvedCustomerName ? ` for ${resolvedCustomerName}` : ""}${resolvedUserName ? `${resolvedCustomerName ? " and " : " for "}${resolvedUserName}` : ""}${dateLabel}${categoryLabel}. Results are condensed to ticket id, summary, status, customer, priority, category path, and latest update.`
          : `No ${statusLabel}HaloPSA tickets found${resolvedCustomerName ? ` for ${resolvedCustomerName}` : ""}${resolvedUserName ? `${resolvedCustomerName ? " and " : " for "}${resolvedUserName}` : ""}${dateLabel}${categoryLabel}.`,
      data: normalizedStatuses.map(({ ticket, status }) => buildNormalizedHaloTicket(ticket, status)),
      source: "halopsa"
    };
  }

  private async getHaloCustomerOverview(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query.trim() : "";
    if (!query) {
      throw new Error("get_customer_overview requires a customer query");
    }

    const customers = await this.lookupHaloCustomers(baseUrl, accessToken, query, 10);
    const matchedCustomer =
      customers.find((customer) =>
        [
          pickString(customer, ["name", "client_name"]),
          pickString(customer, ["reference", "client_reference", "ref"]),
          pickString(customer, ["organisation_name", "customer_name"])
        ].some((candidate) => textMatches(candidate, query))
      ) ?? customers[0];

    if (!matchedCustomer) {
      return {
        summary: `No HaloPSA customer matched ${query}.`,
        data: [],
        source: "halopsa"
      };
    }

    const customerId = pickNumber(matchedCustomer, ["id", "client_id"]);
    const customerName =
      pickString(matchedCustomer, ["name", "client_name", "organisation_name", "customer_name"]) ?? query;
    const tickets = await this.listOpenHaloTickets(baseUrl, accessToken, {
      client_id: customerId,
      query: customerName
    });

    return {
      summary: `Loaded HaloPSA customer overview for ${customerName}. Result includes core customer fields and recent open ticket activity.`,
      data: [
        {
          customer: {
            id: customerId,
            name: customerName,
            reference: pickString(matchedCustomer, ["reference", "client_reference", "ref"]),
            email: pickString(matchedCustomer, ["email", "main_email"]),
            phone: pickString(matchedCustomer, ["phone", "main_phone"]),
            raw: matchedCustomer
          },
          openTicketCount: tickets.data.length,
          recentTickets: tickets.data
        }
      ],
      source: "halopsa"
    };
  }

  private async lookupHaloCustomers(baseUrl: string, accessToken: string, query: string, count = 25) {
    const url = new URL(`${baseUrl}/api/client`);
    url.searchParams.set("search", query);
    url.searchParams.set("count", String(count));

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA customer request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as HaloClientRecord[] | { clients?: HaloClientRecord[] };
    return Array.isArray(payload) ? payload : (payload.clients ?? []);
  }

  private async lookupHaloUsers(baseUrl: string, accessToken: string, options: Record<string, unknown>) {
    const url = new URL(`${baseUrl}/api/users`);

    const searchTerm = pickString(options, ["search", "query"]);
    const requestedCount = pickPositiveInt(options, ["count"]);
    const requestedPageSize = pickPositiveInt(options, ["page_size"]);
    const requestedPageNo = pickPositiveInt(options, ["page_no"]);
    const effectiveCount = Math.min(requestedCount ?? 25, 250);
    const effectivePageSize = requestedPageSize && requestedPageSize >= 5 ? requestedPageSize : undefined;

    appendQueryValue(url, "paginate", typeof options.paginate === "boolean" ? options.paginate : undefined);
    appendQueryValue(url, "page_size", effectivePageSize);
    appendQueryValue(url, "page_no", requestedPageNo);
    appendQueryValue(url, "order", pickString(options, ["order"]));
    appendQueryValue(url, "orderdesc", typeof options.orderdesc === "boolean" ? options.orderdesc : undefined);
    appendQueryValue(url, "search", searchTerm);
    appendQueryValue(
      url,
      "search_phonenumbers",
      typeof options.search_phonenumbers === "boolean" ? options.search_phonenumbers : undefined
    );
    appendQueryValue(url, "toplevel_id", pickPositiveInt(options, ["toplevel_id"]));
    appendQueryValue(url, "client_id", pickPositiveInt(options, ["client_id", "clientId"]));
    appendQueryValue(url, "site_id", pickPositiveInt(options, ["site_id", "siteId"]));
    appendQueryValue(url, "organisation_id", pickPositiveInt(options, ["organisation_id", "organisationId"]));
    appendQueryValue(url, "department_id", pickPositiveInt(options, ["department_id", "departmentId"]));
    appendQueryValue(url, "asset_id", pickPositiveInt(options, ["asset_id", "assetId"]));
    appendQueryValue(
      url,
      "includeactive",
      typeof options.includeactive === "boolean"
        ? options.includeactive
        : typeof options.includeActive === "boolean"
          ? options.includeActive
          : undefined
    );
    appendQueryValue(
      url,
      "includeinactive",
      typeof options.includeinactive === "boolean"
        ? options.includeinactive
        : typeof options.includeInactive === "boolean"
          ? options.includeInactive
          : undefined
    );
    appendQueryValue(url, "approversonly", typeof options.approversonly === "boolean" ? options.approversonly : undefined);
    appendQueryValue(url, "excludeagents", typeof options.excludeagents === "boolean" ? options.excludeagents : undefined);
    appendQueryValue(url, "count", effectiveCount);

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA users request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    let users = normalizeCollectionPayload(payload, ["users", "contacts", "results", "data"]);

    // Halo's /api/users search is exact-token biased and often misses partial/whole-name queries.
    // Retry with split tokens if nothing came back, then merge unique users.
    if (users.length === 0 && searchTerm) {
      const tokens = searchTerm.split(/\s+/).filter((token) => token.length >= 2);
      const seen = new Set<number>();
      const collected: HaloGenericRecord[] = [];

      for (const token of tokens) {
        if (collected.length >= effectiveCount) break;
        const retryUrl = new URL(`${baseUrl}/api/users`);
        retryUrl.searchParams.set("search", token);
        retryUrl.searchParams.set("count", String(effectiveCount));
        const retryResponse = await haloFetch(retryUrl, { headers: buildHaloHeaders(accessToken) });
        if (!retryResponse.ok) continue;
        const retryPayload = (await retryResponse.json()) as unknown;
        const tokenUsers = normalizeCollectionPayload(retryPayload, ["users", "contacts", "results", "data"]);
        for (const user of tokenUsers) {
          const id = pickNumber(user, ["id", "user_id", "contact_id"]);
          const dedupeKey = id ?? Number.NaN;
          if (id !== undefined && seen.has(dedupeKey)) continue;
          if (id !== undefined) seen.add(dedupeKey);
          collected.push(user);
        }
      }

      if (collected.length > 0) {
        users = collected;
      }
    }

    return users;
  }

  private async fetchHaloTickets(
    baseUrl: string,
    accessToken: string,
    options: {
      clientId?: number;
      query?: string;
      includeClosed: boolean;
      limit: number;
      filters?: Record<string, unknown>;
    }
  ) {
    const requestedPageSize = Math.min(Math.max(options.limit, 25), 100);
    let pageSize = requestedPageSize;
    const maxResults = options.limit;
    const collected: HaloTicketRecord[] = [];

    for (let page = 1; page <= 20 && collected.length < maxResults; page += 1) {
      const url = new URL(`${baseUrl}/api/tickets`);
      const filters = options.filters ?? {};
      appendQueryValue(url, "count", pageSize);
      appendQueryValue(url, "includeclosed", options.includeClosed);
      appendQueryValue(url, "paginate", typeof filters.paginate === "boolean" ? filters.paginate : true);
      appendQueryValue(url, "page_no", page);
      appendQueryValue(url, "page_size", pageSize);
      for (const key of [
        "order",
        "orderdesc",
        "ticketidonly",
        "view_id",
        "columns_id",
        "includecolumns",
        "includeslaactiondate",
        "includeslatimer",
        "includetimetaken",
        "includesupplier",
        "includerelease1",
        "includerelease2",
        "includerelease3",
        "includechildids",
        "includenextactivitydate",
        "list_id",
        "agent_id",
        "status_id",
        "requesttype_id",
        "supplier_id",
        "client_id",
        "site",
        "username",
        "user_id",
        "release_id",
        "asset_id",
        "itil_requesttype_id",
        "open_only",
        "closed_only",
        "unlinked_only",
        "contract_id",
        "withattachments",
        "team",
        "agent",
        "status",
        "requesttype",
        "itil_requesttype",
        "category_1",
        "category_2",
        "category_3",
        "category_4",
        "sla",
        "priority",
        "products",
        "flagged",
        "excludethese",
        "search",
        "searchactions",
        "datesearch",
        "startdate",
        "enddate",
        "search_user_name",
        "search_summary",
        "search_details",
        "search_reportedby",
        "search_version",
        "search_release1",
        "search_release2",
        "search_release3",
        "search_releasenote",
        "search_invenotry_number",
        "search_oppcontactname",
        "search_oppcompanyname"
      ]) {
        appendQueryValue(url, key, filters[key]);
      }

      if (options.clientId) {
        url.searchParams.set("client_id", String(options.clientId));
      }
      if (options.query && !url.searchParams.has("search")) {
        url.searchParams.set("search", options.query);
      }

      const response = await haloFetch(url, {
        headers: buildHaloHeaders(accessToken)
      });

      if (!response.ok) {
        const body = (await response.text()).trim();
        // Halo intermittently 500s on broader pages; halve the page size and retry once before bubbling up.
        if (response.status >= 500 && pageSize > 25) {
          pageSize = Math.max(25, Math.floor(pageSize / 2));
          page -= 1;
          continue;
        }
        const friendly = body.length > 0 ? body.slice(0, 500) : "<empty body>";
        throw new Error(
          `HaloPSA tickets request failed (${response.status}) on ${url.pathname}?${url.searchParams.toString()}: ${friendly}`
        );
      }

      const payload = (await response.json()) as unknown;
      const pageTickets = extractHaloTickets(payload);
      collected.push(...pageTickets);

      if (pageTickets.length < pageSize) {
        break;
      }
    }

    return collected.slice(0, maxResults);
  }

  private async fetchHaloStatuses(baseUrl: string, accessToken: string) {
    const cacheKey = buildHaloCacheKey(baseUrl, accessToken);
    const cached = await this.haloStatusCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    for (const path of ["/api/status", "/api/ticketstatus", "/api/statuses"]) {
      const url = new URL(`${baseUrl}${path}`);
      url.searchParams.set("count", "200");

      const response = await haloFetch(url, {
        headers: buildHaloHeaders(accessToken)
      });

      if (!response.ok) {
        continue;
      }

      const payload = (await response.json()) as unknown;
      const records = normalizeCollectionPayload(payload, ["statuses", "ticketstatuses", "results", "data"]);
      if (records.length > 0) {
        await this.haloStatusCache.set(cacheKey, records);
        return records;
      }
    }

    return [];
  }

  private async resolveHaloTicketStatusName(baseUrl: string, accessToken: string, ticket: HaloTicketRecord) {
    const directStatus = getHaloTicketStatus(ticket);
    if (directStatus) {
      return directStatus;
    }

    const statusId =
      pickNumber(ticket, ["status_id", "ticketstatus_id", "ticketStatusId"]) ??
      pickNestedNumber(ticket, ["status", "ticketstatus", "workflow_status", "ticket_status"]);
    if (!statusId) {
      return undefined;
    }

    const statuses = await this.fetchHaloStatuses(baseUrl, accessToken);
    const match = statuses.find((status) => {
      const candidateId =
        pickNumber(status, ["id", "status_id", "ticketstatus_id"]) ??
        pickNestedNumber(status, ["status", "ticketstatus"]);
      return candidateId === statusId;
    });

    return (
      (match ? getHaloTicketStatus(match) : undefined) ??
      pickString(match ?? {}, ["name", "label", "displayName", "text"])
    );
  }

  private async fetchHaloCategories(baseUrl: string, accessToken: string): Promise<HaloCategoryRecord[]> {
    const cacheKey = buildHaloCacheKey(baseUrl, accessToken);
    const cached = await this.haloCategoryCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    for (const path of ["/api/Category", "/api/category", "/api/categories"]) {
      const url = new URL(`${baseUrl}${path}`);
      url.searchParams.set("count", "500");

      const response = await haloFetch(url, {
        headers: buildHaloHeaders(accessToken)
      });

      if (!response.ok) {
        continue;
      }

      const payload = (await response.json()) as unknown;
      const records = normalizeCollectionPayload(payload, ["categories", "results", "data"]);
      if (records.length > 0) {
        await this.haloCategoryCache.set(cacheKey, records);
        return records;
      }
    }

    return [];
  }

  private async listHaloCategories(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query.trim().toLowerCase() : "";
    const categories = await this.fetchHaloCategories(baseUrl, accessToken);

    if (categories.length === 0) {
      return {
        summary: "No HaloPSA categories found. The category API may not be accessible.",
        data: [],
        source: "halopsa"
      };
    }

    const tierMap: Record<number, { tier: number; label: string; filterParam: string }> = {
      0: { tier: 1, label: "Category 1 (Top-level)", filterParam: "category_1" },
      1: { tier: 2, label: "Category 2 (Sub-category)", filterParam: "category_2" },
      2: { tier: 3, label: "Category 3", filterParam: "category_3" },
      3: { tier: 4, label: "Category 4", filterParam: "category_4" }
    };

    // Build a lookup map of id → name for resolving parent references
    const idToName = new Map<number, string>();
    for (const cat of categories) {
      const id = pickNumber(cat, ["id", "category_id"]);
      const name = pickString(cat, ["name", "value", "label", "text", "category_name"]);
      if (typeof id === "number" && name) {
        idToName.set(id, name);
      }
    }

    // Normalize and optionally filter categories
    const normalized = categories
      .map((cat) => {
        const id = pickNumber(cat, ["id", "category_id"]);
        const name = pickString(cat, ["name", "value", "label", "text", "category_name"]);
        const typeId = pickNumber(cat, ["type_id", "typeid", "type"]);
        const parentId = pickNumber(cat, ["category_group_id", "parent_id", "parentid"]);
        const tierInfo = typeof typeId === "number" && tierMap[typeId]
          ? tierMap[typeId]
          : tierMap[0];

        return {
          id,
          name: name ?? "(unnamed)",
          tier: tierInfo.tier,
          tierLabel: tierInfo.label,
          filterParam: tierInfo.filterParam,
          parentId: parentId ?? null,
          parentName: typeof parentId === "number" ? (idToName.get(parentId) ?? null) : null
        };
      })
      .filter((entry): entry is typeof entry & { id: number } => typeof entry.id === "number")
      .filter((entry) => {
        if (!query) {
          return true;
        }
        return entry.name.toLowerCase().includes(query);
      });

    // Group by tier, sort alphabetically within each tier
    const grouped: Record<number, typeof normalized> = {};
    for (const entry of normalized) {
      if (!grouped[entry.tier]) {
        grouped[entry.tier] = [];
      }
      grouped[entry.tier].push(entry);
    }
    for (const tier of Object.values(grouped)) {
      tier.sort((a, b) => a.name.localeCompare(b.name));
    }

    // Flatten back ordered by tier then name
    const results = [1, 2, 3, 4].flatMap((tier) => grouped[tier] ?? []);

    const tierCounts = [1, 2, 3, 4]
      .map((tier) => `tier ${tier}: ${(grouped[tier] ?? []).length}`)
      .filter((s) => !s.endsWith(": 0"))
      .join(", ");

    return {
      summary: query
        ? `Found ${results.length} HaloPSA categories matching "${query}" (${tierCounts}). Use the id values in the corresponding category_1/2/3/4 filter arrays when calling list_open_tickets.`
        : `Found ${results.length} HaloPSA categories across all tiers (${tierCounts}). Use the id values in the corresponding category_1/2/3/4 filter arrays when calling list_open_tickets.`,
      data: results.map((entry) => ({
        id: entry.id,
        name: entry.name,
        tier: entry.tier,
        tierLabel: entry.tierLabel,
        filterParam: entry.filterParam,
        parentId: entry.parentId,
        parentName: entry.parentName
      })),
      source: "halopsa"
    };
  }

  private async resolveHaloCategoryFilters(
    baseUrl: string,
    accessToken: string,
    query: string
  ): Promise<{ category_1?: number[]; category_2?: number[]; category_3?: number[]; category_4?: number[] }> {
    if (!query.trim()) {
      return {};
    }

    const categories = await this.fetchHaloCategories(baseUrl, accessToken);
    if (categories.length === 0) {
      return {};
    }

    const normalizedQuery = query.toLowerCase().trim();
    const queryWords = normalizedQuery.split(/\s+/).filter((word) => word.length >= 3);
    if (queryWords.length === 0) {
      return {};
    }

    // type_id on each category record maps to the tier:
    // 0 → category_1, 1 → category_2, 2 → category_3, 3 → category_4
    const tierMap: Record<number, string> = { 0: "category_1", 1: "category_2", 2: "category_3", 3: "category_4" };
    const buckets: Record<string, number[]> = {};

    for (const category of categories) {
      const categoryName = pickString(category, ["name", "value", "label", "text", "category_name"])?.toLowerCase();
      if (!categoryName) {
        continue;
      }

      const categoryId = pickNumber(category, ["id", "category_id"]);
      if (typeof categoryId !== "number") {
        continue;
      }

      // Determine which tier this category belongs to
      const typeId = pickNumber(category, ["type_id", "typeid", "type"]);
      const tierKey = typeof typeId === "number" && tierMap[typeId]
        ? tierMap[typeId]
        : "category_1"; // default to tier 1 if type_id is missing

      // Require a strong match: exact name match or whole-word boundary match
      const isExactMatch = categoryName === normalizedQuery;
      const hasWordBoundaryMatch = queryWords.some((word) => {
        const pattern = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
        return pattern.test(categoryName);
      });

      if (isExactMatch || hasWordBoundaryMatch) {
        if (!buckets[tierKey]) {
          buckets[tierKey] = [];
        }
        buckets[tierKey].push(categoryId);
      }
    }

    // If any single tier has too many matches the query is too broad for that tier — drop it
    for (const key of Object.keys(buckets)) {
      if (buckets[key].length > 10) {
        delete buckets[key];
      }
    }

    if (Object.keys(buckets).length === 0) {
      return {};
    }

    return buckets as { category_1?: number[]; category_2?: number[]; category_3?: number[]; category_4?: number[] };
  }

  private async resolveHaloEntityHints(tenantId: string, userId: string, query: string): Promise<ResolvedEntityHints> {
    const hints: ResolvedEntityHints = {
      userHints: [],
      organizationHints: [],
      emailHints: [],
      deviceHints: []
    };

    const haloAccount = (await this.store.findByTenantUser(tenantId, userId)).find(
      (candidate) => candidate.provider === "halopsa" && candidate.status === "ACTIVE"
    );
    if (!haloAccount) {
      return hints;
    }

    const freshHalo = await this.ensureFreshAccount(haloAccount);
    const haloToken = this.encryption.decrypt(freshHalo.accessTokenEncrypted);
    const haloBaseUrl = this.getHaloBaseUrlForAccount(freshHalo);
    let matchedCustomerId: number | undefined;

    try {
      const customers = await this.lookupHaloCustomers(haloBaseUrl, haloToken, query, 10);
      const matchedCustomer =
        customers.find((customer) =>
          [
            pickString(customer, ["name", "client_name", "organisation_name", "customer_name"]),
            pickString(customer, ["reference", "client_reference", "ref"])
          ].some((candidate) => textMatches(candidate, query))
        ) ?? customers[0];

      if (matchedCustomer) {
        matchedCustomerId = pickNumber(matchedCustomer, ["id", "client_id"]);
        const customerName = pickString(matchedCustomer, ["name", "client_name", "organisation_name", "customer_name"]);
        if (customerName) {
          hints.organizationHints.push(customerName);
        }
      }
    } catch {
      // Optional enrichment only.
    }

    try {
      const contactResult = await this.findHaloContact(haloBaseUrl, haloToken, { query });
      for (const row of contactResult.data as Record<string, unknown>[]) {
        const name = pickString(row, ["name"]);
        const email = pickString(row, ["email"]);
        const customer = pickString(row, ["customer"]);
        if (name) {
          hints.userHints.push(name);
        }
        if (email) {
          hints.emailHints.push(email);
        }
        if (customer) {
          hints.organizationHints.push(customer);
        }
      }
    } catch {
      // Optional enrichment only.
    }

    try {
      const assetLookups = [
        { query, clientId: matchedCustomerId },
        ...hints.emailHints.map((email) => ({ username: email, clientId: matchedCustomerId })),
        ...hints.userHints.map((name) => ({ username: name, clientId: matchedCustomerId })),
        ...hints.organizationHints.map((name) => ({ query: name, clientId: matchedCustomerId }))
      ];

      for (const assetLookup of assetLookups.slice(0, 6)) {
        const assets = await this.lookupHaloAssets(haloBaseUrl, haloToken, {
          ...assetLookup,
          count: 15,
          includeActive: true
        });
        for (const asset of assets) {
          const assetName = pickString(asset, ["name", "inventory_number", "hostname"]);
          const serialNumber = pickString(asset, ["serial_number", "serialno"]);
          const siteName = pickString(asset, ["site_name", "location_name"]);
          if (assetName) {
            hints.deviceHints.push(assetName);
          }
          if (serialNumber) {
            hints.deviceHints.push(serialNumber);
          }
          if (siteName) {
            hints.organizationHints.push(siteName);
          }
        }
      }
    } catch {
      // Optional enrichment only.
    }

    hints.userHints = [...new Set(hints.userHints.map((value) => value.trim()).filter(Boolean))];
    hints.organizationHints = [...new Set(hints.organizationHints.map((value) => value.trim()).filter(Boolean))];
    hints.emailHints = [...new Set(hints.emailHints.map((value) => value.trim()).filter(Boolean))];
    hints.deviceHints = [...new Set(hints.deviceHints.map((value) => value.trim()).filter(Boolean))];
    return hints;
  }

  private async lookupHaloAssets(
    baseUrl: string,
    accessToken: string,
    options: {
      query?: string;
      clientId?: number;
      siteId?: number;
      username?: string;
      includeActive?: boolean;
      includeInactive?: boolean;
      count?: number;
    }
  ) {
    const url = new URL(`${baseUrl}/api/assets`);
    url.searchParams.set("count", String(options.count ?? 25));
    appendQueryValue(url, "search", options.query);
    appendQueryValue(url, "client_id", options.clientId);
    appendQueryValue(url, "site_id", options.siteId);
    appendQueryValue(url, "username", options.username);
    appendQueryValue(url, "includeactive", options.includeActive ?? true);
    appendQueryValue(url, "includeinactive", options.includeInactive ?? false);

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      return [] as HaloGenericRecord[];
    }

    const payload = (await response.json()) as unknown;
    return normalizeCollectionPayload(payload, ["assets", "devices", "results", "data"]).slice(0, options.count ?? 25);
  }

  private async listHaloTicketActions(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId = input.id ?? input.ticketId ?? input.ticket_id ?? input.query;
    const ticketId = typeof rawId === "number" || typeof rawId === "string" ? String(rawId).trim() : undefined;
    if (!ticketId) {
      throw new Error("list_ticket_actions requires a ticket id");
    }

    const includeRaw = isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]);
    const requestedCount = pickNumber(input, ["count", "limit", "max"]);
    const count = Math.max(1, Math.min(50, requestedCount ?? 10));
    const noteCharLimit = Math.max(200, Math.min(4000, pickNumber(input, ["note_char_limit", "noteMaxChars"]) ?? 1200));

    const url = new URL(`${baseUrl}/api/actions`);
    url.searchParams.set("count", String(count));
    url.searchParams.set("ticket_id", ticketId);
    url.searchParams.set("includehtmlnote", "false");
    url.searchParams.set("includehtmlemail", "false");
    url.searchParams.set("includeattachments", "false");

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA actions request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    const actions = normalizeCollectionPayload(payload, ["actions"]).slice(0, count);

    return {
      summary:
        actions.length > 0
          ? `Loaded ${actions.length} HaloPSA actions for ticket ${ticketId}. Results include agent, note text, action type, and created time.${includeRaw ? "" : " Pass include_raw: true to also return raw Halo action payloads."}`
          : `No HaloPSA actions found for ticket ${ticketId}.`,
      data: actions.map((action) => {
        const note =
          truncateText(stripHtmlToText(action.note_html ?? action.note), noteCharLimit) ??
          truncateText(pickString(action, ["note", "outcome", "details"]), noteCharLimit);
        return {
          id: pickNumber(action, ["id", "action_id"]),
          ticketId: pickNumber(action, ["ticket_id", "ticketid"]),
          agent: pickString(action, ["agent_name", "agent", "who"]),
          note,
          actionType: pickString(action, ["action_type", "type", "category", "outcome"]),
          createdAt: pickString(action, ["datecreated", "created_at", "datetime"]),
          ...(includeRaw ? { raw: action } : {})
        };
      }),
      source: "halopsa"
    };
  }

  private async getHaloTicketWithActions(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId = input.id ?? input.ticketId ?? input.ticket_id ?? input.query;
    const upfrontTicketId =
      typeof rawId === "number"
        ? rawId
        : typeof rawId === "string" && !Number.isNaN(Number(rawId.trim()))
          ? Number(rawId.trim())
          : undefined;

    const [ticket, actions] = await Promise.all([
      this.getHaloTicket(baseUrl, accessToken, input),
      upfrontTicketId !== undefined
        ? this.listHaloTicketActions(baseUrl, accessToken, { ...input, ticket_id: upfrontTicketId })
        : Promise.resolve({ summary: "No ticket actions loaded.", data: [] as unknown[], source: "halopsa" })
    ]);

    const ticketRecord = ticket.data[0] as Record<string, unknown> | undefined;
    const resolvedTicketId = pickNumber(ticketRecord ?? {}, ["id"]) ?? upfrontTicketId;

    const finalActions =
      upfrontTicketId === undefined && resolvedTicketId !== undefined
        ? await this.listHaloTicketActions(baseUrl, accessToken, { ...input, ticket_id: resolvedTicketId })
        : actions;

    return {
      summary: `Loaded HaloPSA ticket with recent actions. Result includes the main ticket fields and recent internal updates or actions.`,
      data: [
        {
          ticket: ticket.data[0] ?? null,
          recentActions: finalActions.data
        }
      ],
      source: "halopsa"
    };
  }

  private async searchHaloProjects(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawQuery = typeof input.query === "string" ? input.query.trim() : "";
    const query = extractMeaningfulQuery(rawQuery, [
      /\bopen\b/g,
      /\bactive\b/g,
      /\bprojects?\b/g,
      /\bfor\b/g
    ]);
    const openOnly = wantsOpenItems(input, rawQuery);
    const url = new URL(`${baseUrl}/api/projects`);
    url.searchParams.set("count", "50");
    if (query) {
      url.searchParams.set("search", query);
    }

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA projects request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    const projects = normalizeCollectionPayload(payload, ["projects"])
      .filter((project) => (openOnly ? isProjectOpen(project) : true))
      .slice(0, 25);

    return {
      summary:
        projects.length > 0
          ? `Found ${projects.length} ${openOnly ? "open " : ""}HaloPSA projects. Results are condensed to project id, summary, status, customer, and manager.`
          : `No ${openOnly ? "open " : ""}HaloPSA projects matched that query.`,
      data: projects.map((project) => ({
        id: pickNumber(project, ["id", "project_id", "ticket_id"]),
        summary: pickString(project, ["summary", "name", "title"]),
        status: pickString(project, ["status_name", "status"]),
        customer: pickString(project, ["client_name", "customer_name", "organisation_name"]),
        manager: pickString(project, ["project_manager", "agent_name", "owner_name"]),
        ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: project } : {})
      })),
      source: "halopsa"
    };
  }

  private async findHaloContact(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query.trim() : pickString(input, ["search"]) ?? "";
    const hasAnyFilter =
      pickPositiveInt(input, ["client_id", "clientId", "site_id", "siteId", "department_id", "departmentId", "asset_id", "assetId", "organisation_id", "organisationId"]) !== undefined;
    if (!query && !hasAnyFilter) {
      throw new Error("find_contact requires a query (name/email/phone) or a real id filter");
    }

    const includeRaw = isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]);
    const requestedCount = pickPositiveInt(input, ["count"]) ?? 25;

    const contacts = (await this.lookupHaloUsers(baseUrl, accessToken, {
      ...input,
      query,
      count: requestedCount
    })).slice(0, requestedCount);

    return {
      summary:
        contacts.length > 0
          ? `Found ${contacts.length} HaloPSA users. Results include user id, name, email, phone, customer, site, department, and active status.${includeRaw ? "" : " Pass include_raw: true to also return the full Halo user payload."}`
          : "No HaloPSA users matched that query.",
      data: contacts.map((contact) => ({
        id: pickNumber(contact, ["id", "user_id", "contact_id"]),
        name: pickString(contact, ["name", "display_name", "fullname", "full_name"]),
        email: pickString(contact, ["email", "emailaddress", "email_address"]),
        phone:
          pickString(contact, ["phonenumber_preferred", "phone", "mobilephone", "telephone", "mobilenumber", "mobilenumber2"]),
        customer: pickString(contact, ["client_name", "organisation_name"]),
        site: pickString(contact, ["site_name"]),
        department: pickString(contact, ["department_name", "department"]),
        username: pickString(contact, ["username", "user_name", "samaccountname"]),
        active: typeof contact.inactive === "boolean" ? !contact.inactive : undefined,
        ...(includeRaw ? { raw: contact } : {})
      })),
      source: "halopsa"
    };
  }

  private async searchHaloDocuments(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query.trim() : "";
    if (!query) {
      throw new Error("search_documents requires a query");
    }

    const url = new URL(`${baseUrl}/api/kbarticle`);
    url.searchParams.set("count", "25");
    url.searchParams.set("search", query);

    const response = await fetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA knowledge request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    const documents = normalizeCollectionPayload(payload, ["articles", "kbarticles", "knowledgebase"]).slice(0, 25);

    return {
      summary:
        documents.length > 0
          ? `Found ${documents.length} HaloPSA knowledge articles. Results include article id, title, category, excerpt, and last updated time where available.`
          : "No HaloPSA knowledge articles matched that query.",
      data: documents.map((document) => ({
        id: pickNumber(document, ["id", "kbarticle_id", "article_id"]),
        title: pickString(document, ["title", "summary", "name"]),
        category: pickString(document, ["category", "category_name"]),
        excerpt: truncateText(stripHtmlToText(document.excerpt ?? document.summary_text ?? document.short_description), 1000),
        updatedAt: pickString(document, ["dateupdated", "updated_at", "lastmodified"]),
        ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: document } : {})
      })),
      source: "halopsa"
    };
  }

  private async listHaloDevicesForSite(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawSite = input.siteId ?? input.site_id ?? input.query;
    const siteRef = typeof rawSite === "number" || typeof rawSite === "string" ? String(rawSite).trim() : "";
    if (!siteRef) {
      throw new Error("list_devices_for_site requires a site id or search query");
    }

    let siteId = siteRef;
    if (Number.isNaN(Number(siteRef))) {
      const siteUrl = new URL(`${baseUrl}/api/site`);
      siteUrl.searchParams.set("count", "10");
      siteUrl.searchParams.set("search", siteRef);
      const siteResponse = await haloFetch(siteUrl, {
        headers: buildHaloHeaders(accessToken)
      });

      if (!siteResponse.ok) {
        const body = await siteResponse.text();
        throw new Error(`HaloPSA site lookup failed (${siteResponse.status}): ${body}`);
      }

      const sitePayload = (await siteResponse.json()) as unknown;
      const sites = normalizeCollectionPayload(sitePayload, ["sites"]);
      const site = sites[0];
      if (!site) {
        throw new Error(`No HaloPSA site matched ${siteRef}`);
      }

      siteId = String(pickNumber(site, ["id", "site_id"]) ?? "");
    }

    const assetUrl = new URL(`${baseUrl}/api/assets`);
    assetUrl.searchParams.set("count", "50");
    assetUrl.searchParams.set("site_id", siteId);

    const response = await haloFetch(assetUrl, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA assets request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    const assets = normalizeCollectionPayload(payload, ["assets", "devices"]).slice(0, 50);

    return {
      summary:
        assets.length > 0
          ? `Found ${assets.length} HaloPSA devices for site ${siteId}. Results include asset id, name, type, site, status, and serial number where available.`
          : `No HaloPSA devices found for site ${siteId}.`,
      data: assets.map((asset) => ({
        id: pickNumber(asset, ["id", "asset_id"]),
        name: pickString(asset, ["name", "inventory_number", "hostname"]),
        type: pickString(asset, ["assettype", "asset_type", "type"]),
        site: pickString(asset, ["site_name", "location_name"]),
        status: pickString(asset, ["status_name", "status"]),
        serialNumber: pickString(asset, ["serial_number", "serialno"]),
        ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: asset } : {})
      })),
      source: "halopsa"
    };
  }

  private buildNinjaOneHeaders(accessToken: string) {
    return {
      accept: "application/json",
      authorization: `Bearer ${accessToken}`
    };
  }

  private normalizeNinjaOneCollection(payload: unknown) {
    return normalizeCollectionPayload(payload, [
      "results",
      "items",
      "devices",
      "organizations",
      "organisations",
      "data",
      "alerts",
      "activities"
    ]);
  }

  private async fetchNinjaOneJson(baseUrl: string, accessToken: string, path: string, query?: Record<string, string | number | undefined>) {
    const url = new URL(`${baseUrl}${path}`);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== null && String(value).length > 0) {
        url.searchParams.set(key, String(value));
      }
    }

    logNinjaDebug("request", {
      method: "GET",
      url: url.toString()
    });

    const response = await fetch(url, {
      headers: this.buildNinjaOneHeaders(accessToken)
    });

    logNinjaDebug("response", {
      method: "GET",
      url: url.toString(),
      status: response.status,
      ok: response.ok
    });

    if (!response.ok) {
      const body = await response.text();
      logNinjaDebug("error", {
        method: "GET",
        url: url.toString(),
        status: response.status,
        body
      });
      throw new Error(`NinjaOne request failed (${response.status}) for ${path}: ${body}`);
    }

    return response.json() as Promise<unknown>;
  }

  private async tryFetchNinjaOneJson(baseUrl: string, accessToken: string, path: string) {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: this.buildNinjaOneHeaders(accessToken)
    });

    if (!response.ok) {
      logNinjaDebug("optional-miss", {
        method: "GET",
        url: `${baseUrl}${path}`,
        status: response.status
      });
      return undefined;
    }

    return response.json() as Promise<unknown>;
  }

  private async fetchNinjaOneJsonWithFallback(
    baseUrl: string,
    accessToken: string,
    paths: string[],
    query?: Record<string, string | number | undefined>
  ) {
    let lastError: Error | undefined;

    for (const path of paths) {
      try {
        return await this.fetchNinjaOneJson(baseUrl, accessToken, path, query);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
      }
    }

    throw lastError ?? new Error("NinjaOne request failed");
  }

  private async searchNinjaOneIndex(
    baseUrl: string,
    accessToken: string,
    options: {
      q?: string;
      limit?: number;
      organizationId?: number;
    }
  ) {
    const searchTerm = options.q?.trim();
    const limit = options.limit ?? 100;

    if (searchTerm) {
      try {
        return await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, ["/devices/search"], {
          q: searchTerm,
          limit
        });
      } catch {
        // Fall through to older/list-style endpoints.
      }
    }

    return this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, ["/devices"], {
      search: searchTerm || undefined,
      q: searchTerm || undefined,
      organizationId: options.organizationId,
      limit
    });
  }

  private async listNinjaOneOrganizations(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query.trim() : "";
    const limitValue =
      typeof input.limit === "number" ? input.limit : typeof input.limit === "string" ? Number(input.limit) : 100;
    const limit = Number.isFinite(limitValue) ? Math.min(Math.max(limitValue, 1), 250) : 100;

    const payload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, ["/organizations"], {
      limit
    });
    const organizations = this.normalizeNinjaOneCollection(payload);
    const filteredOrganizations = query
      ? organizations.filter((organization) =>
          [
            pickString(organization, ["name", "organizationName", "organisationName", "nodeClass"]),
            pickString(organization, ["description", "displayName"])
          ].some((value) => textMatches(value, query))
        )
      : organizations;

    return {
      summary:
        filteredOrganizations.length > 0
          ? `Found ${filteredOrganizations.length} NinjaOne organizations${query ? ` matching ${query}` : ""}. Results include organization id, name, description, and raw context where available.`
          : query
            ? `No NinjaOne organizations matched ${query}.`
            : "No NinjaOne organizations found.",
      data: filteredOrganizations.slice(0, limit).map((organization) => ({
        id: pickNumber(organization, ["id", "organizationId", "organisationId"]),
        name: pickString(organization, ["name", "organizationName", "organisationName"]),
        description: pickString(organization, ["description", "displayName", "nodeClass"]),
        parentId: pickNumber(organization, ["parentId", "parentOrganizationId"]),
        raw: organization
      })),
      source: "ninjaone"
    };
  }

  private async getNinjaOneOrganization(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId = input.id ?? input.organizationId ?? input.organisationId ?? input.organization_id ?? input.organisation_id;
    const organizationId =
      typeof rawId === "number" || typeof rawId === "string" ? String(rawId).trim() : "";

    if (!organizationId) {
      throw new Error("get_rmm_organization requires an organization id");
    }

    const payload = (await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
      `/organization/${organizationId}`,
      `/organizations/${organizationId}`
    ])) as Record<string, unknown>;

    return {
      summary: `Loaded NinjaOne organization ${pickString(payload, ["name", "organizationName", "organisationName"]) ?? organizationId}.`,
      data: [
        {
          id: pickNumber(payload, ["id", "organizationId", "organisationId"]),
          name: pickString(payload, ["name", "organizationName", "organisationName"]),
          description: pickString(payload, ["description", "displayName", "nodeClass"]),
          parentId: pickNumber(payload, ["parentId", "parentOrganizationId"]),
          raw: payload
        }
      ],
      source: "ninjaone"
    };
  }

  private async listNinjaOneDevicesForOrganization(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId = input.id ?? input.organizationId ?? input.organisationId ?? input.organization_id ?? input.organisation_id;
    let organizationId =
      typeof rawId === "number" || typeof rawId === "string" ? String(rawId).trim() : "";

    if (!organizationId) {
      const query = typeof input.query === "string" ? input.query.trim() : "";
      if (!query) {
        throw new Error("list_rmm_devices_for_site requires an organization id or search query");
      }

      const organizations = await this.listNinjaOneOrganizations(baseUrl, accessToken, { query, limit: 25 });
      const first = organizations.data[0];
      organizationId =
        typeof first?.id === "number" || typeof first?.id === "string" ? String(first.id).trim() : "";

      if (!organizationId) {
        return {
          summary: `No NinjaOne organization matched ${query}.`,
          data: [],
          source: "ninjaone"
        };
      }
    }

    const payload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
      `/organization/${organizationId}/devices`,
      `/organizations/${organizationId}/devices`
    ]);
    const devices = this.normalizeNinjaOneCollection(payload).slice(0, 100);

    return {
      summary:
        devices.length > 0
          ? `Found ${devices.length} NinjaOne devices for organization ${organizationId}.`
          : `No NinjaOne devices found for organization ${organizationId}.`,
      data: devices.map((device) => this.mapNinjaOneDevice(device)),
      source: "ninjaone"
    };
  }

  private pickDeviceId(input: Record<string, unknown>) {
    const rawId =
      input.id ??
      input.deviceId ??
      input.device_id ??
      input.endpointId ??
      input.endpoint_id;

    if (typeof rawId === "number" || typeof rawId === "string") {
      return String(rawId).trim();
    }

    const query = typeof input.query === "string" ? input.query.trim() : "";
    if (/^\d+$/.test(query)) {
      return query;
    }

    return "";
  }

  private mapNinjaOneDevice(device: Record<string, unknown>, options: { includeRaw?: boolean } = {}) {
    return {
      id: pickNumber(device, ["id", "deviceId", "device_id"]),
      name: pickString(device, ["systemName", "displayName", "name", "hostname"]),
      hostname: pickString(device, ["hostname", "dnsName", "systemName"]),
      organization: pickString(device, ["organizationName", "organisationName", "customerName"]),
      organizationId: pickNumber(device, ["organizationId", "organisationId", "customerId"]),
      site: pickString(device, ["siteName", "locationName"]),
      status: pickString(device, ["online", "status", "healthStatus"]),
      os: pickString(device, ["osName", "operatingSystem", "os"]),
      serialNumber: pickString(device, ["serialNumber", "serial"]),
      lastSeen: pickString(device, ["lastContact", "lastSeen", "lastLoggedInUser"]),
      ...(options.includeRaw ? { raw: device } : {})
    };
  }

  private async resolveNinjaOneDevice(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const deviceId = this.pickDeviceId(input);
    if (deviceId) {
      const payload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
        `/devices/${deviceId}`,
        `/device/${deviceId}`
      ]);
      return payload as Record<string, unknown>;
    }

    const query = typeof input.query === "string" ? input.query.trim() : "";
    if (!query) {
      throw new Error("A NinjaOne device id or search query is required");
    }

    const payload = await this.searchNinjaOneIndex(baseUrl, accessToken, {
      q: query,
      limit: 50
    });
    const devices = this.normalizeNinjaOneCollection(payload);
    const matched = devices.find((device) =>
      [pickString(device, ["systemName", "displayName", "name", "hostname", "serialNumber", "serial"])].some((candidate) =>
        textMatches(candidate, query)
      )
    ) ?? devices[0];

    if (!matched) {
      throw new Error(`No NinjaOne device matched ${query}`);
    }

    const matchedId = pickNumber(matched, ["id", "deviceId", "device_id"]);
    if (!matchedId) {
      return matched;
    }

    const detail = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
      `/devices/${matchedId}`,
      `/device/${matchedId}`
    ]);
    return detail as Record<string, unknown>;
  }

  private async searchNinjaOneDevices(
    tenantId: string,
    userId: string,
    baseUrl: string,
    accessToken: string,
    input: Record<string, unknown>,
    options: { requireUserMatch?: boolean } = {}
  ) {
    const rawQuery = typeof input.query === "string" ? input.query.trim() : "";
    const userHint = extractUserHint(rawQuery);
    const query = extractMeaningfulQuery(rawQuery, [
      /\bdevices?\b/g,
      /\bdevice\b/g,
      /\bendpoints?\b/g,
      /\bendpoint\b/g,
      /\bfor\b/g,
      /\bused by\b/g,
      /\bbelonging to\b/g,
      /\bassigned to\b/g
    ]);
    const organizationId = pickNumber(input, ["organizationId", "organisationId", "customerId", "siteId", "site_id"]);
    const haloHints = rawQuery ? await this.resolveHaloEntityHints(tenantId, userId, rawQuery) : undefined;
    const effectiveUserHints = [userHint, ...(haloHints?.userHints ?? []), ...(haloHints?.emailHints ?? [])]
      .map((value) => value.trim())
      .filter(Boolean);
    const effectiveOrganizationHints = (haloHints?.organizationHints ?? []).map((value) => value.trim()).filter(Boolean);
    const effectiveDeviceHints = (haloHints?.deviceHints ?? []).map((value) => value.trim()).filter(Boolean);
    const userSearchVariants = Array.from(
      new Set(
        effectiveUserHints
          .flatMap((hint) => buildIdentityVariants(hint))
          .map((value) => value.trim())
          .filter(Boolean)
      )
    );
    const shouldUseRawSearch = query ? looksLikeDeviceIdentityQuery(query) : false;
    const usedHaloAssetBridge = effectiveDeviceHints.length > 0;
    const candidateSearches = Array.from(
      new Set([
        ...(usedHaloAssetBridge ? effectiveDeviceHints.slice(0, 10) : []),
        shouldUseRawSearch ? query : "",
        !shouldUseRawSearch && effectiveOrganizationHints.length > 0 ? effectiveOrganizationHints[0] ?? "" : "",
        ...(usedHaloAssetBridge ? [] : effectiveDeviceHints.slice(0, 6)),
        ...userSearchVariants.slice(0, 10)
      ].filter(Boolean))
    );

    logNinjaDebug("user-device-search", {
      rawQuery,
      cleanedQuery: query,
      effectiveUserHints,
      effectiveOrganizationHints,
      effectiveDeviceHints,
      candidateSearches,
      requireUserMatch: Boolean(options.requireUserMatch)
    });

    const candidatePayloads = await Promise.all([
      this.searchNinjaOneIndex(baseUrl, accessToken, {
        organizationId,
        limit: 100
      }),
      ...candidateSearches.map((searchTerm) =>
        this.searchNinjaOneIndex(baseUrl, accessToken, {
          q: searchTerm,
          organizationId,
          limit: 100
        })
      )
    ]);

    const allDevices = dedupeTicketsById(
      candidatePayloads.flatMap((payload) => this.normalizeNinjaOneCollection(payload))
    ) as Record<string, unknown>[];

    const filteredDevices = allDevices.filter((device) => {
      if (effectiveUserHints.length === 0 && effectiveOrganizationHints.length === 0) {
        return true;
      }

      const userMatch =
        effectiveUserHints.length === 0 ||
        effectiveUserHints.some((hint) => deviceMatchesUserHint(device, hint));
      const organizationCandidate = pickString(device, ["organizationName", "organisationName", "customerName", "siteName"]);
      const organizationMatch =
        effectiveOrganizationHints.length === 0 ||
        effectiveOrganizationHints.some((hint) => textMatches(organizationCandidate, hint));

      if (options.requireUserMatch && effectiveUserHints.length > 0) {
        return userMatch;
      }

      if (effectiveUserHints.length > 0 && effectiveOrganizationHints.length > 0) {
        return userMatch && organizationMatch;
      }

      return userMatch || organizationMatch;
    });

    const hasTargetedHints = effectiveUserHints.length > 0 || effectiveOrganizationHints.length > 0;
    const candidatePool =
      filteredDevices.length > 0
        ? filteredDevices
        : options.requireUserMatch && hasTargetedHints
          ? allDevices
          : hasTargetedHints
            ? []
            : allDevices;
    let rankedDevices = filteredDevices.length > 0 ? filteredDevices : hasTargetedHints ? [] : allDevices;

    if (effectiveUserHints.length > 0) {
      const topCandidates = candidatePool
        .sort(
          (left, right) =>
            scoreNinjaOneDevice(right, query, effectiveUserHints, effectiveOrganizationHints, effectiveDeviceHints) -
            scoreNinjaOneDevice(left, query, effectiveUserHints, effectiveOrganizationHints, effectiveDeviceHints)
        )
        .slice(0, options.requireUserMatch ? 25 : 15);

      const detailedCandidates = await Promise.all(
        topCandidates.map(async (device) => {
          const deviceId = pickNumber(device, ["id", "deviceId", "device_id"]);
          if (!deviceId) {
            return device;
          }

          try {
            return (await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
              `/devices/${deviceId}`,
              `/device/${deviceId}`
            ])) as Record<string, unknown>;
          } catch {
            return device;
          }
        })
      );

      const detailMatches = detailedCandidates.filter((device) =>
        effectiveUserHints.some((hint) => deviceMatchesUserHint(device, hint))
      );

      if (detailMatches.length > 0) {
        rankedDevices = detailMatches;
      } else if (options.requireUserMatch && effectiveDeviceHints.length > 0) {
        rankedDevices = detailedCandidates.filter((device) => {
          const nameCandidate = pickString(device, ["systemName", "displayName", "hostname", "name"]);
          const serialCandidate = pickString(device, ["serialNumber", "serial"]);
          return effectiveDeviceHints.some((hint) => textMatches(nameCandidate, hint) || textMatches(serialCandidate, hint));
        });
      } else if (!hasTargetedHints) {
        rankedDevices = detailedCandidates;
      } else {
        rankedDevices = [];
      }
    }

    logNinjaDebug("user-device-result", {
      rawQuery,
      candidatePoolSize: candidatePool.length,
      filteredDeviceCount: filteredDevices.length,
      resultCount: rankedDevices.length,
      topResultIds: rankedDevices
        .slice(0, 10)
        .map((device) => pickNumber(device, ["id", "deviceId", "device_id"]) ?? pickString(device, ["id", "deviceId", "device_id"]))
    });

    const devices = rankedDevices
      .sort(
        (left, right) =>
          scoreNinjaOneDevice(right, query, effectiveUserHints, effectiveOrganizationHints, effectiveDeviceHints) -
          scoreNinjaOneDevice(left, query, effectiveUserHints, effectiveOrganizationHints, effectiveDeviceHints)
      )
      .slice(0, options.requireUserMatch ? 15 : 50);

    return {
      summary:
        devices.length > 0
          ? `Found ${devices.length} NinjaOne devices${
              effectiveUserHints[0] || effectiveOrganizationHints[0]
                ? ` related to ${effectiveUserHints[0] ?? effectiveOrganizationHints[0]}`
                : ""
            }${
              usedHaloAssetBridge ? " using Halo asset records as the device bridge." : "."
            } Username variants such as domain-prefixed logins are considered during matching. Results are condensed to device identity, organization, site, health, operating system, and serial information.`
          : hasTargetedHints
            ? options.requireUserMatch && effectiveUserHints.length > 0
              ? "No NinjaOne devices could be confidently linked to that specific user. Organization-only matches are intentionally excluded for this user-focused lookup."
              : "No NinjaOne devices could be confidently linked to that person or organization. Generic top devices are intentionally excluded until a real user, org, or asset match is found."
            : "No NinjaOne devices matched that search.",
      data: devices.map((device) => this.mapNinjaOneDevice(device)),
      source: "ninjaone"
    };
  }

  private async getUserDevicesViaHaloAssets(
    tenantId: string,
    userId: string,
    baseUrl: string,
    accessToken: string,
    input: Record<string, unknown>
  ) {
    const rawQuery = typeof input.query === "string" ? input.query.trim() : "";
    if (!rawQuery) {
      throw new Error("get_user_devices requires a user query");
    }

    const haloAccount = (await this.store.findByTenantUser(tenantId, userId)).find(
      (candidate) => candidate.provider === "halopsa" && candidate.status === "ACTIVE"
    );
    if (!haloAccount) {
      throw new Error(`No active HaloPSA account found for ${tenantId}/${userId}`);
    }

    const freshHalo = await this.ensureFreshAccount(haloAccount);
    const haloToken = this.encryption.decrypt(freshHalo.accessTokenEncrypted);
    const haloBaseUrl = this.getHaloBaseUrlForAccount(freshHalo);

    const userSearchUrl = new URL(`${haloBaseUrl}/api/users`);
    userSearchUrl.searchParams.set("count", "25");
    userSearchUrl.searchParams.set("search", rawQuery);
    const userSearchResponse = await haloFetch(userSearchUrl, {
      headers: buildHaloHeaders(haloToken)
    });

    if (!userSearchResponse.ok) {
      const body = await userSearchResponse.text();
      throw new Error(`HaloPSA user lookup failed (${userSearchResponse.status}): ${body}`);
    }

    const userMatches = normalizeCollectionPayload(await userSearchResponse.json(), ["users", "contacts", "results", "data"]);
    const matchedUser =
      userMatches.find((candidate) =>
        [
          pickString(candidate, ["name", "display_name", "fullname", "full_name"]),
          pickString(candidate, ["email", "emailaddress", "email_address"]),
          pickString(candidate, ["username", "user_name"])
        ].some((value) => textMatches(value, rawQuery))
      ) ?? userMatches[0];

    if (!matchedUser) {
      return {
        summary: `No HaloPSA user matched ${rawQuery}.`,
        data: [],
        source: "ninjaone"
      };
    }

    const matchedUserId = pickNumber(matchedUser, ["id", "user_id", "contact_id"]);
    if (!matchedUserId) {
      return {
        summary: `A HaloPSA user matched ${rawQuery}, but no user id was available to load assets.`,
        data: [],
        source: "ninjaone"
      };
    }

    const haloUserDetail = await haloFetch(`${haloBaseUrl}/api/users/${matchedUserId}?includeusersassets=true`, {
      headers: buildHaloHeaders(haloToken)
    });

    if (!haloUserDetail.ok) {
      const body = await haloUserDetail.text();
      throw new Error(`HaloPSA user asset lookup failed (${haloUserDetail.status}): ${body}`);
    }

    const haloUserPayload = (await haloUserDetail.json()) as unknown;
    const haloUserRecord =
      Array.isArray(haloUserPayload) && haloUserPayload[0] && typeof haloUserPayload[0] === "object"
        ? (haloUserPayload[0] as Record<string, unknown>)
        : payloadIsRecord(haloUserPayload)
          ? haloUserPayload
          : {};
    let haloAssets = extractHaloAssetRecords(haloUserPayload);

    if (haloAssets.length === 0) {
      const assetSearchUrl = new URL(`${haloBaseUrl}/api/assets`);
      assetSearchUrl.searchParams.set("count", "50");
      assetSearchUrl.searchParams.set("includeinactive", "false");
      assetSearchUrl.searchParams.set("includeactive", "true");

      const matchedUserName =
        pickString(haloUserRecord, ["name", "display_name", "fullname", "full_name"]) ??
        pickString(matchedUser, ["name", "display_name", "fullname", "full_name"]);
      const matchedUserEmail =
        pickString(haloUserRecord, ["email", "emailaddress", "email_address"]) ??
        pickString(matchedUser, ["email", "emailaddress", "email_address"]);
      const matchedUserUsername =
        pickString(haloUserRecord, ["username", "user_name", "samaccountname"]) ??
        pickString(matchedUser, ["username", "user_name", "samaccountname"]);
      const matchedSiteRecord = payloadIsRecord(haloUserRecord.site) ? haloUserRecord.site : undefined;
      const matchedClientId =
        pickNumber(haloUserRecord, ["client_id"]) ??
        (matchedSiteRecord ? pickNumber(matchedSiteRecord, ["client_id"]) : undefined) ??
        pickNumber(matchedUser, ["client_id"]);
      const matchedSiteId =
        pickNumber(haloUserRecord, ["site_id", "site_id_int"]) ??
        pickNumber(matchedUser, ["site_id", "site_id_int"]);

      if (matchedClientId !== undefined) {
        assetSearchUrl.searchParams.set("client_id", String(matchedClientId));
      }
      if (matchedSiteId !== undefined) {
        assetSearchUrl.searchParams.set("site_id", String(matchedSiteId));
      }
      if (matchedUserName) {
        assetSearchUrl.searchParams.set("username", matchedUserName);
        assetSearchUrl.searchParams.set("search", matchedUserName);
      } else if (matchedUserEmail || matchedUserUsername) {
        assetSearchUrl.searchParams.set("search", matchedUserEmail ?? matchedUserUsername ?? rawQuery);
      } else {
        assetSearchUrl.searchParams.set("search", rawQuery);
      }

      const assetSearchResponse = await haloFetch(assetSearchUrl, {
        headers: buildHaloHeaders(haloToken)
      });

      if (assetSearchResponse.ok) {
        haloAssets = normalizeCollectionPayload(await assetSearchResponse.json(), ["assets", "devices", "results", "data"]);
        logNinjaDebug("halo-user-assets-fallback", {
          rawQuery,
          matchedUserId,
          assetSearchUrl: assetSearchUrl.toString(),
          fallbackAssetCount: haloAssets.length
        });
      } else {
        const fallbackBody = await assetSearchResponse.text();
        logNinjaDebug("halo-user-assets-fallback-error", {
          rawQuery,
          matchedUserId,
          assetSearchUrl: assetSearchUrl.toString(),
          status: assetSearchResponse.status,
          body: fallbackBody.slice(0, 500)
        });
      }
    }

    const assetIdentifiers = Array.from(
      new Set(
        haloAssets.flatMap((asset) => extractHaloAssetIdentifiers(asset).map((value) => normalizeWhitespace(value)))
      )
    ) as string[];
    const assetSystemNames = Array.from(
      new Set(haloAssets.flatMap((asset) => extractHaloAssetSystemNames(asset)))
    ) as string[];

    logNinjaDebug("halo-user-assets", {
      rawQuery,
      matchedUserId,
      matchedUserName: pickString(matchedUser, ["name", "display_name", "fullname", "full_name"]),
      haloUserPayloadType: Array.isArray(haloUserPayload) ? "array" : typeof haloUserPayload,
      haloAssetCount: haloAssets.length,
      assetSystemNames,
      assetIdentifiers: assetIdentifiers.slice(0, 25),
      sampleAssets: haloAssets.slice(0, 5).map((asset: HaloGenericRecord) => ({
        id: pickNumber(asset, ["id", "asset_id"]),
        inventoryNumber: pickString(asset, ["inventory_number", "inventoryNumber"]),
        keyField: pickString(asset, ["key_field", "keyfield", "name", "hostname"]),
        keyField2: pickString(asset, ["key_field2", "keyfield2", "serial_number", "serialno"]),
        username: pickString(asset, ["username", "business_owner_name", "technical_owner_name"])
      }))
    });

    if (assetIdentifiers.length === 0) {
      return {
        summary: `Found HaloPSA user ${pickString(haloUserRecord, ["name", "display_name", "fullname", "full_name"]) ?? pickString(matchedUser, ["name", "display_name", "fullname", "full_name"]) ?? rawQuery}, but no user assets were returned from HaloPSA.`,
        data: [],
        source: "ninjaone"
      };
    }

    const ninjaPayload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, ["/devices"], {
      limit: 1000
    });
    const allDevices = this.normalizeNinjaOneCollection(ninjaPayload);
    const rankedMatches = allDevices
      .map((device) => {
        const systemName = normalizeWhitespace(
          pickString(device, ["systemName", "displayName", "name", "hostname"]) ?? ""
        );
        const serialNumber = normalizeWhitespace(pickString(device, ["serialNumber", "serial"]) ?? "");
        let score = 0;

        for (const candidate of assetSystemNames) {
          const normalizedCandidate = normalizeWhitespace(candidate);
          if (!normalizedCandidate || !systemName) {
            continue;
          }
          if (systemName.toLowerCase() === normalizedCandidate.toLowerCase()) {
            score = Math.max(score, 100);
          } else if (textMatches(systemName, normalizedCandidate) || textMatches(normalizedCandidate, systemName)) {
            score = Math.max(score, 70);
          }
        }

        for (const identifier of assetIdentifiers) {
          const normalizedIdentifier = normalizeWhitespace(identifier);
          if (!normalizedIdentifier) {
            continue;
          }
          if (serialNumber && serialNumber.toLowerCase() === normalizedIdentifier.toLowerCase()) {
            score = Math.max(score, 95);
          } else if (serialNumber && textMatches(serialNumber, normalizedIdentifier)) {
            score = Math.max(score, 65);
          }
        }

        return { device, score };
      })
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score);
    const matchedDevices = rankedMatches.map((entry) => entry.device);

    const matchedDeviceIds = matchedDevices
      .slice(0, 10)
      .map((device) => pickNumber(device, ["id", "deviceId", "device_id"]))
      .filter((value) => value !== undefined) as number[];

    const detailedDevices = await Promise.all(
      matchedDeviceIds.slice(0, 5).map(async (deviceId) => {
        try {
          return (await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
            `/device/${deviceId}`,
            `/devices/${deviceId}`
          ])) as Record<string, unknown>;
        } catch {
          return matchedDevices.find((device) => pickNumber(device, ["id", "deviceId", "device_id"]) === deviceId);
        }
      })
    );
    const devices = detailedDevices.filter(Boolean) as Record<string, unknown>[];

    logNinjaDebug("halo-asset-device-match", {
      rawQuery,
      assetSystemNames,
      assetIdentifiers,
      totalDevices: allDevices.length,
      matchedDeviceIds
    });

    return {
      summary:
        devices.length > 0
          ? `Found ${devices.length} NinjaOne devices for ${pickString(haloUserRecord, ["name", "display_name", "fullname", "full_name"]) ?? pickString(matchedUser, ["name", "display_name", "fullname", "full_name"]) ?? rawQuery} using Halo user assets as the device bridge.`
          : `No NinjaOne devices matched the Halo user assets for ${pickString(haloUserRecord, ["name", "display_name", "fullname", "full_name"]) ?? pickString(matchedUser, ["name", "display_name", "fullname", "full_name"]) ?? rawQuery}.`,
      data: devices.map((device: Record<string, unknown>) => this.mapNinjaOneDevice(device)),
      source: "ninjaone"
    };
  }

  private async getNinjaOneDeviceAlerts(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const device = await this.resolveNinjaOneDevice(baseUrl, accessToken, input);
    const deviceId = pickNumber(device, ["id", "deviceId", "device_id"]);
    if (!deviceId) {
      throw new Error("Could not resolve a NinjaOne device id for alerts");
    }

    const payload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
      `/device/${deviceId}/alerts`,
      `/devices/${deviceId}/alerts`
    ]);
    const alerts = this.normalizeNinjaOneCollection(payload).slice(0, 50);

    return {
      summary:
        alerts.length > 0
          ? `Found ${alerts.length} NinjaOne alerts for device ${deviceId}. Results include severity, category, source, timestamps, and raw alert context where available.`
          : `No NinjaOne alerts found for device ${deviceId}.`,
      data: alerts.map((alert) => ({
        id: pickNumber(alert, ["id", "alertId", "uid"]),
        severity: pickString(alert, ["severity", "priority", "status"]),
        category: pickString(alert, ["category", "type", "alertType"]),
        message: pickString(alert, ["message", "title", "summary"]),
        source: pickString(alert, ["source", "policyName", "checkName"]),
        createdAt: pickString(alert, ["created", "createdAt", "raisedAt"]),
        raw: alert
      })),
      source: "ninjaone"
    };
  }

  private async getNinjaOneDeviceActivities(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const device = await this.resolveNinjaOneDevice(baseUrl, accessToken, input);
    const deviceId = pickNumber(device, ["id", "deviceId", "device_id"]);
    if (!deviceId) {
      throw new Error("Could not resolve a NinjaOne device id for activities");
    }

    const payload = await this.fetchNinjaOneJsonWithFallback(baseUrl, accessToken, [
      `/device/${deviceId}/activities`,
      `/devices/${deviceId}/activities`
    ]);
    const activities = this.normalizeNinjaOneCollection(payload).slice(0, 50);

    return {
      summary:
        activities.length > 0
          ? `Found ${activities.length} NinjaOne activities for device ${deviceId}. Results include activity type, summary, user or source, and timestamps where available.`
          : `No NinjaOne activities found for device ${deviceId}.`,
      data: activities.map((activity) => ({
        id: pickNumber(activity, ["id", "activityId"]),
        type: pickString(activity, ["type", "activityType", "category"]),
        summary: pickString(activity, ["summary", "message", "description"]),
        actor: pickString(activity, ["userName", "actor", "source"]),
        createdAt: pickString(activity, ["created", "createdAt", "timestamp"]),
        raw: activity
      })),
      source: "ninjaone"
    };
  }

  private async getNinjaOneDeviceOverview(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const device = await this.resolveNinjaOneDevice(baseUrl, accessToken, input);
    const deviceId = pickNumber(device, ["id", "deviceId", "device_id"]);
    if (!deviceId) {
      throw new Error("Could not resolve a NinjaOne device id");
    }

    const [
      alertsPayload,
      activitiesPayload,
      disksPayload,
      softwarePayload,
      softwarePatchInstallsPayload,
      osPatchInstallsPayload,
      processorsPayload,
      networkInterfacesPayload,
      windowsServicesPayload
    ] = await Promise.all([
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/alerts`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/alerts`)),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/activities`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/activities`)),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/disks`)
        .then(
          (payload) =>
            payload
            ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/volumes`)
            ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/volumes`)
            ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/disks`)
        ),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/software`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/software`)),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/software-patch-installs`).then(
        (payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/software-patch-installs`)
      ),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/os-patch-installs`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/os-patch-installs`)),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/processors`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/processors`)),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/network-interfaces`).then(
        (payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/network-interfaces`)
      ),
      this.tryFetchNinjaOneJson(baseUrl, accessToken, `/device/${deviceId}/windows-services`)
        .then((payload) => payload ?? this.tryFetchNinjaOneJson(baseUrl, accessToken, `/devices/${deviceId}/windows-services`))
    ]);

    const alerts = alertsPayload ? this.normalizeNinjaOneCollection(alertsPayload).slice(0, 10) : [];
    const activities = activitiesPayload ? this.normalizeNinjaOneCollection(activitiesPayload).slice(0, 10) : [];
    const disks = disksPayload ? this.normalizeNinjaOneCollection(disksPayload).slice(0, 20) : [];
    const software = softwarePayload ? this.normalizeNinjaOneCollection(softwarePayload).slice(0, 50) : [];
    const softwarePatchInstalls = softwarePatchInstallsPayload
      ? this.normalizeNinjaOneCollection(softwarePatchInstallsPayload).slice(0, 50)
      : [];
    const osPatchInstalls = osPatchInstallsPayload ? this.normalizeNinjaOneCollection(osPatchInstallsPayload).slice(0, 50) : [];
    const processors = processorsPayload ? this.normalizeNinjaOneCollection(processorsPayload).slice(0, 20) : [];
    const networkInterfaces = networkInterfacesPayload
      ? this.normalizeNinjaOneCollection(networkInterfacesPayload).slice(0, 20)
      : [];
    const windowsServices = windowsServicesPayload ? this.normalizeNinjaOneCollection(windowsServicesPayload).slice(0, 50) : [];
    const mappedDevice = this.mapNinjaOneDevice(device);

    return {
      summary: `Loaded NinjaOne device ${mappedDevice.name ?? deviceId}. Results include endpoint identity, health context, alerts, recent activities, storage, software, patching, processors, network interfaces, and Windows service details where the API exposes them.`,
      data: [
        {
          ...mappedDevice,
          alerts: alerts.map((alert) => ({
            id: pickNumber(alert, ["id", "alertId", "uid"]),
            severity: pickString(alert, ["severity", "priority", "status"]),
            message: pickString(alert, ["message", "title", "summary"]),
            source: pickString(alert, ["source", "policyName", "checkName"]),
            createdAt: pickString(alert, ["created", "createdAt", "raisedAt"])
          })),
          activities: activities.map((activity) => ({
            id: pickNumber(activity, ["id", "activityId"]),
            type: pickString(activity, ["type", "activityType", "category"]),
            summary: pickString(activity, ["summary", "message", "description"]),
            createdAt: pickString(activity, ["created", "createdAt", "timestamp"])
          })),
          disks: disks.map((disk) => ({
            name: pickString(disk, ["name", "label", "mountPoint", "device"]),
            totalBytes: pickNumber(disk, ["size", "totalBytes", "capacity"]),
            freeBytes: pickNumber(disk, ["free", "freeBytes", "available"]),
            usedPercent: pickNumber(disk, ["usedPercent", "usagePercent", "percentUsed"]),
            fileSystem: pickString(disk, ["fileSystem", "filesystem", "fsType"])
          })),
          software: software.map((entry) => ({
            name: pickString(entry, ["name", "displayName", "softwareName"]),
            version: pickString(entry, ["version", "displayVersion"]),
            publisher: pickString(entry, ["publisher", "vendor"]),
            installDate: pickString(entry, ["installDate", "installedAt", "date"])
          })),
          softwarePatchInstalls: softwarePatchInstalls.map((entry) => ({
            name: pickString(entry, ["name", "title", "patchName"]),
            kb: pickString(entry, ["kb", "kbNumber", "articleId"]),
            status: pickString(entry, ["status", "result"]),
            installedAt: pickString(entry, ["installedAt", "date", "createdAt"])
          })),
          osPatchInstalls: osPatchInstalls.map((entry) => ({
            name: pickString(entry, ["name", "title", "patchName"]),
            kb: pickString(entry, ["kb", "kbNumber", "articleId"]),
            status: pickString(entry, ["status", "result"]),
            installedAt: pickString(entry, ["installedAt", "date", "createdAt"])
          })),
          processors: processors.map((entry) => ({
            name: pickString(entry, ["name", "model", "processorName"]),
            manufacturer: pickString(entry, ["manufacturer", "vendor"]),
            cores: pickNumber(entry, ["cores", "coreCount"]),
            logicalProcessors: pickNumber(entry, ["logicalProcessors", "threadCount"]),
            speed: pickString(entry, ["speed", "clockSpeed", "maxSpeed"])
          })),
          networkInterfaces: networkInterfaces.map((entry) => ({
            name: pickString(entry, ["name", "interfaceName", "description"]),
            macAddress: pickString(entry, ["macAddress", "mac"]),
            ipv4: pickString(entry, ["ipv4", "ipAddress", "address"]),
            ipv6: pickString(entry, ["ipv6"]),
            status: pickString(entry, ["status", "state"])
          })),
          windowsServices: windowsServices.map((entry) => ({
            name: pickString(entry, ["name", "serviceName", "displayName"]),
            status: pickString(entry, ["status", "state"]),
            startupType: pickString(entry, ["startupType", "startType"]),
            logOnAs: pickString(entry, ["logOnAs", "account"])
          }))
        }
      ],
      source: "ninjaone"
    };
  }

  private async getRecentHaloInvoices(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const countValue = typeof input.count === "number" ? input.count : typeof input.count === "string" ? Number(input.count) : 25;
    const count = Number.isFinite(countValue) ? Math.min(Math.max(countValue, 1), 50) : 25;
    const url = new URL(`${baseUrl}/api/invoices`);
    url.searchParams.set("count", String(count));

    const response = await haloFetch(url, {
      headers: buildHaloHeaders(accessToken)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA invoices request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as unknown;
    const invoices = normalizeCollectionPayload(payload, ["invoices"]).slice(0, count);

    return {
      summary:
        invoices.length > 0
          ? `Loaded ${invoices.length} recent HaloPSA invoices. Results include invoice id, reference, customer, status, total, and issued date where available.`
          : "No recent HaloPSA invoices found.",
      data: invoices.map((invoice) => ({
        id: pickNumber(invoice, ["id", "invoice_id"]),
        reference: pickString(invoice, ["invoice_number", "reference", "ref"]),
        customer: pickString(invoice, ["client_name", "customer_name"]),
        status: pickString(invoice, ["status_name", "status"]),
        total: pickString(invoice, ["total", "amount", "grand_total"]),
        issuedAt: pickString(invoice, ["date", "issued_at", "invoice_date"]),
        ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: invoice } : {})
      })),
      source: "halopsa"
    };
  }

  private async createDraftHaloTicket(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const summary = typeof input.summary === "string" ? input.summary.trim() : typeof input.query === "string" ? input.query.trim() : "";
    if (!summary) {
      throw new Error("create_draft_ticket requires a summary");
    }

    const payload = {
      summary,
      details: typeof input.details === "string" ? input.details : undefined,
      client_id: pickNumber(input, ["clientId", "client_id"]),
      site_id: pickNumber(input, ["siteId", "site_id"]),
      user_id: pickNumber(input, ["contactId", "contact_id", "userId", "user_id"]),
      tickettype_id: pickNumber(input, ["ticketTypeId", "ticket_type_id"]),
      priority_id: pickNumber(input, ["priorityId", "priority_id"])
    };

    const response = await haloFetch(`${baseUrl}/api/tickets`, {
      method: "POST",
      headers: buildHaloJsonHeaders(accessToken),
      body: JSON.stringify(payload),
      bodyPreview: payload
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA ticket creation failed (${response.status}): ${body}`);
    }

    const ticket = (await response.json()) as HaloGenericRecord;
    return {
      summary: "Created a draft HaloPSA ticket. Result includes the new ticket id, summary, and current status.",
      data: [
        {
          id: pickNumber(ticket, ["id", "ticket_id", "TicketID"]),
          summary: pickString(ticket, ["summary", "subject", "title"]),
          status: getHaloTicketStatus(ticket),
          ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: ticket } : {})
        }
      ],
      source: "halopsa"
    };
  }

  private async addHaloInternalNote(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId =
      input.id ??
      input.ticketId ??
      input.ticket_id ??
      input.ticket ??
      input.ticketNumber ??
      input.ticket_number;
    let ticketId = typeof rawId === "number" || typeof rawId === "string" ? String(rawId).trim() : undefined;
    let note =
      typeof input.note === "string"
        ? input.note.trim()
        : typeof input.message === "string"
          ? input.message.trim()
          : typeof input.text === "string"
            ? input.text.trim()
            : typeof input.content === "string"
              ? input.content.trim()
              : typeof input.comment === "string"
                ? input.comment.trim()
                : typeof input.body === "string"
                  ? input.body.trim()
                  : "";

    if ((!ticketId || !note) && typeof input.query === "string") {
      const query = input.query.trim();

      if (!ticketId) {
        const ticketMatch = query.match(/ticket\s+#?0*([0-9]+)/i);
        if (ticketMatch) {
          ticketId = ticketMatch[1];
        }
      }

      if (!note) {
        note = query
          .replace(/add\s+(an?\s+)?internal\s+note\s+(to|for)\s+ticket\s+#?0*[0-9]+/i, "")
          .replace(/ticket\s+#?0*[0-9]+/i, "")
          .trim();
      }
    }

    if (!ticketId || !note) {
      throw new Error("add_internal_note requires a ticket id and note");
    }

    const actionPayload = [
      {
        ticket_id: ticketId,
        outcome: "Private Note",
        note,
        note_html: note,
        hiddenfromuser: true
      }
    ];

    const response = await haloFetch(`${baseUrl}/api/actions`, {
      method: "POST",
      headers: buildHaloJsonHeaders(accessToken),
      body: JSON.stringify(actionPayload),
      bodyPreview: actionPayload
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HaloPSA action creation failed (${response.status}): ${body}`);
    }

    const action = (await response.json()) as HaloGenericRecord;
    return {
      summary: `Added an internal HaloPSA note to ticket ${ticketId}. Result includes the created action id and stored note text.`,
      data: [
        {
          id: pickNumber(action, ["id", "action_id"]),
          ticketId: pickNumber(action, ["ticket_id", "ticketid"]),
          note: pickString(action, ["note", "note_html", "outcome"]) ?? note,
          ...(isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]) ? { raw: action } : {})
        }
      ],
      source: "halopsa"
    };
  }

  private async getHaloTicket(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const rawId = input.id ?? input.ticketId ?? input.ticket_id ?? input.query;
    const id = typeof rawId === "number" || typeof rawId === "string" ? String(rawId).trim() : undefined;
    if (!id) {
      throw new Error("get_ticket requires an id");
    }

    const includeRaw = isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]);

    let ticket: HaloTicketRecord | undefined;

    const directUrl = new URL(`${baseUrl}/api/tickets/${id}`);
    directUrl.searchParams.set("includedetails", "true");
    directUrl.searchParams.set("includelastaction", "true");
    directUrl.searchParams.set("includechildtickets", "false");
    directUrl.searchParams.set("includeattachments", "false");

    const directResponse = await haloFetch(directUrl, {
      headers: buildHaloHeaders(accessToken)
    });

    if (directResponse.ok) {
      ticket = (await directResponse.json()) as HaloTicketRecord;
    } else {
      const searchUrl = new URL(`${baseUrl}/api/tickets`);
      searchUrl.searchParams.set("search", id);
      searchUrl.searchParams.set("count", "25");

      const searchResponse = await haloFetch(searchUrl, {
        headers: buildHaloHeaders(accessToken)
      });

      if (!searchResponse.ok) {
        const body = await searchResponse.text();
        throw new Error(`HaloPSA ticket request failed (${searchResponse.status}): ${body}`);
      }

      const payload = (await searchResponse.json()) as HaloTicketRecord[] | { tickets?: HaloTicketRecord[] };
      const tickets = Array.isArray(payload) ? payload : (payload.tickets ?? []);
      ticket = tickets.find((candidate) => ticketMatchesIdentifier(candidate, id));

      if (!ticket) {
        const directBody = await directResponse.text();
        throw new Error(`HaloPSA ticket request failed (${directResponse.status}): ${directBody}`);
      }
    }

    const resolvedStatus = await this.resolveHaloTicketStatusName(baseUrl, accessToken, ticket);

    return {
      summary: `Loaded HaloPSA ticket ${id}. Result includes summary, status, customer, priority, description, requester, agent, and key dates.${includeRaw ? "" : " Pass include_raw: true to also return the full Halo payload."}`,
      data: [buildDetailedHaloTicket(ticket, resolvedStatus, { includeRaw })],
      source: "halopsa"
    };
  }

  private async findHaloCustomer(baseUrl: string, accessToken: string, input: Record<string, unknown>) {
    const query = typeof input.query === "string" ? input.query : undefined;
    if (!query) {
      throw new Error("find_customer requires a query");
    }

    const includeRaw = isTruthyFlag(input, ["include_raw", "includeRaw", "raw", "full"]);
    const clients = await this.lookupHaloCustomers(baseUrl, accessToken, query, 25);

    return {
      summary:
        clients.length > 0
          ? `Found ${clients.length} HaloPSA customers. Results include customer id, name, reference, email, and phone where available.${includeRaw ? "" : " Pass include_raw: true for the full Halo client payload."}`
          : "No HaloPSA customers matched that query.",
      data: clients.map((client) => ({
        id: pickNumber(client, ["id", "client_id"]),
        name: pickString(client, ["name", "client_name"]),
        reference: pickString(client, ["reference", "client_reference", "ref"]),
        email: pickString(client, ["email", "main_email"]),
        phone: pickString(client, ["phone", "main_phone"]),
        ...(includeRaw ? { raw: client } : {})
      })),
      source: "halopsa"
    };
  }

  private readOptionalString(input: ConnectorConfigInput, key: string) {
    const value = input[key];
    return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
  }

  private normalizeApiUrl(value: string | undefined) {
    return value?.replace(/\/$/, "");
  }

  private normalizeHaloBaseUrl(value: string | undefined) {
    const normalized = this.normalizeApiUrl(value);
    if (!normalized) {
      return normalized;
    }

    return normalized.replace(/\/auth(?:\/authorize|\/token)?$/i, "");
  }

  private normalizeHaloRedirectUri(value: string | undefined) {
    const normalized = this.normalizeApiUrl(value);
    if (!normalized) {
      return undefined;
    }

    return normalized.endsWith("/oauth/halopsa/callback") ? normalized : `${normalized}/oauth/halopsa/callback`;
  }

  private normalizeNinjaOneBaseUrl(value: string | undefined) {
    const normalized = this.normalizeApiUrl(value);
    if (!normalized) {
      return normalized;
    }

    return normalized.replace(/\/ws\/oauth(?:\/authorize|\/token)?$/i, "");
  }

  private normalizeNinjaOneRedirectUri(value: string | undefined) {
    const normalized = this.normalizeApiUrl(value);
    if (!normalized) {
      return undefined;
    }

    return normalized.endsWith("/oauth/ninjaone/callback") ? normalized : `${normalized}/oauth/ninjaone/callback`;
  }

  private normalizeActionStepRedirectUri(value: string | undefined) {
    const normalized = this.normalizeApiUrl(value);
    if (!normalized) {
      return undefined;
    }

    return normalized.endsWith("/oauth/actionstep/callback") ? normalized : `${normalized}/oauth/actionstep/callback`;
  }

  private getDefaultActionStepScopes() {
    return (process.env.ACTIONSTEP_SCOPES ?? "actions participants tasks timeentries")
      .split(/\s+/)
      .filter(Boolean);
  }

  private getActionStepEnvironmentUrls(environment?: string) {
    const env = (environment ?? process.env.ACTIONSTEP_ENV ?? "production").toLowerCase();
    if (env === "staging") {
      return {
        authorizeUrl: "https://go.actionstepstaging.com/api/oauth/authorize",
        tokenUrl: "https://api.actionstepstaging.com/api/oauth/token"
      };
    }
    return {
      authorizeUrl: "https://go.actionstep.com/api/oauth/authorize",
      tokenUrl: "https://api.actionstep.com/api/oauth/token"
    };
  }

  private parseScopes(value: unknown, fallback: string[]) {
    if (Array.isArray(value)) {
      const scopes = value.map((item) => String(item).trim()).filter(Boolean);
      return scopes.length > 0 ? scopes : fallback;
    }

    if (typeof value === "string") {
      const scopes = value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
      return scopes.length > 0 ? scopes : fallback;
    }

    return fallback;
  }

  private getDefaultHaloScopes() {
    return (process.env.HALOPSA_SCOPES ?? "read:tickets read:customers read:actions offline_access")
      .split(/\s+/)
      .filter(Boolean);
  }

  private buildConnectorConfig(provider: ProviderName, input: ConnectorConfigInput, existing: StoredConnectorConfig = {}) {
    const rawApiUrl = this.readOptionalString(input, "apiUrl");
    const apiUrl =
      provider === "halopsa"
        ? this.normalizeHaloBaseUrl(rawApiUrl) ?? this.normalizeHaloBaseUrl(existing.apiUrl)
        : this.normalizeApiUrl(rawApiUrl) ?? existing.apiUrl;
    const clientId = this.readOptionalString(input, "clientId") ?? existing.clientId;
    const rawSecret = this.readOptionalString(input, "clientSecret");
    const clientSecretEncrypted = rawSecret ? this.encryption.encrypt(rawSecret) : existing.clientSecretEncrypted;

    switch (provider) {
      case "halopsa":
        return {
          apiUrl,
          authUrl:
            this.normalizeHaloBaseUrl(this.readOptionalString(input, "authUrl"))
            ?? this.normalizeHaloBaseUrl(existing.authUrl)
            ?? apiUrl,
          clientId,
          clientSecretEncrypted,
          redirectUri: this.normalizeHaloRedirectUri(this.readOptionalString(input, "redirectUri") ?? existing.redirectUri)
            ?? this.normalizeHaloRedirectUri(process.env.HALOPSA_REDIRECT_URI)
            ?? `${config.apiUrl}/oauth/halopsa/callback`,
          scopes: this.parseScopes(input.scopes, existing.scopes ?? this.getDefaultHaloScopes())
        } satisfies StoredConnectorConfig;
      case "ninjaone":
        return {
          apiUrl,
          authUrl:
            this.normalizeNinjaOneBaseUrl(this.readOptionalString(input, "authUrl"))
            ?? this.normalizeNinjaOneBaseUrl(existing.authUrl)
            ?? apiUrl,
          clientId,
          clientSecretEncrypted,
          redirectUri:
            this.normalizeNinjaOneRedirectUri(this.readOptionalString(input, "redirectUri") ?? existing.redirectUri)
            ?? this.normalizeNinjaOneRedirectUri(process.env.NINJAONE_REDIRECT_URI)
            ?? `${config.apiUrl}/oauth/ninjaone/callback`,
          scopes: this.parseScopes(input.scopes, existing.scopes ?? ["monitoring", "management", "control"])
        } satisfies StoredConnectorConfig;
      case "cipp":
        return {
          apiUrl,
          tenantId: this.readOptionalString(input, "tenantId") ?? existing.tenantId,
          appId: clientId,
          clientId,
          clientSecretEncrypted
        } satisfies StoredConnectorConfig;
      case "n8n":
        return {
          apiUrl,
          clientId,
          clientSecretEncrypted,
          webhookBaseUrl: this.normalizeApiUrl(this.readOptionalString(input, "redirectUri")) ?? existing.webhookBaseUrl
        } satisfies StoredConnectorConfig;
      case "actionstep":
        return {
          clientId,
          clientSecretEncrypted,
          redirectUri:
            this.normalizeActionStepRedirectUri(this.readOptionalString(input, "redirectUri") ?? existing.redirectUri)
            ?? this.normalizeActionStepRedirectUri(process.env.ACTIONSTEP_REDIRECT_URI)
            ?? `${config.apiUrl}/oauth/actionstep/callback`,
          scopes: this.parseScopes(input.scopes, existing.scopes ?? this.getDefaultActionStepScopes()),
          environment:
            this.readOptionalString(input, "environment")?.toLowerCase()
            ?? existing.environment
            ?? "production"
        } satisfies StoredConnectorConfig;
      default:
        return existing;
    }
  }

  private getHaloBaseUrlForAccount(account: ConnectedAccountRecord) {
    const metadata = (account.metadataJson ?? {}) as StoredConnectorConfig;
    const baseUrl = this.normalizeHaloBaseUrl(metadata.apiUrl ?? process.env.HALOPSA_BASE_URL ?? process.env.HALOPSA_URL);
    if (!baseUrl) {
      throw new Error("Set HaloPSA API URL in connector settings or HALOPSA_BASE_URL in the environment");
    }

    return baseUrl;
  }

  private getNinjaOneBaseUrlForAccount(account: ConnectedAccountRecord) {
    const metadata = (account.metadataJson ?? {}) as StoredConnectorConfig;
    const baseUrl = this.normalizeNinjaOneBaseUrl(metadata.apiUrl ?? process.env.NINJAONE_BASE_URL ?? process.env.NINJAONE_URL);
    if (!baseUrl) {
      throw new Error("Set NinjaOne API URL in connector settings or NINJAONE_BASE_URL in the environment");
    }

    return baseUrl;
  }

  private async resolveHaloConfig(tenantId: string) {
    const stored = ((await this.configStore.get(tenantId, "halopsa"))?.configJson ?? {}) as StoredConnectorConfig;
    const apiUrl = this.normalizeHaloBaseUrl(stored.apiUrl ?? process.env.HALOPSA_BASE_URL ?? process.env.HALOPSA_URL);
    const authUrl = this.normalizeHaloBaseUrl(stored.authUrl) ?? apiUrl;
    const clientId = stored.clientId ?? process.env.HALOPSA_CLIENT_ID;
    const clientSecret =
      stored.clientSecretEncrypted ? this.encryption.decrypt(stored.clientSecretEncrypted) : process.env.HALOPSA_CLIENT_SECRET;
    const redirectUri =
      this.normalizeHaloRedirectUri(stored.redirectUri)
      ?? this.normalizeHaloRedirectUri(process.env.HALOPSA_REDIRECT_URI)
      ?? `${config.apiUrl}/oauth/halopsa/callback`;
    const scopes = stored.scopes ?? this.getDefaultHaloScopes();

    if (!apiUrl || !authUrl || !clientId || !clientSecret) {
      throw new Error("HaloPSA requires API URL, client ID, and client secret in connector settings before connecting");
    }

    return { apiUrl, authUrl, clientId, clientSecret, redirectUri, scopes };
  }

  private async resolveN8nConfig(tenantId: string) {
    const stored = ((await this.configStore.get(tenantId, "n8n"))?.configJson ?? {}) as StoredConnectorConfig;
    const apiUrl = this.normalizeApiUrl(stored.apiUrl);
    const apiKey = stored.clientSecretEncrypted ? this.encryption.decrypt(stored.clientSecretEncrypted) : undefined;

    if (!apiUrl || !apiKey) {
      throw new Error("n8n requires API URL and bearer token/API key in connector settings");
    }

    return {
      apiUrl: apiUrl.replace(/\/$/, ""),
      apiKey
    };
  }

  private async resolveActionStepConfig(tenantId: string) {
    const stored = ((await this.configStore.get(tenantId, "actionstep"))?.configJson ?? {}) as StoredConnectorConfig;
    const clientId = stored.clientId ?? process.env.ACTIONSTEP_CLIENT_ID;
    const clientSecret = stored.clientSecretEncrypted
      ? this.encryption.decrypt(stored.clientSecretEncrypted)
      : process.env.ACTIONSTEP_CLIENT_SECRET;
    const redirectUri =
      this.normalizeActionStepRedirectUri(stored.redirectUri)
      ?? this.normalizeActionStepRedirectUri(process.env.ACTIONSTEP_REDIRECT_URI)
      ?? `${config.apiUrl}/oauth/actionstep/callback`;
    const scopes = stored.scopes ?? this.getDefaultActionStepScopes();
    const environment = stored.environment ?? process.env.ACTIONSTEP_ENV ?? "production";
    const { authorizeUrl, tokenUrl } = this.getActionStepEnvironmentUrls(environment);

    if (!clientId || !clientSecret) {
      throw new Error(
        "ActionStep requires client ID and client secret in connector settings before connecting"
      );
    }

    return { clientId, clientSecret, redirectUri, scopes, environment, authorizeUrl, tokenUrl };
  }

  private async exchangeActionStepToken(
    asConfig: { tokenUrl: string },
    params: URLSearchParams
  ) {
    const response = await fetch(asConfig.tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json"
      },
      body: params.toString()
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`ActionStep token exchange failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
      scope?: string;
      api_endpoint?: string;
      token_type?: string;
    };

    return {
      accessToken: payload.access_token,
      refreshToken: payload.refresh_token,
      expiresAt: payload.expires_in ? new Date(Date.now() + payload.expires_in * 1000) : undefined,
      scopes: payload.scope?.split(/\s+/).filter(Boolean),
      apiEndpoint: payload.api_endpoint
    };
  }

  private async resolveNinjaOneConfig(tenantId: string) {
    const stored = ((await this.configStore.get(tenantId, "ninjaone"))?.configJson ?? {}) as StoredConnectorConfig;
    const apiUrl = this.normalizeNinjaOneBaseUrl(stored.apiUrl ?? process.env.NINJAONE_BASE_URL ?? process.env.NINJAONE_URL);
    const authUrl = this.normalizeNinjaOneBaseUrl(stored.authUrl ?? process.env.NINJAONE_AUTH_URL) ?? apiUrl;
    const clientId = stored.clientId ?? process.env.NINJAONE_CLIENT_ID;
    const clientSecret =
      stored.clientSecretEncrypted ? this.encryption.decrypt(stored.clientSecretEncrypted) : process.env.NINJAONE_CLIENT_SECRET;
    const redirectUri =
      this.normalizeNinjaOneRedirectUri(stored.redirectUri)
      ?? this.normalizeNinjaOneRedirectUri(process.env.NINJAONE_REDIRECT_URI)
      ?? `${config.apiUrl}/oauth/ninjaone/callback`;
    const scopes = stored.scopes ?? (process.env.NINJAONE_SCOPES ?? "monitoring management control").split(/\s+/).filter(Boolean);

    if (!apiUrl || !authUrl || !clientId) {
      throw new Error("NinjaOne requires API URL and client ID in connector settings before connecting");
    }

    return { apiUrl, authUrl, clientId, clientSecret, redirectUri, scopes };
  }

  private async exchangeHaloToken(
    haloConfig: { apiUrl: string; authUrl: string; clientId: string; clientSecret: string; redirectUri: string; scopes: string[] },
    params: URLSearchParams
  ) {
    const response = await haloFetch(`${haloConfig.authUrl}/auth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body: params.toString(),
      bodyPreview: params.toString()
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

  private async exchangeNinjaOneToken(
    ninjaConfig: { apiUrl: string; authUrl: string; clientId: string; clientSecret?: string; redirectUri: string; scopes: string[] },
    params: URLSearchParams
  ) {
    const response = await fetch(`${ninjaConfig.authUrl}/ws/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json"
      },
      body: params.toString()
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`NinjaOne token exchange failed (${response.status}): ${body}`);
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
      scopes: payload.scope?.split(/\s+/).filter(Boolean)
    };
  }

  private async refreshHaloAccountIfNeeded(account: ConnectedAccountRecord): Promise<ConnectedAccountRecord> {
    if (!account.expiresAt || account.expiresAt.getTime() > Date.now() + 60_000) {
      return account;
    }

    if (!account.refreshTokenEncrypted) {
      throw new Error(`No refresh path configured for ${account.provider}`);
    }

    try {
      const haloConfig = await this.resolveHaloConfig(account.tenantId);
      const refreshToken = this.encryption.decrypt(account.refreshTokenEncrypted);
      const tokens = await this.exchangeHaloToken(
        haloConfig,
        new URLSearchParams({
          grant_type: "refresh_token",
          client_id: haloConfig.clientId,
          client_secret: haloConfig.clientSecret,
          refresh_token: refreshToken
        })
      );

      return {
        ...account,
        accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
        refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : account.refreshTokenEncrypted,
        expiresAt: tokens.expiresAt ?? account.expiresAt,
        status: "ACTIVE",
        lastError: undefined
      };
    } catch (error) {
      return {
        ...account,
        status: "ERROR",
        lastError: error instanceof Error ? error.message : "Unknown refresh error"
      };
    }
  }

  private async refreshNinjaOneAccountIfNeeded(account: ConnectedAccountRecord): Promise<ConnectedAccountRecord> {
    if (!account.expiresAt || account.expiresAt.getTime() > Date.now() + 60_000) {
      return account;
    }

    return this.forceRefreshNinjaOneAccount(account);
  }

  private async forceRefreshNinjaOneAccount(account: ConnectedAccountRecord): Promise<ConnectedAccountRecord> {
    if (!account.refreshTokenEncrypted) {
      return account;
    }

    try {
      const ninjaConfig = await this.resolveNinjaOneConfig(account.tenantId);
      const refreshToken = this.encryption.decrypt(account.refreshTokenEncrypted);
      const params = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: ninjaConfig.clientId,
        refresh_token: refreshToken
      });
      if (ninjaConfig.clientSecret) {
        params.set("client_secret", ninjaConfig.clientSecret);
      }

      const tokens = await this.exchangeNinjaOneToken(ninjaConfig, params);

      return {
        ...account,
        accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
        refreshTokenEncrypted: tokens.refreshToken ? this.encryption.encrypt(tokens.refreshToken) : account.refreshTokenEncrypted,
        expiresAt: tokens.expiresAt ?? account.expiresAt,
        status: "ACTIVE",
        lastError: undefined
      };
    } catch (error) {
      return {
        ...account,
        status: "ERROR",
        lastError: error instanceof Error ? error.message : "Unknown refresh error"
      };
    }
  }
}
