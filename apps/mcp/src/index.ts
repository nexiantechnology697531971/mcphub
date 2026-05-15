import crypto from "node:crypto";

import Fastify from "fastify";

import { getProviderRegistry } from "@nexian/connectors";
import type { AuthContext } from "@nexian/core/domain/models";
import type { NormalizedToolResponse } from "@nexian/core/mcp/tools";

import { parseBearerToken } from "./auth/bearer";
import { buildToolCatalog } from "./tools/catalog";
import {
  initializeParamsSchema,
  jsonRpcError,
  jsonRpcRequestSchema,
  jsonRpcResult,
  toolsCallParamsSchema,
  toolsListParamsSchema
} from "./transport/http";

const app = Fastify({ logger: true });
const jwtSecret = process.env.SESSION_SECRET ?? "local-session-secret";
const authMode = process.env.MCP_AUTH_MODE ?? "required";
const providers = getProviderRegistry();
const toolCatalog = buildToolCatalog();
const sessionAuth = new Map<string, AuthContext>();
const heartbeatTimers = new WeakMap<NodeJS.WritableStream, NodeJS.Timeout>();

function getDefaultAuthContext(): AuthContext {
  return {
    tenantId: process.env.MCP_DEFAULT_TENANT_ID ?? "demo-tenant",
    userId: process.env.MCP_DEFAULT_USER_ID ?? "demo-user",
    roles: (process.env.MCP_DEFAULT_ROLES ?? "ADMIN")
      .split(",")
      .map((role) => role.trim())
      .filter(Boolean)
  };
}

function applyUnauthorized(reply: { code: (statusCode: number) => unknown; header: (name: string, value: string) => unknown }) {
  const metadataUrl = `${process.env.MCP_URL ?? "http://localhost:4100"}/.well-known/oauth-protected-resource`;
  reply.header(
    "WWW-Authenticate",
    `Bearer resource_metadata="${metadataUrl}", error="invalid_token", error_description="Bearer token required"`
  );
  reply.code(401);
}

function getAuthContext(
  authorization: string | undefined,
  reply?: { code: (statusCode: number) => unknown; header: (name: string, value: string) => unknown }
): AuthContext {
  if (authorization?.startsWith("Bearer ")) {
    return parseBearerToken(authorization, jwtSecret);
  }

  if (authMode === "required") {
    if (reply) {
      applyUnauthorized(reply);
    }
    throw new Error("Missing bearer token");
  }

  return getDefaultAuthContext();
}

async function executeTool(auth: AuthContext, name: string, input: Record<string, unknown>) {
  const response = await fetch(`${process.env.API_URL ?? "http://localhost:4000"}/internal/mcp/tools/call`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-internal-mcp-secret": process.env.INTERNAL_MCP_SHARED_SECRET ?? jwtSecret
    },
    body: JSON.stringify({
      tenantId: auth.tenantId,
      userId: auth.userId,
      roles: auth.roles,
      name,
      arguments: input
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`API tool execution failed (${response.status}): ${body}`);
  }

  const payload = (await response.json()) as { result: NormalizedToolResponse };
  return payload.result;
}

async function getDisabledToolsForTenant(tenantId: string): Promise<Set<string>> {
  try {
    const response = await fetch(
      `${process.env.API_URL ?? "http://localhost:4000"}/internal/mcp/tool-policies?tenantId=${encodeURIComponent(tenantId)}`,
      {
        headers: {
          "x-internal-mcp-secret": process.env.INTERNAL_MCP_SHARED_SECRET ?? jwtSecret
        }
      }
    );
    if (!response.ok) return new Set();
    const payload = (await response.json()) as { disabledTools: string[] };
    return new Set(payload.disabledTools ?? []);
  } catch (error) {
    app.log.warn({ err: error }, "Failed to fetch tool policies — exposing full catalog");
    return new Set();
  }
}

const MAX_TOOL_TEXT_BYTES = 200_000;

function buildToolCallResult(output: NormalizedToolResponse) {
  let body = "";
  if (output.data.length > 0) {
    const full = JSON.stringify(output.data, null, 2);
    if (full.length <= MAX_TOOL_TEXT_BYTES) {
      body = `\n\n${full}`;
    } else {
      // Result set too large to inline in full — emit as many records as fit
      // and tell the model the rest are available via structuredContent so it
      // does NOT make a second tool call to "paginate".
      const records: string[] = [];
      let used = 0;
      let included = 0;
      for (const record of output.data) {
        const serialized = JSON.stringify(record, null, 2);
        if (used + serialized.length + 2 > MAX_TOOL_TEXT_BYTES) break;
        records.push(serialized);
        used += serialized.length + 2;
        included += 1;
      }
      const remaining = output.data.length - included;
      body = `\n\n[${included} of ${output.data.length} records shown inline; the remaining ${remaining} are in structuredContent.data — DO NOT call this tool again to fetch them]\n\n[${records.join(",\n")}]`;
    }
  }

  return {
    content: [
      {
        type: "text",
        text: `${output.summary}${body}`
      }
    ],
    structuredContent: output,
    isError: false
  };
}

function registerMcpHttpEndpoint(path: string) {
  app.get(path, async (request, reply) => {
    try {
      getAuthContext(request.headers.authorization, reply);
    } catch (error) {
      if (reply.statusCode === 401) {
        return reply.send({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: "Unauthorized"
          }
        });
      }
      throw error;
    }

    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive"
    });
    reply.raw.write(": connected\n\n");

    const timer = setInterval(() => {
      reply.raw.write(": ping\n\n");
    }, 15000);

    heartbeatTimers.set(reply.raw, timer);

    request.raw.on("close", () => {
      const activeTimer = heartbeatTimers.get(reply.raw);
      if (activeTimer) {
        clearInterval(activeTimer);
      }
      heartbeatTimers.delete(reply.raw);
    });

    return reply.hijack();
  });

  app.post(path, async (request, reply) => {
    const parsed = jsonRpcRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send(jsonRpcError(undefined, -32600, "Invalid Request", parsed.error.flatten()));
    }

    const rpc = parsed.data;

    try {
      if (rpc.method === "initialize") {
        const auth = getAuthContext(request.headers.authorization, reply);
        const params = initializeParamsSchema.parse(rpc.params ?? {});
        const sessionId = crypto.randomUUID();
        sessionAuth.set(sessionId, auth);
        reply.header("Mcp-Session-Id", sessionId);

        return reply.send(
          jsonRpcResult(rpc.id, {
            protocolVersion: params.protocolVersion ?? "2025-03-26",
            capabilities: {
              tools: {}
            },
            serverInfo: {
              name: "nexian-mcp-hub",
              version: "0.1.0"
            }
          })
        );
      }

      const auth = getAuthContext(request.headers.authorization, reply);

      if (rpc.method === "notifications/initialized") {
        return reply.status(202).send();
      }

      if (rpc.method === "ping") {
        return reply.send(jsonRpcResult(rpc.id, {}));
      }

      if (rpc.method === "tools/list") {
        toolsListParamsSchema.parse(rpc.params ?? {});
        const disabled = await getDisabledToolsForTenant(auth.tenantId);
        const filteredCatalog = disabled.size === 0 ? toolCatalog : toolCatalog.filter((tool) => !disabled.has(tool.name));
        return reply.send(
          jsonRpcResult(rpc.id, {
            tools: filteredCatalog
          })
        );
      }

      if (rpc.method === "tools/call") {
        const params = toolsCallParamsSchema.parse(rpc.params ?? {});
        const output = await executeTool(auth, params.name, params.arguments ?? {});
        return reply.send(jsonRpcResult(rpc.id, buildToolCallResult(output)));
      }

      return reply.status(404).send(jsonRpcError(rpc.id, -32601, `Method not found: ${rpc.method}`));
    } catch (error) {
      request.log.error(error);
      const message = error instanceof Error ? error.message : "Unexpected MCP server error";
      return reply.status(500).send(jsonRpcError(rpc.id, -32000, message));
    }
  });
}

app.get("/health", async () => ({ ok: true }));

app.get("/.well-known/oauth-protected-resource", async () => ({
  resource: process.env.MCP_URL ?? "http://localhost:4100",
  authorization_servers: [process.env.API_URL ?? "http://localhost:4000"]
}));

registerMcpHttpEndpoint("/");
registerMcpHttpEndpoint("/mcp");
registerMcpHttpEndpoint("/invoke");

app.listen({ host: "0.0.0.0", port: Number(process.env.PORT ?? process.env.MCP_PORT ?? 4100) }).catch((error) => {
  app.log.error(error);
  process.exit(1);
});
