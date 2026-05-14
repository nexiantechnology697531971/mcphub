import crypto from "node:crypto";

import type { FastifyReply, FastifyInstance } from "fastify";
import { z } from "zod";

import type { ProviderName } from "@nexian/core/domain/models";

import type { AuditService } from "../audit/audit.service";
import type { AuthService, PlatformAuthContext } from "../auth/auth.service";
import type { ConnectorService } from "../connectors/connector.service";
import type { ModuleService } from "../modules/module.service";
import type { PlatformService } from "../platform/platform.service";
import type { ToolPolicyService } from "../policies/tool-policy.service";

const oauthQuerySchema = z.object({
  tenantId: z.string().min(1),
  userId: z.string().min(1),
  returnTo: z.string().url().optional()
});

const oauthCallbackSchema = z.object({
  code: z.string().min(1),
  state: z.string().min(1)
});

const connectedAccountQuerySchema = z.object({
  tenantId: z.string().min(1),
  userId: z.string().min(1)
});

const disconnectSchema = z.object({
  tenantId: z.string().min(1),
  userId: z.string().min(1)
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  displayName: z.string().min(1),
  workspaceName: z.string().min(2)
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

const oauthAuthorizeQuerySchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  state: z.string().optional(),
  scope: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(["plain", "S256"]).optional()
});

const oauthTokenSchema = z.object({
  grant_type: z.enum(["authorization_code", "refresh_token"]),
  code: z.string().optional(),
  redirect_uri: z.string().url().optional(),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
  code_verifier: z.string().optional(),
  refresh_token: z.string().optional()
});

const oauthRegistrationSchema = z.object({
  redirect_uris: z.array(z.string().url()).min(1),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  scope: z.string().optional(),
  token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic", "none"]).optional(),
  client_name: z.string().min(1).optional()
});

const createTenantSchema = z.object({
  workspaceName: z.string().min(2)
});

const switchTenantSchema = z.object({
  tenantId: z.string().min(1)
});

const connectorConfigSchema = z.object({
  apiUrl: z.string().optional(),
  authUrl: z.string().optional(),
  clientId: z.string().optional(),
  clientSecret: z.string().optional(),
  redirectUri: z.string().optional(),
  scopes: z.union([z.string(), z.array(z.string())]).optional(),
  tenantId: z.string().optional(),
  environment: z.string().optional(),
  azureAgentResponsesUrl: z.string().optional(),
  azureAgentActivityUrl: z.string().optional(),
  azureAgentPrincipalId: z.string().optional(),
  azureAgentTenantId: z.string().optional(),
  azureAgentApiKey: z.string().optional()
});

const n8nExecutionsQuerySchema = z.object({
  workflowId: z.string().optional()
});

const createPlatformUserSchema = z.object({
  tenantId: z.string().min(1),
  email: z.string().email(),
  displayName: z.string().min(1),
  role: z.enum(["OWNER", "ADMIN", "ANALYST", "USER"]),
  platformRole: z.enum(["PLATFORM_OWNER", "PLATFORM_ADMIN", "PLATFORM_OPERATOR", "PLATFORM_MEMBER"]).optional(),
  temporaryPassword: z.string().min(8).optional()
});

const resetPlatformUserPasswordSchema = z.object({
  temporaryPassword: z.string().min(8).optional()
});

function parseBasicClientCredentials(authorizationHeader: string | undefined) {
  if (!authorizationHeader?.startsWith("Basic ")) {
    return undefined;
  }

  const decoded = Buffer.from(authorizationHeader.slice("Basic ".length), "base64").toString("utf8");
  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) {
    return undefined;
  }

  return {
    clientId: decoded.slice(0, separatorIndex),
    clientSecret: decoded.slice(separatorIndex + 1)
  };
}

function applyCors(reply: FastifyReply, origin: string) {
  reply.header("access-control-allow-origin", origin);
  reply.header("access-control-allow-headers", "content-type, authorization");
  reply.header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS");
  reply.header("access-control-allow-credentials", "true");
}

function parsePlatformAuth(
  authorizationHeader: string | undefined,
  authService: AuthService
): PlatformAuthContext | undefined {
  if (!authorizationHeader?.startsWith("Bearer ")) {
    return undefined;
  }

  return authService.verifyPlatformToken(authorizationHeader.slice("Bearer ".length));
}

function parseProviderParam(request: { params: unknown }) {
  return (request.params as { provider: ProviderName }).provider;
}

function hasPlatformConsoleAccess(auth: PlatformAuthContext) {
  return ["PLATFORM_OWNER", "PLATFORM_ADMIN", "PLATFORM_OPERATOR"].includes(auth.platformRole);
}

function parseCookies(cookieHeader: string | undefined) {
  return Object.fromEntries(
    (cookieHeader ?? "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separatorIndex = part.indexOf("=");
        return [part.slice(0, separatorIndex), decodeURIComponent(part.slice(separatorIndex + 1))];
      })
  );
}

function parsePlatformAuthFromRequest(
  request: { headers: { authorization?: string; cookie?: string } },
  authService: AuthService
) {
  const bearer = parsePlatformAuth(request.headers.authorization, authService);
  if (bearer) {
    return bearer;
  }

  const cookies = parseCookies(request.headers.cookie);
  if (!cookies.nexian_session) {
    return undefined;
  }

  return authService.verifyPlatformToken(cookies.nexian_session);
}

function renderAuthorizeLoginPage(apiUrl: string, query: Record<string, string | undefined>, notice?: string) {
  const encodedQuery = encodeURIComponent(JSON.stringify(query));
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Nexian Login</title>
        <style>
          body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0d1c24; color: #f3f4f6; padding: 40px; }
          .card { max-width: 460px; margin: 60px auto; background: #152733; border: 1px solid #244556; border-radius: 18px; padding: 28px; }
          input { width: 100%; padding: 12px; margin-top: 6px; margin-bottom: 14px; border-radius: 10px; border: 1px solid #355e74; background: #0f1b24; color: #fff; }
          button { background: #0ea5a4; border: 0; color: #03141c; padding: 12px 16px; border-radius: 999px; font-weight: 700; cursor: pointer; }
          .notice { background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.32); color: #fde68a; padding: 12px; border-radius: 12px; margin-bottom: 16px; }
          .muted { color: #a9bbc6; }
        </style>
      </head>
      <body>
        <div class="card">
          <p class="muted">Nexian MCP Login</p>
          <h1>Sign in to continue</h1>
          <p class="muted">Claude is requesting access to your Nexian MCP workspace.</p>
          ${notice ? `<div class="notice">${notice}</div>` : ""}
          <label>Email</label>
          <input id="email" type="email" placeholder="admin@example.com" />
          <label>Password</label>
          <input id="password" type="password" placeholder="Your platform password" />
          <button id="submit">Sign in</button>
        </div>
        <script>
          const submit = document.getElementById("submit");
          submit.addEventListener("click", async () => {
            const response = await fetch("${apiUrl}/auth/login", {
              method: "POST",
              credentials: "include",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                email: document.getElementById("email").value,
                password: document.getElementById("password").value
              })
            });

            if (!response.ok) {
              const payload = await response.json().catch(() => ({}));
              alert(payload.message || payload.error || "Could not sign in.");
              return;
            }

            const query = JSON.parse(decodeURIComponent("${encodedQuery}"));
            const params = new URLSearchParams(query);
            window.location.href = "${apiUrl}/oauth/authorize?" + params.toString();
          });
        </script>
      </body>
    </html>
  `;
}

function renderConsentPage(apiUrl: string, query: Record<string, string | undefined>, displayName: string) {
  const params = new URLSearchParams(query as Record<string, string>);
  const approveUrl = `${apiUrl}/oauth/authorize/approve?${params.toString()}`;
  const denyUrl = `${apiUrl}/oauth/authorize/deny?${params.toString()}`;

  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Nexian Consent</title>
        <style>
          body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0d1c24; color: #f3f4f6; padding: 40px; }
          .card { max-width: 560px; margin: 60px auto; background: #152733; border: 1px solid #244556; border-radius: 18px; padding: 28px; }
          .muted { color: #a9bbc6; }
          .row { display: flex; gap: 12px; margin-top: 18px; }
          .primary, .secondary { padding: 12px 16px; border-radius: 999px; text-decoration: none; font-weight: 700; }
          .primary { background: #0ea5a4; color: #03141c; }
          .secondary { border: 1px solid #355e74; color: #f3f4f6; }
          code { background: #0f1b24; padding: 2px 6px; border-radius: 8px; }
        </style>
      </head>
      <body>
        <div class="card">
          <p class="muted">Signed in as ${displayName}</p>
          <h1>Authorize Claude</h1>
          <p class="muted">Claude wants to access your Nexian MCP workspace and act using your connected tools.</p>
          <p><strong>Requested scopes:</strong> <code>${query.scope ?? "mcp"}</code></p>
          <div class="row">
            <a class="primary" href="${approveUrl}">Approve</a>
            <a class="secondary" href="${denyUrl}">Deny</a>
          </div>
        </div>
      </body>
    </html>
  `;
}

export function registerApiRoutes(
  app: FastifyInstance,
  deps: {
    authService: AuthService;
    connectorService: ConnectorService;
    auditService: AuditService;
    moduleService: ModuleService;
    toolPolicyService: ToolPolicyService;
    platformService: PlatformService;
    config: {
      apiUrl: string;
      appUrl: string;
      internalMcpSharedSecret: string;
      sessionSecret: string;
      mcpOauthClientId: string;
      mcpOauthClientSecret: string;
      mcpOauthRedirectUris: string[];
      mcpOauthScopes: string[];
    };
  }
) {
  app.addHook("onRequest", async (_request, reply) => {
    applyCors(reply, deps.config.appUrl);
  });

  app.options("/*", async (_request, reply) => {
    applyCors(reply, deps.config.appUrl);
    return reply.status(204).send();
  });

  app.get("/health", async () => ({ ok: true }));

  app.post("/auth/register", async (request, reply) => {
    const body = registerSchema.parse(request.body);
    const session = await deps.authService.register(body);
    reply.header("set-cookie", deps.authService.issueSessionCookie(session.token));
    return session;
  });

  app.post("/auth/login", async (request, reply) => {
    const body = loginSchema.parse(request.body);
    const session = await deps.authService.login(body.email, body.password);
    reply.header("set-cookie", deps.authService.issueSessionCookie(session.token));
    return session;
  });

  app.get("/auth/me", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    return deps.authService.getSession(auth);
  });

  app.get("/auth/tenants", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    return {
      tenants: await deps.authService.listUserTenants(auth)
    };
  });

  app.post("/auth/tenants", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    const body = createTenantSchema.parse(request.body);
    const session = await deps.authService.createTenantForUser(auth, body);
    reply.header("set-cookie", deps.authService.issueSessionCookie(session.token));
    return session;
  });

  app.post("/auth/switch-tenant", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const body = switchTenantSchema.parse(request.body);
    const session = await deps.authService.switchTenant(auth, body.tenantId);
    reply.header("set-cookie", deps.authService.issueSessionCookie(session.token));
    return session;
  });

  app.get("/.well-known/oauth-authorization-server", async () => ({
    issuer: deps.config.apiUrl,
    authorization_endpoint: `${deps.config.apiUrl}/oauth/authorize`,
    token_endpoint: `${deps.config.apiUrl}/oauth/token`,
    registration_endpoint: `${deps.config.apiUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    code_challenge_methods_supported: ["plain", "S256"],
    scopes_supported: deps.config.mcpOauthScopes
  }));

  app.post("/oauth/register", async (request, reply) => {
    const body = oauthRegistrationSchema.parse(request.body);
    const client = await deps.authService.registerOAuthClient({
      redirectUris: body.redirect_uris,
      grantTypes: body.grant_types,
      responseTypes: body.response_types,
      scopes: body.scope?.split(/\s+/).filter(Boolean),
      tokenEndpointAuthMethod: body.token_endpoint_auth_method,
      clientName: body.client_name
    });

    return reply.status(201).send({
      client_id: client.clientId,
      redirect_uris: client.redirectUris,
      grant_types: client.grantTypes,
      response_types: client.responseTypes,
      scope: client.scopes.join(" "),
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      client_name: client.clientName,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      ...(client.clientSecret ? { client_secret: client.clientSecret, client_secret_expires_at: 0 } : { client_secret_expires_at: 0 })
    });
  });

  app.get("/oauth/authorize", async (request, reply) => {
    const query = oauthAuthorizeQuerySchema.parse(request.query);
    const registeredClient =
      query.client_id === deps.config.mcpOauthClientId ? undefined : await deps.authService.getOAuthClient(query.client_id);

    if (query.client_id !== deps.config.mcpOauthClientId && !registeredClient) {
      return reply.status(400).send("Unknown OAuth client");
    }

    const allowedRedirectUris =
      query.client_id === deps.config.mcpOauthClientId ? deps.config.mcpOauthRedirectUris : registeredClient?.redirectUris ?? [];

    if (!allowedRedirectUris.includes(query.redirect_uri)) {
      return reply.status(400).send("Redirect URI is not allowed");
    }

    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      reply.type("text/html").send(
        renderAuthorizeLoginPage(deps.config.apiUrl, {
          response_type: query.response_type,
          client_id: query.client_id,
          redirect_uri: query.redirect_uri,
          state: query.state,
          scope: query.scope,
          code_challenge: query.code_challenge,
          code_challenge_method: query.code_challenge_method
        })
      );
      return;
    }

    reply.type("text/html").send(
      renderConsentPage(
        deps.config.apiUrl,
        {
          response_type: query.response_type,
          client_id: query.client_id,
          redirect_uri: query.redirect_uri,
          state: query.state,
          scope: query.scope,
          code_challenge: query.code_challenge,
          code_challenge_method: query.code_challenge_method
        },
        auth.displayName
      )
    );
  });

  app.get("/oauth/authorize/approve", async (request, reply) => {
    const query = oauthAuthorizeQuerySchema.parse(request.query);
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.redirect(
        `${deps.config.apiUrl}/oauth/authorize?${new URLSearchParams(query as Record<string, string>).toString()}`
      );
    }

    const scope = (query.scope ?? "mcp").split(/\s+/).filter(Boolean);
    const code = await deps.authService.createAuthorizationCode({
      clientId: query.client_id,
      userId: auth.userId,
      tenantId: auth.tenantId,
      redirectUri: query.redirect_uri,
      scope,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: query.code_challenge_method
    });

    const redirectUrl = new URL(query.redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (query.state) {
      redirectUrl.searchParams.set("state", query.state);
    }

    return reply.redirect(redirectUrl.toString());
  });

  app.get("/oauth/authorize/deny", async (request, reply) => {
    const query = oauthAuthorizeQuerySchema.parse(request.query);
    const redirectUrl = new URL(query.redirect_uri);
    redirectUrl.searchParams.set("error", "access_denied");
    if (query.state) {
      redirectUrl.searchParams.set("state", query.state);
    }
    return reply.redirect(redirectUrl.toString());
  });

  app.post("/oauth/token", async (request, reply) => {
    const body = oauthTokenSchema.parse(request.body);
    const basicCredentials = parseBasicClientCredentials(request.headers.authorization);
    const clientId = body.client_id ?? basicCredentials?.clientId;
    const clientSecret = body.client_secret ?? basicCredentials?.clientSecret;
    if (!clientId) {
      return reply.status(401).send({ error: "invalid_client" });
    }

    const registeredClient =
      clientId === deps.config.mcpOauthClientId
        ? {
            clientId: deps.config.mcpOauthClientId,
            redirectUris: deps.config.mcpOauthRedirectUris,
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: deps.config.mcpOauthScopes,
            tokenEndpointAuthMethod: "client_secret_basic",
            createdAt: new Date(0)
          }
        : await deps.authService.validateOAuthClient(clientId, clientSecret);

    if (
      !registeredClient ||
      (clientId === deps.config.mcpOauthClientId && clientSecret !== deps.config.mcpOauthClientSecret)
    ) {
      return reply.status(401).send({ error: "invalid_client" });
    }

    if (body.grant_type === "authorization_code") {
      if (!body.code || !body.redirect_uri) {
        return reply.status(400).send({ error: "invalid_request" });
      }

      const { code, user } = await deps.authService.consumeAuthorizationCode(
        body.code,
        clientId,
        body.redirect_uri
      );

      if (code.code_challenge) {
        if (!body.code_verifier) {
          return reply.status(400).send({ error: "invalid_request", error_description: "Missing code_verifier" });
        }

        const computed =
          code.code_challenge_method === "S256"
            ? crypto.createHash("sha256").update(body.code_verifier).digest("base64url")
            : body.code_verifier;

        if (computed !== code.code_challenge) {
          return reply.status(400).send({ error: "invalid_grant", error_description: "PKCE verification failed" });
        }
      }

      return {
        access_token: deps.authService.issueMcpAccessToken({
          tenantId: user.tenant_id,
          userId: user.id,
          role: user.role,
          email: user.email,
          displayName: user.display_name
        }),
        refresh_token: deps.authService.issueMcpRefreshToken({
          tenantId: user.tenant_id,
          userId: user.id,
          role: user.role,
          email: user.email,
          displayName: user.display_name
        }),
        token_type: "Bearer",
        expires_in: 3600,
        scope: code.scope.join(" ")
      };
    }

    if (!body.refresh_token) {
      return reply.status(400).send({ error: "invalid_request" });
    }

    const payload = deps.authService.verifyRefreshToken(body.refresh_token);
    return {
      access_token: deps.authService.issueMcpAccessToken({
        tenantId: payload.tenantId,
        userId: payload.userId,
        role: payload.role,
        email: payload.email,
        displayName: payload.displayName
      }),
      refresh_token: deps.authService.issueMcpRefreshToken({
        tenantId: payload.tenantId,
        userId: payload.userId,
        role: payload.role,
        email: payload.email,
        displayName: payload.displayName
      }),
      token_type: "Bearer",
      expires_in: 3600,
      scope: deps.config.mcpOauthScopes.join(" ")
    };
  });

  app.get("/providers", async (request) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    const query = connectedAccountQuerySchema.safeParse(request.query);
    return {
      providers: await deps.connectorService.getProviders(
        auth?.tenantId ?? (query.success ? query.data.tenantId : undefined),
        auth?.userId ?? (query.success ? query.data.userId : undefined)
      )
    };
  });

  app.get("/connected-accounts", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    return { accounts: await deps.connectorService.getConnectedAccounts(auth.tenantId, auth.userId) };
  });

  app.post("/oauth/:provider/url", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const provider = parseProviderParam(request);
    const body = z.object({ returnTo: z.string().url().optional() }).parse(request.body ?? {});
    const result = await deps.connectorService.beginOAuth(provider, auth.tenantId, auth.userId, body.returnTo);
    return { authorizationUrl: result.authorizationUrl };
  });

  app.get("/oauth/:provider/start", async (request, reply) => {
    const provider = parseProviderParam(request);
    const query = oauthQuerySchema.parse(request.query);
    const result = await deps.connectorService.beginOAuth(provider, query.tenantId, query.userId, query.returnTo);
    return reply.redirect(result.authorizationUrl);
  });

  app.get("/oauth/:provider/callback", async (request, reply) => {
    const provider = parseProviderParam(request);
    const query = oauthCallbackSchema.parse(request.query);
    const result = await deps.connectorService.finishOAuth(provider, query.code, query.state);
    return reply.redirect(
      `${result.returnTo}?oauth=success&provider=${provider}&tenantId=${result.tenantId}&userId=${result.userId}`
    );
  });

  app.delete("/connected-accounts/:provider", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const provider = parseProviderParam(request);
    await deps.connectorService.disconnect(provider, auth.tenantId, auth.userId);
    return { ok: true };
  });

  app.get("/connector-config/:provider", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const provider = parseProviderParam(request);
    return deps.connectorService.getConnectorConfig(auth.tenantId, provider);
  });

  app.put("/connector-config/:provider", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const provider = parseProviderParam(request);
    const body = connectorConfigSchema.parse(request.body ?? {});
    return deps.connectorService.saveConnectorConfig(auth.tenantId, auth.userId, provider, body);
  });

  app.post("/connectors/actionstep/chat", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const body = z
      .object({
        message: z.string().min(1).max(8000),
        history: z
          .array(
            z.object({
              role: z.enum(["user", "assistant", "system"]),
              content: z.string().max(8000)
            })
          )
          .max(40)
          .default([])
      })
      .parse(request.body ?? {});

    try {
      return await deps.connectorService.chatWithActionStepAgent(auth.tenantId, body.message, body.history);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not reach the ActionStep agent.";
      return reply.status(502).send({ error: "chat_failed", message });
    }
  });

  app.post("/connectors/actionstep/chat/stream", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const body = z
      .object({
        message: z.string().min(1).max(8000),
        history: z
          .array(
            z.object({
              role: z.enum(["user", "assistant", "system"]),
              content: z.string().max(8000)
            })
          )
          .max(40)
          .default([])
      })
      .parse(request.body ?? {});

    let upstream: Response;
    try {
      upstream = await deps.connectorService.streamAgentChat(auth.tenantId, body.message, body.history);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not reach the ActionStep agent.";
      return reply.status(502).send({ error: "chat_failed", message });
    }

    if (!upstream.body) {
      return reply.status(502).send({ error: "chat_failed", message: "Empty stream from agent." });
    }

    reply.hijack();
    const raw = reply.raw;
    raw.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no"
    });
    raw.flushHeaders?.();

    const reader = upstream.body.getReader();
    const close = () => {
      try {
        raw.end();
      } catch {
        /* already closed */
      }
    };
    raw.on("close", () => {
      void reader.cancel().catch(() => undefined);
    });

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) raw.write(value);
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : "stream error";
      raw.write(`event: error\ndata: ${JSON.stringify({ message: detail })}\n\n`);
    } finally {
      close();
    }
  });

  app.get("/connectors/n8n/workflows", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    return {
      workflows: await deps.connectorService.listN8nWorkflows(auth.tenantId)
    };
  });

  app.get("/connectors/n8n/executions", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const query = n8nExecutionsQuerySchema.parse(request.query ?? {});
    return {
      executions: await deps.connectorService.listN8nExecutions(auth.tenantId, query.workflowId)
    };
  });

  app.post("/auth/mcp-token", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    return { token: deps.connectorService.issueMcpToken(auth.tenantId, auth.userId, [auth.role]) };
  });

  app.post("/internal/mcp/tools/call", async (request, reply) => {
    const secret = request.headers["x-internal-mcp-secret"];
    if (secret !== deps.config.internalMcpSharedSecret) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const body = z
      .object({
        tenantId: z.string().min(1),
        userId: z.string().min(1),
        roles: z.array(z.string()).default(["ADMIN"]),
        name: z.string().min(1),
        arguments: z.record(z.unknown()).default({})
      })
      .parse(request.body);

    const result = await deps.connectorService.executeTool(
      body.tenantId,
      body.userId,
      body.roles,
      body.name,
      body.arguments
    );

    return { result };
  });

  app.get("/internal/mcp/tool-policies", async (request, reply) => {
    const secret = request.headers["x-internal-mcp-secret"];
    if (secret !== deps.config.internalMcpSharedSecret) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const query = z.object({ tenantId: z.string().min(1) }).parse(request.query);
    const disabled = await deps.toolPolicyService.getDisabledToolsForTenant(query.tenantId);
    return { disabledTools: [...disabled] };
  });

  app.get("/tool-policies", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const [providers, policies] = await Promise.all([
      deps.connectorService.getProviders(auth.tenantId, auth.userId),
      deps.toolPolicyService.listForTenant(auth.tenantId)
    ]);
    const policyByTool = new Map(policies.map((p) => [p.toolName, p]));

    const tools = providers.flatMap((provider) =>
      (provider.toolDefinitions ?? []).map((tool) => {
        const policy = policyByTool.get(tool.name);
        return {
          provider: provider.displayName,
          name: tool.name,
          description: tool.description ?? "",
          enabled: policy ? policy.enabled : true,
          isOverride: Boolean(policy),
          updatedAt: policy?.updatedAt
        };
      })
    );

    return { tools };
  });

  app.put("/tool-policies/:toolName", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const params = z.object({ toolName: z.string().min(1) }).parse(request.params);
    const body = z.object({ enabled: z.boolean() }).parse(request.body);

    const policy = await deps.toolPolicyService.setToolEnabled({
      actorTenantId: auth.tenantId,
      actorUserId: auth.userId,
      tenantId: auth.tenantId,
      toolName: params.toolName,
      enabled: body.enabled
    });
    return { policy };
  });

  app.delete("/tool-policies/:toolName", async (request, reply) => {
    const auth = parsePlatformAuth(request.headers.authorization, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const params = z.object({ toolName: z.string().min(1) }).parse(request.params);
    await deps.toolPolicyService.clearTool({
      actorTenantId: auth.tenantId,
      actorUserId: auth.userId,
      tenantId: auth.tenantId,
      toolName: params.toolName
    });
    return reply.status(204).send();
  });

  app.get("/platform/overview", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    return deps.platformService.getOverview();
  });

  app.get("/platform/tenants", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    return {
      tenants: await deps.platformService.listTenants()
    };
  });

  app.get("/platform/tenants/:tenantId", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    const { tenantId } = request.params as { tenantId: string };
    const detail = await deps.platformService.getTenantDetail(tenantId);

    if (!detail) {
      return reply.status(404).send({ error: "not_found" });
    }

    return detail;
  });

  app.get("/platform/users", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    return {
      users: await deps.platformService.listUsers()
    };
  });

  app.post("/platform/users", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    const body = createPlatformUserSchema.parse(request.body);
    return deps.platformService.createUser(body);
  });

  app.post("/platform/users/:userId/reset-password", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    const { userId } = request.params as { userId: string };
    const body = resetPlatformUserPasswordSchema.parse(request.body ?? {});
    return deps.platformService.resetUserPassword({
      actorTenantId: auth.tenantId,
      actorUserId: auth.userId,
      userId,
      temporaryPassword: body.temporaryPassword
    });
  });

  app.get("/platform/connectors", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    return {
      connectors: await deps.platformService.getConnectorSummary()
    };
  });

  app.get("/platform/audit", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) {
      return reply.status(401).send({ error: "unauthorized" });
    }
    if (!hasPlatformConsoleAccess(auth)) {
      return reply.status(403).send({ error: "forbidden" });
    }

    const query = z
      .object({
        tenantId: z.string().optional(),
        limit: z.coerce.number().int().positive().max(100).optional()
      })
      .safeParse(request.query);

    return {
      events: await deps.auditService.listRecent(
        query.success ? { tenantId: query.data.tenantId, limit: query.data.limit } : undefined
      )
    };
  });

  app.get("/platform/modules", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });
    return { modules: await deps.moduleService.listModules() };
  });

  app.post("/platform/modules", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const body = z
      .object({
        name: z.string().min(1),
        description: z.string().optional(),
        enabledByDefault: z.boolean().optional(),
        slug: z.string().optional()
      })
      .parse(request.body);

    return {
      module: await deps.moduleService.createModule({
        actorTenantId: auth.tenantId,
        actorUserId: auth.userId,
        ...body
      })
    };
  });

  app.patch("/platform/modules/:moduleId", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { moduleId } = z.object({ moduleId: z.string().min(1) }).parse(request.params);
    const body = z
      .object({
        name: z.string().min(1).optional(),
        description: z.string().nullable().optional(),
        enabledByDefault: z.boolean().optional()
      })
      .parse(request.body);

    return {
      module: await deps.moduleService.updateModule(moduleId, {
        actorTenantId: auth.tenantId,
        actorUserId: auth.userId,
        ...body
      })
    };
  });

  app.delete("/platform/modules/:moduleId", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { moduleId } = z.object({ moduleId: z.string().min(1) }).parse(request.params);
    await deps.moduleService.deleteModule({
      actorTenantId: auth.tenantId,
      actorUserId: auth.userId,
      id: moduleId
    });
    return { ok: true };
  });

  app.put("/platform/modules/:moduleId/connectors", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { moduleId } = z.object({ moduleId: z.string().min(1) }).parse(request.params);
    const body = z.object({ providers: z.array(z.string()) }).parse(request.body);

    return {
      module: await deps.moduleService.setModuleConnectors({
        actorTenantId: auth.tenantId,
        actorUserId: auth.userId,
        moduleId,
        providers: body.providers
      })
    };
  });

  app.get("/platform/tenants/:tenantId/modules", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { tenantId } = z.object({ tenantId: z.string().min(1) }).parse(request.params);
    return { modules: await deps.moduleService.listTenantModuleAssignments(tenantId) };
  });

  app.put("/platform/tenants/:tenantId/modules/:moduleId", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { tenantId, moduleId } = z
      .object({ tenantId: z.string().min(1), moduleId: z.string().min(1) })
      .parse(request.params);
    const body = z.object({ enabled: z.boolean() }).parse(request.body);

    return {
      modules: await deps.moduleService.setTenantModuleEnabled({
        actorTenantId: auth.tenantId,
        actorUserId: auth.userId,
        tenantId,
        moduleId,
        enabled: body.enabled
      })
    };
  });

  app.delete("/platform/tenants/:tenantId/modules/:moduleId", async (request, reply) => {
    const auth = parsePlatformAuthFromRequest(request, deps.authService);
    if (!auth) return reply.status(401).send({ error: "unauthorized" });
    if (!hasPlatformConsoleAccess(auth)) return reply.status(403).send({ error: "forbidden" });

    const { tenantId, moduleId } = z
      .object({ tenantId: z.string().min(1), moduleId: z.string().min(1) })
      .parse(request.params);

    return {
      modules: await deps.moduleService.clearTenantModuleOverride({
        actorTenantId: auth.tenantId,
        actorUserId: auth.userId,
        tenantId,
        moduleId
      })
    };
  });
}
