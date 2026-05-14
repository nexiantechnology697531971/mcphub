import Fastify from "fastify";
import { URLSearchParams } from "node:url";

import { buildAppConfig } from "./common/config/env";
import { ensureDatabaseSchema } from "./common/db/postgres";
import { AuditService } from "./modules/audit/audit.service";
import { AuthService } from "./modules/auth/auth.service";
import { ConnectorService } from "./modules/connectors/connector.service";
import { registerApiRoutes } from "./modules/mcp/routes";
import { ModuleService } from "./modules/modules/module.service";
import { PlatformService } from "./modules/platform/platform.service";

const config = buildAppConfig();
const app = Fastify({ logger: true });

app.addContentTypeParser(
  "application/x-www-form-urlencoded",
  { parseAs: "string" },
  (_request, body, done) => {
    try {
      const params = new URLSearchParams(typeof body === "string" ? body : body.toString("utf8"));
      const parsed = Object.fromEntries(params.entries());
      done(null, parsed);
    } catch (error) {
      done(error as Error, undefined);
    }
  }
);

const auditService = new AuditService();
const authService = new AuthService();
const moduleService = new ModuleService(auditService);
const connectorService = new ConnectorService(auditService, moduleService);
const platformService = new PlatformService(auditService);

registerApiRoutes(app, {
  authService,
  connectorService,
  auditService,
  moduleService,
  platformService,
  config
});

await ensureDatabaseSchema();
await platformService.ensureSeedData();

app.listen({ host: "0.0.0.0", port: config.port }).catch((error) => {
  app.log.error(error);
  process.exit(1);
});
