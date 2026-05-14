export type ProviderName = "halopsa" | "microsoft365" | "hubspot" | "itglue" | "ninjaone" | "cipp" | "n8n" | "actionstep";

export interface AuthContext {
  tenantId: string;
  userId: string;
  roles: string[];
}

export interface ConnectedAccountRecord {
  id: string;
  tenantId: string;
  userId: string;
  provider: ProviderName;
  providerAccountId?: string;
  accessTokenEncrypted: string;
  refreshTokenEncrypted?: string;
  expiresAt?: Date;
  scopes: string[];
  metadataJson?: Record<string, unknown>;
  status: "ACTIVE" | "EXPIRED" | "REVOKED" | "ERROR" | "DISCONNECTED";
  lastError?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TokenPair {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
  scopes?: string[];
}

export interface ToolExecutionContext extends AuthContext {
  requestId: string;
  accountId: string;
}
