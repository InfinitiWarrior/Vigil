import { createHash } from "node:crypto";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";

export type ApiKeyExtractFrom = "header" | "query" | ((request: VigilRequest) => string | undefined);

export interface ApiKeyStrategyOptions<TUser> {
  extractFrom?: ApiKeyExtractFrom;
  /** Defaults to `"x-api-key"`. */
  headerName?: string;
  /** Defaults to `"api_key"`. */
  queryName?: string;
  verify(key: string): Promise<AuthResult<TUser>>;
}

/** Deterministic lookup hash for at-rest storage — API keys are already
 * high-entropy random values, so unlike passwords a fast, indexable hash
 * (rather than bcrypt/argon2) is the right tool: store this, never the raw key. */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function extractKey(request: VigilRequest, options: ApiKeyStrategyOptions<unknown>): string | undefined {
  const mode = options.extractFrom ?? "header";

  if (typeof mode === "function") return mode(request);

  if (mode === "header") {
    const raw = request.headers[(options.headerName ?? "x-api-key").toLowerCase()];
    return Array.isArray(raw) ? raw[0] : raw;
  }

  const raw = request.query[options.queryName ?? "api_key"];
  return Array.isArray(raw) ? raw[0] : raw;
}

export class ApiKeyStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "apikey";

  private readonly options: ApiKeyStrategyOptions<TUser>;

  constructor(options: ApiKeyStrategyOptions<TUser>) {
    this.options = options;
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const key = extractKey(request, this.options);
    if (!key) return { success: false, reason: "No API key provided", status: 401 };

    return this.options.verify(key);
  }
}
