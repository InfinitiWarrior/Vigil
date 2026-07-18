import { createHash } from "node:crypto";
import { generateToken } from "@vigil/core";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";
import { MemoryMagicLinkTokenStore, type MagicLinkTokenStore } from "./token-store.js";

export { MemoryMagicLinkTokenStore, createMemoryMagicLinkTokenStore } from "./token-store.js";
export type { MagicLinkTokenData, MagicLinkTokenStore } from "./token-store.js";

export interface MagicLinkStrategyOptions<TUser> {
  tokenStore?: MagicLinkTokenStore;
  /** Defaults to 600 (10 minutes). */
  tokenTtlSeconds?: number;
  /** Defaults to `"email"`, read from the request body in `sendToken`. */
  identifierField?: string;
  /** Defaults to `"token"`, read from the query string or body in `authenticate`. */
  tokenField?: string;
  /** Builds the clickable URL embedding the raw token — e.g. `${baseUrl}?token=${token}`. */
  buildUrl(token: string, request: VigilRequest<TUser>): string;
  /** Deliver the link (send the email); the strategy never sends email itself. */
  sendLink(identifier: string, url: string, token: string, request: VigilRequest<TUser>): Promise<void>;
  verify(identifier: string): Promise<AuthResult<TUser>>;
}

function readField(request: VigilRequest, field: string): string | undefined {
  const body =
    typeof request.body === "object" && request.body !== null ? (request.body as Record<string, unknown>) : {};
  const fromBody = body[field];
  if (typeof fromBody === "string") return fromBody;

  const fromQuery = request.query[field];
  if (typeof fromQuery === "string") return fromQuery;
  if (Array.isArray(fromQuery) && fromQuery.length > 0) return fromQuery[0];

  return undefined;
}

/** Tokens are secrets — only their hash is ever persisted, so a leaked store
 * doesn't hand out working sign-in links. */
function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class MagicLinkStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "magic-link";

  private readonly options: MagicLinkStrategyOptions<TUser>;
  private readonly tokenStore: MagicLinkTokenStore;
  private readonly identifierField: string;
  private readonly tokenField: string;

  constructor(options: MagicLinkStrategyOptions<TUser>) {
    this.options = options;
    this.tokenStore = options.tokenStore ?? new MemoryMagicLinkTokenStore();
    this.identifierField = options.identifierField ?? "email";
    this.tokenField = options.tokenField ?? "token";
  }

  /** Generates a token, stores its hash, and hands the raw token to `sendLink`
   * for delivery. Not part of the `Strategy` contract — call it directly from
   * the app's own "request a link" route, separately from `authenticate`. */
  async sendToken(request: VigilRequest<TUser>): Promise<void> {
    const identifier = readField(request, this.identifierField);
    if (!identifier) throw new Error(`Missing "${this.identifierField}"`);

    const token = generateToken(32, "base64url");
    await this.tokenStore.set(hashToken(token), { identifier, createdAt: Date.now() }, this.options.tokenTtlSeconds);

    const url = this.options.buildUrl(token, request);
    await this.options.sendLink(identifier, url, token, request);
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const token = readField(request, this.tokenField);
    if (!token) return { success: false, reason: "Missing token", status: 400 };

    const data = await this.tokenStore.consume(hashToken(token));
    if (!data) return { success: false, reason: "Invalid or expired token", status: 400 };

    return this.options.verify(data.identifier);
  }
}
