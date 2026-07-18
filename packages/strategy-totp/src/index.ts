import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";
import { buildOtpauthUrl, generateTotpSecret, verifyTotpCode, verifyTotpCodeStep, type TotpAlgorithm } from "./totp.js";
import type { TotpSecretStore } from "./secret-store.js";

export { base32Decode, base32Encode } from "./base32.js";
export { buildOtpauthUrl, generateTotpCode, generateTotpSecret, verifyTotpCode, verifyTotpCodeStep } from "./totp.js";
export type { TotpAlgorithm, TotpOptions } from "./totp.js";
export { MemoryTotpSecretStore } from "./secret-store.js";
export type { TotpSecretStore } from "./secret-store.js";

export interface TotpStrategyOptions<TUser> {
  issuer: string;
  /** Defaults to 6. */
  digits?: number;
  /** Step size in seconds. Defaults to 30. */
  period?: number;
  /** Accepted drift, in periods either side of the current one. Defaults to 1. */
  window?: number;
  algorithm?: TotpAlgorithm;
  secretStore: TotpSecretStore;
  /** Defaults to `"code"`, read from the request body. */
  codeField?: string;
  /** Resolves the userId of the already-partially-authenticated principal
   * completing second-factor verification. Defaults to `request.user.id`. */
  identify?(request: VigilRequest<TUser>): Promise<string | null> | string | null;
  verify(userId: string): Promise<AuthResult<TUser>>;
}

function defaultIdentify<TUser>(request: VigilRequest<TUser>): string | null {
  const user = request.user as { id?: string } | null | undefined;
  return user?.id ?? null;
}

function readCode(request: VigilRequest, field: string): string | undefined {
  const body =
    typeof request.body === "object" && request.body !== null ? (request.body as Record<string, unknown>) : {};
  const value = body[field];
  return typeof value === "string" ? value : undefined;
}

export class TotpStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "totp";

  private readonly options: TotpStrategyOptions<TUser>;
  private readonly codeField: string;

  constructor(options: TotpStrategyOptions<TUser>) {
    this.options = options;
    this.codeField = options.codeField ?? "code";
  }

  /** Returns a fresh secret plus its otpauth:// provisioning URI for a QR code.
   * The app holds the secret (e.g. in its own session) until `verifySetup`
   * confirms the user scanned it correctly, then persists it via `secretStore`. */
  generateSecret(accountName: string): { secret: string; otpauthUrl: string } {
    const secret = generateTotpSecret();
    const otpauthUrl = buildOtpauthUrl({
      secret,
      accountName,
      issuer: this.options.issuer,
      digits: this.options.digits,
      period: this.options.period,
      algorithm: this.options.algorithm,
    });
    return { secret, otpauthUrl };
  }

  verifySetup(secret: string, code: string): boolean {
    return verifyTotpCode(secret, code, {
      digits: this.options.digits,
      period: this.options.period,
      window: this.options.window,
      algorithm: this.options.algorithm,
    });
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const identify = this.options.identify ?? defaultIdentify;
    const userId = await identify(request);
    if (!userId) return { success: false, reason: "Not authenticated", status: 401 };

    const code = readCode(request, this.codeField);
    if (!code) return { success: false, reason: "Missing TOTP code", status: 400 };

    const secret = await this.options.secretStore.get(userId);
    if (!secret) return { success: false, reason: "TOTP not configured", status: 400 };

    const step = verifyTotpCodeStep(secret, code, {
      digits: this.options.digits,
      period: this.options.period,
      window: this.options.window,
      algorithm: this.options.algorithm,
    });
    if (step === null) return { success: false, reason: "Invalid code", status: 401 };

    const lastUsedStep = await this.options.secretStore.getLastUsedStep(userId);
    if (lastUsedStep !== null && step <= lastUsedStep) {
      return { success: false, reason: "Code already used", status: 401 };
    }
    await this.options.secretStore.setLastUsedStep(userId, step);

    return this.options.verify(userId);
  }
}
