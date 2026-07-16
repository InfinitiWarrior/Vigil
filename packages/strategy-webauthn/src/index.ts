import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";
import { MemoryWebAuthnChallengeStore, type WebAuthnChallengeStore } from "./challenge-store.js";
import type { WebAuthnCredentialStore } from "./credential-store.js";

export { MemoryWebAuthnChallengeStore } from "./challenge-store.js";
export type { WebAuthnChallengeData, WebAuthnChallengeStore } from "./challenge-store.js";
export { MemoryWebAuthnCredentialStore } from "./credential-store.js";
export type { WebAuthnCredentialRecord, WebAuthnCredentialStore } from "./credential-store.js";

export interface WebAuthnStrategyOptions<TUser> {
  rpName: string;
  rpId: string;
  origin: string | string[];
  challengeStore?: WebAuthnChallengeStore;
  /** Defaults to 300 (5 minutes) — how long a registration/authentication challenge stays valid. */
  challengeTtlSeconds?: number;
  credentialStore: WebAuthnCredentialStore;
  verify(userId: string): Promise<AuthResult<TUser>>;
}

/** All ceremony/crypto (attestation parsing, signature verification, replay
 * counter semantics) is delegated to @simplewebauthn/server, an audited,
 * widely-used implementation — this wrapper only bridges pluggable storage
 * and adapts the result into Vigil's Strategy/AuthResult shape. */
export class WebAuthnStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "webauthn";

  private readonly options: WebAuthnStrategyOptions<TUser>;
  private readonly challengeStore: WebAuthnChallengeStore;
  private readonly challengeTtlSeconds: number | undefined;

  constructor(options: WebAuthnStrategyOptions<TUser>) {
    this.options = options;
    this.challengeStore = options.challengeStore ?? new MemoryWebAuthnChallengeStore();
    this.challengeTtlSeconds = options.challengeTtlSeconds;
  }

  async registrationOptions(
    userId: string,
    userName: string,
    userDisplayName?: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const existing = await this.options.credentialStore.list(userId);

    const options = await generateRegistrationOptions({
      rpName: this.options.rpName,
      rpID: this.options.rpId,
      userName,
      userDisplayName,
      userID: new TextEncoder().encode(userId),
      attestationType: "none",
      excludeCredentials: existing.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    });

    await this.challengeStore.set(options.challenge, { userId, createdAt: Date.now() }, this.challengeTtlSeconds);
    return options;
  }

  async registrationVerify(userId: string, response: RegistrationResponseJSON): Promise<{ verified: boolean }> {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: async (challenge) => {
        const data = await this.challengeStore.consume(challenge);
        return data?.userId === userId;
      },
      expectedOrigin: this.options.origin,
      expectedRPID: this.options.rpId,
    });

    if (!verification.verified || !verification.registrationInfo) return { verified: false };

    const { credential } = verification.registrationInfo;
    await this.options.credentialStore.save(userId, {
      id: credential.id,
      userId,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports,
    });

    return { verified: true };
  }

  /** Omit `userId` for a fully discoverable-credential (passkey) attempt,
   * where the browser prompts the user before the server knows who they are. */
  async authenticationOptions(userId?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const allowCredentials = userId
      ? (await this.options.credentialStore.list(userId)).map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        }))
      : undefined;

    const options = await generateAuthenticationOptions({
      rpID: this.options.rpId,
      allowCredentials,
      userVerification: "preferred",
    });

    await this.challengeStore.set(
      options.challenge,
      { userId: userId ?? null, createdAt: Date.now() },
      this.challengeTtlSeconds,
    );
    return options;
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const response = request.body as AuthenticationResponseJSON | undefined;
    if (!response || typeof response !== "object" || !("id" in response)) {
      return { success: false, reason: "Missing WebAuthn authentication response", status: 400 };
    }

    const credentialRecord = await this.options.credentialStore.get(response.id);
    if (!credentialRecord) return { success: false, reason: "Unknown credential", status: 401 };

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: async (challenge) => (await this.challengeStore.consume(challenge)) !== null,
        expectedOrigin: this.options.origin,
        expectedRPID: this.options.rpId,
        credential: {
          id: credentialRecord.id,
          publicKey: credentialRecord.publicKey,
          counter: credentialRecord.counter,
          transports: credentialRecord.transports,
        },
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : "WebAuthn verification failed";
      return { success: false, reason, status: 401 };
    }

    if (!verification.verified) return { success: false, reason: "WebAuthn verification failed", status: 401 };

    await this.options.credentialStore.updateCounter(credentialRecord.id, verification.authenticationInfo.newCounter);

    return this.options.verify(credentialRecord.userId);
  }
}
