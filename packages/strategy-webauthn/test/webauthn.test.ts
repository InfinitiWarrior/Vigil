import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { MemoryWebAuthnCredentialStore, WebAuthnStrategy } from "@vigil/strategy-webauthn";

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

const baseRequest = {
  method: "POST",
  url: "/webauthn/authenticate",
  path: "/webauthn/authenticate",
  headers: {},
  cookies: {},
  query: {},
} as const;

function makeStrategy(credentialStore = new MemoryWebAuthnCredentialStore()) {
  const strategy = new WebAuthnStrategy<{ id: string }>({
    rpName: "Vigil Test",
    rpId: "app.example",
    origin: "https://app.example",
    credentialStore,
    verify: async (userId) => ({ success: true, user: { id: userId } }),
  });
  return { strategy, credentialStore };
}

describe("WebAuthnStrategy.registrationOptions", () => {
  beforeEach(() => vi.clearAllMocks());

  it("stores the issued challenge against the userId and excludes existing credentials", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", {
      id: "cred-existing",
      userId: "user-1",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: ["internal"],
    });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(generateRegistrationOptions).mockResolvedValue({
      challenge: "reg-challenge-1",
    } as Awaited<ReturnType<typeof generateRegistrationOptions>>);

    const options = await strategy.registrationOptions("user-1", "alice@example.com", "Alice");

    expect(options.challenge).toBe("reg-challenge-1");
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        rpName: "Vigil Test",
        rpID: "app.example",
        userName: "alice@example.com",
        userDisplayName: "Alice",
        excludeCredentials: [{ id: "cred-existing", transports: ["internal"] }],
      }),
    );
  });
});

describe("WebAuthnStrategy.registrationVerify", () => {
  beforeEach(() => vi.clearAllMocks());

  it("saves the credential when verification succeeds and the challenge matches the userId", async () => {
    const { strategy, credentialStore } = makeStrategy();

    vi.mocked(generateRegistrationOptions).mockResolvedValue({
      challenge: "reg-challenge-1",
    } as Awaited<ReturnType<typeof generateRegistrationOptions>>);
    await strategy.registrationOptions("user-1", "alice@example.com");

    vi.mocked(verifyRegistrationResponse).mockImplementation(async (opts) => {
      const matches = await (opts.expectedChallenge as (c: string) => Promise<boolean>)("reg-challenge-1");
      return {
        verified: matches,
        registrationInfo: matches
          ? {
              credential: { id: "cred-1", publicKey: new Uint8Array([9, 9, 9]), counter: 0, transports: ["internal"] },
            }
          : undefined,
      } as Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    });

    const result = await strategy.registrationVerify("user-1", {} as never);
    expect(result).toEqual({ verified: true });
    expect(await credentialStore.get("cred-1")).toMatchObject({ userId: "user-1", counter: 0 });
  });

  it("rejects when the challenge was issued for a different user", async () => {
    const { strategy, credentialStore } = makeStrategy();

    vi.mocked(generateRegistrationOptions).mockResolvedValue({
      challenge: "reg-challenge-1",
    } as Awaited<ReturnType<typeof generateRegistrationOptions>>);
    await strategy.registrationOptions("user-1", "alice@example.com");

    vi.mocked(verifyRegistrationResponse).mockImplementation(async (opts) => {
      const matches = await (opts.expectedChallenge as (c: string) => Promise<boolean>)("reg-challenge-1");
      return { verified: matches } as Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    });

    // A different user (user-2) attempts to complete user-1's registration challenge.
    const result = await strategy.registrationVerify("user-2", {} as never);
    expect(result).toEqual({ verified: false });
    expect(await credentialStore.get("cred-1")).toBeNull();
  });

  it("does not save a credential when the library reports verification failure", async () => {
    const { strategy, credentialStore } = makeStrategy();
    vi.mocked(verifyRegistrationResponse).mockResolvedValue({
      verified: false,
    } as Awaited<ReturnType<typeof verifyRegistrationResponse>>);

    const result = await strategy.registrationVerify("user-1", {} as never);
    expect(result).toEqual({ verified: false });
    expect(await credentialStore.list("user-1")).toEqual([]);
  });
});

describe("WebAuthnStrategy.authenticationOptions", () => {
  beforeEach(() => vi.clearAllMocks());

  it("scopes allowCredentials to the given userId", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", {
      id: "cred-1",
      userId: "user-1",
      publicKey: new Uint8Array(),
      counter: 0,
      transports: ["usb"],
    });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(generateAuthenticationOptions).mockResolvedValue({
      challenge: "auth-challenge-1",
    } as Awaited<ReturnType<typeof generateAuthenticationOptions>>);

    await strategy.authenticationOptions("user-1");
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({ allowCredentials: [{ id: "cred-1", transports: ["usb"] }] }),
    );
  });

  it("omits allowCredentials for a discoverable-credential (passkey) attempt", async () => {
    const { strategy } = makeStrategy();
    vi.mocked(generateAuthenticationOptions).mockResolvedValue({
      challenge: "auth-challenge-2",
    } as Awaited<ReturnType<typeof generateAuthenticationOptions>>);

    await strategy.authenticationOptions();
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({ allowCredentials: undefined }),
    );
  });
});

describe("WebAuthnStrategy.authenticate", () => {
  beforeEach(() => vi.clearAllMocks());

  it("rejects a request with no WebAuthn response body", async () => {
    const { strategy } = makeStrategy();
    const result = await strategy.authenticate({ ...baseRequest, body: {} });
    expect(result).toMatchObject({ success: false, status: 400 });
  });

  it("rejects an unknown credential id", async () => {
    const { strategy } = makeStrategy();
    const result = await strategy.authenticate({ ...baseRequest, body: { id: "never-registered" } });
    expect(result).toMatchObject({ success: false, reason: "Unknown credential", status: 401 });
  });

  it("verifies, updates the counter, and calls verify() on success", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", {
      id: "cred-1",
      userId: "user-1",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 4,
      transports: ["internal"],
    });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(generateAuthenticationOptions).mockResolvedValue({
      challenge: "auth-challenge-1",
    } as Awaited<ReturnType<typeof generateAuthenticationOptions>>);
    await strategy.authenticationOptions("user-1");

    vi.mocked(verifyAuthenticationResponse).mockImplementation(async (opts) => {
      const valid = await (opts.expectedChallenge as (c: string) => Promise<boolean>)("auth-challenge-1");
      return {
        verified: valid,
        authenticationInfo: { newCounter: 5 },
      } as Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    });

    const result = await strategy.authenticate({ ...baseRequest, body: { id: "cred-1" } });
    expect(result).toEqual({ success: true, user: { id: "user-1" } });
    expect((await credentialStore.get("cred-1"))?.counter).toBe(5);
  });

  it("enforces single-use challenges — a replayed assertion is rejected", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", {
      id: "cred-1",
      userId: "user-1",
      publicKey: new Uint8Array(),
      counter: 0,
    });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(generateAuthenticationOptions).mockResolvedValue({
      challenge: "auth-challenge-1",
    } as Awaited<ReturnType<typeof generateAuthenticationOptions>>);
    await strategy.authenticationOptions("user-1");

    vi.mocked(verifyAuthenticationResponse).mockImplementation(async (opts) => {
      const valid = await (opts.expectedChallenge as (c: string) => Promise<boolean>)("auth-challenge-1");
      return { verified: valid, authenticationInfo: { newCounter: 1 } } as Awaited<
        ReturnType<typeof verifyAuthenticationResponse>
      >;
    });

    const first = await strategy.authenticate({ ...baseRequest, body: { id: "cred-1" } });
    expect(first).toMatchObject({ success: true });

    const second = await strategy.authenticate({ ...baseRequest, body: { id: "cred-1" } });
    expect(second).toMatchObject({ success: false, status: 401 });
  });

  it("does not update the counter when verification fails", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", { id: "cred-1", userId: "user-1", publicKey: new Uint8Array(), counter: 2 });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
      verified: false,
      authenticationInfo: { newCounter: 99 },
    } as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    const result = await strategy.authenticate({ ...baseRequest, body: { id: "cred-1" } });
    expect(result).toMatchObject({ success: false, status: 401 });
    expect((await credentialStore.get("cred-1"))?.counter).toBe(2);
  });

  it("converts a thrown verification error into a failure result", async () => {
    const credentialStore = new MemoryWebAuthnCredentialStore();
    await credentialStore.save("user-1", { id: "cred-1", userId: "user-1", publicKey: new Uint8Array(), counter: 0 });
    const { strategy } = makeStrategy(credentialStore);

    vi.mocked(verifyAuthenticationResponse).mockRejectedValue(new Error("Signature verification failed"));

    const result = await strategy.authenticate({ ...baseRequest, body: { id: "cred-1" } });
    expect(result).toEqual({ success: false, reason: "Signature verification failed", status: 401 });
  });
});
