import type { AuthenticatorTransportFuture, Uint8Array_ } from "@simplewebauthn/server";

export interface WebAuthnCredentialRecord {
  /** Base64url credential ID. */
  id: string;
  userId: string;
  publicKey: Uint8Array_;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
}

export interface WebAuthnCredentialStore {
  get(credentialId: string): Promise<WebAuthnCredentialRecord | null>;
  save(userId: string, credential: WebAuthnCredentialRecord): Promise<void>;
  list(userId: string): Promise<WebAuthnCredentialRecord[]>;
  updateCounter(credentialId: string, counter: number): Promise<void>;
}

/** In-memory credential store for local development and tests. Passkey
 * credentials are long-lived and security-relevant — production deployments
 * must implement WebAuthnCredentialStore against a real database. */
export class MemoryWebAuthnCredentialStore implements WebAuthnCredentialStore {
  private readonly byId = new Map<string, WebAuthnCredentialRecord>();
  private readonly byUser = new Map<string, Set<string>>();

  async get(credentialId: string): Promise<WebAuthnCredentialRecord | null> {
    return this.byId.get(credentialId) ?? null;
  }

  async save(userId: string, credential: WebAuthnCredentialRecord): Promise<void> {
    this.byId.set(credential.id, credential);
    const existing = this.byUser.get(userId) ?? new Set();
    existing.add(credential.id);
    this.byUser.set(userId, existing);
  }

  async list(userId: string): Promise<WebAuthnCredentialRecord[]> {
    const ids = this.byUser.get(userId);
    if (!ids) return [];
    return [...ids].map((id) => this.byId.get(id)).filter((c): c is WebAuthnCredentialRecord => c !== undefined);
  }

  async updateCounter(credentialId: string, counter: number): Promise<void> {
    const existing = this.byId.get(credentialId);
    if (existing) existing.counter = counter;
  }
}
