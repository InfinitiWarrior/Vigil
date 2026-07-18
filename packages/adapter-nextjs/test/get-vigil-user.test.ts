import { describe, expect, it, vi } from "vitest";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { getVigilUser } from "@vigil/adapter-nextjs";

interface User {
  id: string;
}

let cookieValue: string | undefined;

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => (name === "vigil.sid" && cookieValue ? { name, value: cookieValue } : undefined),
  }),
}));

describe("getVigilUser", () => {
  it("resolves the user from the session cookie in a Server Component context", async () => {
    const store = new MemorySessionStore();
    await store.set("sess-1", { subject: { id: "1" }, createdAt: Date.now() });
    const vigil = createVigil<User>({ strategies: [], session: { store, cookie: { name: "vigil.sid" } } });

    cookieValue = "sess-1";
    expect(await getVigilUser(vigil)).toEqual({ id: "1" });
  });

  it("returns null when there's no session cookie", async () => {
    const vigil = createVigil<User>({
      strategies: [],
      session: { store: new MemorySessionStore(), cookie: { name: "vigil.sid" } },
    });

    cookieValue = undefined;
    expect(await getVigilUser(vigil)).toBeNull();
  });
});
