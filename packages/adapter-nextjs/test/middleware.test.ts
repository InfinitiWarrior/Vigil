import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { composeNextMiddleware, toNext } from "@vigil/adapter-nextjs";

interface User {
  id: string;
}

describe("composeNextMiddleware", () => {
  it("falls through to NextResponse.next() when every step calls next()", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    const middleware = composeNextMiddleware(toNext(vigil.optionalAuth()));

    const res = await middleware(new NextRequest("http://localhost/dashboard"));
    // NextResponse.next() sets this header to signal "continue routing".
    expect(res.headers.get("x-middleware-next")).toBe("1");
  });

  it("blocks the request with a 401 when requireAuth() fails", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    const middleware = composeNextMiddleware(toNext(vigil.requireAuth()));

    const res = await middleware(new NextRequest("http://localhost/dashboard"));
    expect(res.status).toBe(401);
    expect(res.headers.get("x-middleware-next")).not.toBe("1");
  });

  it("redirects when requireAuth() is configured with redirectTo", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    const middleware = composeNextMiddleware(toNext(vigil.requireAuth({ redirectTo: "/login" })));

    const res = await middleware(new NextRequest("http://localhost/dashboard"));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/login");
  });

  it("lets an authenticated request through to NextResponse.next()", async () => {
    const store = new MemorySessionStore();
    await store.set("sess-1", { subject: { id: "1" }, createdAt: Date.now() });
    const vigil = createVigil<User>({ strategies: [], session: { store, cookie: { name: "vigil.sid" } } });
    const middleware = composeNextMiddleware(toNext(vigil.requireAuth()));

    const res = await middleware(
      new NextRequest("http://localhost/dashboard", { headers: { cookie: "vigil.sid=sess-1" } }),
    );
    expect(res.headers.get("x-middleware-next")).toBe("1");
  });
});
