import type { VigilRequest, VigilResponse } from "@vigil/core";

export function fakeRequest<TUser = unknown>(overrides: Partial<VigilRequest<TUser>> = {}): VigilRequest<TUser> {
  return {
    method: "GET",
    url: "/",
    path: "/",
    headers: {},
    cookies: {},
    query: {},
    body: {},
    user: null,
    ...overrides,
  };
}

export interface FakeResponse extends VigilResponse {
  statusCode: number;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  cleared: string[];
  redirected?: { url: string; status: number };
  body?: unknown;
}

export function fakeResponse(): FakeResponse {
  return {
    statusCode: 200,
    headers: {},
    cookies: {},
    cleared: [],
    status(code) {
      this.statusCode = code;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
    setCookie(name, value) {
      this.cookies[name] = value;
    },
    clearCookie(name) {
      this.cleared.push(name);
      delete this.cookies[name];
    },
    redirect(url, status = 302) {
      this.redirected = { url, status };
    },
    json(body) {
      this.body = body;
    },
    send(body) {
      this.body = body;
    },
  };
}

/** Runs a VigilHandler and resolves once it has called `next` (or written a response). */
export async function run<TUser>(
  handler: (req: VigilRequest<TUser>, res: VigilResponse, next: (err?: unknown) => void) => Promise<void>,
  req: VigilRequest<TUser>,
  res: FakeResponse = fakeResponse(),
): Promise<{ error?: unknown; called: boolean; res: FakeResponse }> {
  let error: unknown;
  let called = false;
  await handler(req, res, (err) => {
    called = true;
    error = err;
  });
  return { error, called, res };
}
