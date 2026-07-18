import { isAuthError } from "@vigil/core";
import type { CookieOptions, Strategy, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";

export function mockStrategy<TUser>(
  name: string,
  user: TUser | null,
  failureReason = "Mock authentication failed",
): Strategy<TUser> {
  return {
    name,
    async authenticate() {
      if (user === null) return { success: false, reason: failureReason, status: 401 };
      return { success: true, user };
    },
  };
}

export function mockUser<T extends Record<string, unknown>>(overrides: T = {} as T): { id: string; email: string } & T {
  return { id: "mock-user-1", email: "mock@example.com", ...overrides };
}

export function testRequest<TUser = unknown>(overrides: Partial<VigilRequest<TUser>> = {}): VigilRequest<TUser> {
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

export interface MockResponse extends VigilResponse {
  statusCode: number;
  headers: Record<string, string>;
  cookies: Record<string, { value: string; options?: CookieOptions }>;
  clearedCookies: string[];
  redirected?: { url: string; status: number };
  body?: unknown;
}

export function mockResponse(): MockResponse {
  return {
    statusCode: 200,
    headers: {},
    cookies: {},
    clearedCookies: [],
    status(code) {
      this.statusCode = code;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
    setCookie(name, value, options) {
      this.cookies[name] = { value, options };
    },
    clearCookie(name) {
      this.clearedCookies.push(name);
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

export interface HandlerOutcome<TUser> {
  req: VigilRequest<TUser>;
  res: MockResponse;
  error?: unknown;
  nextCalled: boolean;
}

export async function runHandler<TUser>(
  handler: VigilHandler<TUser>,
  req: VigilRequest<TUser> = testRequest<TUser>(),
  res: MockResponse = mockResponse(),
): Promise<HandlerOutcome<TUser>> {
  let error: unknown;
  let nextCalled = false;
  await handler(req, res, (err) => {
    nextCalled = true;
    error = err;
  });
  return { req, res, error, nextCalled };
}

export function expectAuthenticated<TUser>(outcome: HandlerOutcome<TUser>): void {
  if (outcome.error) {
    throw new Error(`Expected authentication to succeed, but got error: ${String(outcome.error)}`);
  }
  if (!outcome.req.user) {
    throw new Error("Expected req.user to be set after authentication");
  }
}

export function expectRejected<TUser>(outcome: HandlerOutcome<TUser>, status?: number): void {
  if (!outcome.error) {
    throw new Error("Expected authentication to be rejected, but it succeeded");
  }
  if (status !== undefined) {
    const actualStatus = isAuthError(outcome.error) ? outcome.error.status : undefined;
    if (actualStatus !== status) {
      throw new Error(`Expected rejection status ${status}, got ${actualStatus}`);
    }
  }
}
