import type { CookieOptions, Vigil, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import { cookies } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";
import { parseCookieHeader, serializeCookie } from "./cookies.js";

/** A Next.js middleware/Route Handler function has no per-request mutable
 * state of its own, so auth state — and the in-progress response, since
 * Fetch API Responses are immutable once built — is threaded through this
 * single context object, shared across a chain of NextMiddleware for one
 * request by `composeNextMiddleware`/`composeNextRoute`. */
export interface NextContext<TUser = unknown> {
  user?: TUser;
  csrfToken?: () => string;
  /** @internal accumulated response state; do not set directly. */
  responseStatus: number;
  /** @internal accumulated response state; do not set directly. */
  responseHeaders: Headers;
}

export type NextMiddleware<TUser = unknown> = (
  request: NextRequest,
  ctx: NextContext<TUser>,
  next: () => Promise<NextResponse>,
) => Promise<NextResponse>;

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** A Next.js `NextRequest` is a standard Fetch API Request with no
 * framework body parser, so the adapter reads it itself based on
 * Content-Type to keep behavior consistent with the other adapters. */
async function readBody(request: NextRequest): Promise<unknown> {
  if (BODYLESS_METHODS.has(request.method)) return {};

  const contentType = request.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const text = await request.text();
      return text ? JSON.parse(text) : {};
    }
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const form = await request.formData();
      const body: Record<string, string> = {};
      for (const [key, value] of form.entries()) {
        body[key] = String(value);
      }
      return body;
    }
  } catch {
    return {};
  }
  return {};
}

function toVigilRequest<TUser>(request: NextRequest, ctx: NextContext<TUser>, body: unknown): VigilRequest<TUser> {
  const url = new URL(request.url);
  const query: Record<string, string | string[]> = {};
  for (const key of url.searchParams.keys()) {
    const values = url.searchParams.getAll(key);
    query[key] = values.length > 1 ? values : (values[0] ?? "");
  }

  return {
    method: request.method,
    url: request.url,
    path: url.pathname,
    headers: Object.fromEntries(request.headers) as VigilRequest<TUser>["headers"],
    cookies: parseCookieHeader(request.headers.get("cookie") ?? undefined),
    query,
    body,
    ip: request.headers.get("x-forwarded-for") ?? undefined,
    secure: request.headers.get("x-forwarded-proto") === "https" || url.protocol === "https:",
    user: ctx.user,
  };
}

function toVigilResponse<TUser>(ctx: NextContext<TUser>, setTerminal: (response: NextResponse) => void): VigilResponse {
  return {
    status(code) {
      ctx.responseStatus = code;
    },
    setHeader(name, value) {
      ctx.responseHeaders.set(name, value);
    },
    setCookie(name, value, options) {
      ctx.responseHeaders.append("Set-Cookie", serializeCookie(name, value, options));
    },
    clearCookie(name, options) {
      const clearOptions: CookieOptions = { ...options, maxAge: 0 };
      ctx.responseHeaders.append("Set-Cookie", serializeCookie(name, "", clearOptions));
    },
    redirect(url, status) {
      ctx.responseStatus = status ?? 302;
      ctx.responseHeaders.set("Location", url);
      setTerminal(new NextResponse(null, { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
    json(body) {
      ctx.responseHeaders.set("Content-Type", "application/json");
      setTerminal(new NextResponse(JSON.stringify(body), { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
    send(body) {
      setTerminal(new NextResponse(body ?? null, { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
  };
}

/** Wraps a framework-agnostic VigilHandler into Next.js middleware. Compose
 * a chain with `composeNextMiddleware` (for `middleware.ts`) or
 * `composeNextRoute` (for a Route Handler). */
export function toNext<TUser = unknown>(handler: VigilHandler<TUser>): NextMiddleware<TUser> {
  return async (request, ctx, next) => {
    const body = await readBody(request);
    const vreq = toVigilRequest<TUser>(request, ctx, body);

    let terminal: NextResponse | undefined;
    const vres = toVigilResponse(ctx, (response) => {
      terminal = response;
    });

    let nextError: unknown;
    let hasNextError = false;

    await handler(vreq, vres, (err) => {
      hasNextError = err !== undefined;
      nextError = err;
    });

    ctx.user = vreq.user ?? undefined;
    if (vreq.csrfToken) ctx.csrfToken = vreq.csrfToken;

    if (hasNextError) throw nextError;
    if (terminal) return terminal;
    return next();
  };
}

function errorResponse(err: unknown): NextResponse {
  const status = (err as { status?: number } | undefined)?.status ?? 500;
  return NextResponse.json({ error: (err as Error)?.message ?? "error" }, { status });
}

/**
 * Chains NextMiddleware into a single `middleware.ts`-compatible function:
 * `export default composeNextMiddleware(toNext(vigil.requireAuth()))`.
 * Unlike `composeNextRoute`, running off the end of the chain without a
 * terminal response falls through to `NextResponse.next()` — i.e. "let
 * Next.js's own router handle it" — since middleware always sits in front
 * of further routing, unlike a Route Handler which is a dead end.
 */
export function composeNextMiddleware<TUser = unknown>(
  ...middlewares: NextMiddleware<TUser>[]
): (request: NextRequest) => Promise<NextResponse> {
  return async (request) => {
    const ctx: NextContext<TUser> = { responseStatus: 200, responseHeaders: new Headers() };
    let index = 0;
    const dispatch = async (): Promise<NextResponse> => {
      const middleware = middlewares[index++];
      if (!middleware) return NextResponse.next();
      return middleware(request, ctx, dispatch);
    };

    try {
      return await dispatch();
    } catch (err) {
      return errorResponse(err);
    }
  };
}

/**
 * Chains NextMiddleware (auth steps plus a terminal handler) into a single
 * Route Handler function, e.g. in `app/api/login/route.ts`:
 * `export const POST = composeNextRoute(toNext(vigil.authenticate("local")), toNext(sendUser))`.
 * Since a Route Handler is a dead end (no further routing beneath it),
 * running off the end of the chain without a terminal response is treated
 * as a handler bug, not "continue" — unlike `composeNextMiddleware`.
 */
export function composeNextRoute<TUser = unknown>(
  ...middlewares: NextMiddleware<TUser>[]
): (request: NextRequest) => Promise<NextResponse> {
  return async (request) => {
    const ctx: NextContext<TUser> = { responseStatus: 200, responseHeaders: new Headers() };
    let index = 0;
    const dispatch = async (): Promise<NextResponse> => {
      const middleware = middlewares[index++];
      if (!middleware) {
        return NextResponse.json({ error: "No handler in the chain produced a response" }, { status: 500 });
      }
      return middleware(request, ctx, dispatch);
    };

    try {
      return await dispatch();
    } catch (err) {
      return errorResponse(err);
    }
  };
}

/**
 * Reads the session user in a Server Component or Server Action, where
 * there's no Request/Response cycle to run through `requireAuth()`. Reads
 * the session cookie via `next/headers` and resolves the user through
 * `vigil.getUserBySessionId()`. Returns `null` outside a request context
 * (e.g. build time) or when there's no valid session.
 */
export async function getVigilUser<TUser>(vigil: Vigil<TUser>): Promise<TUser | null> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(vigil.sessionCookieName())?.value;
  if (!sessionId) return null;
  return vigil.getUserBySessionId(sessionId);
}
