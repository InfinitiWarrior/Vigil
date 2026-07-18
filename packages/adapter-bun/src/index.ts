import type { CookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import { parseCookieHeader, serializeCookie } from "./cookies.js";

/** Bun.serve's `fetch(req)` has no per-request mutable state of its own
 * (unlike Express's `req.user` or Koa's `ctx.state`), so auth state — and
 * the in-progress response, since Fetch API Responses are immutable once
 * built — is threaded through this single context object, shared by
 * `composeBun` across the whole chain of BunMiddleware for one request. */
export interface BunContext<TUser = unknown> {
  user?: TUser;
  csrfToken?: () => string;
  /** @internal accumulated response state; do not set directly. */
  responseStatus: number;
  /** @internal accumulated response state; do not set directly. */
  responseHeaders: Headers;
}

export type BunMiddleware<TUser = unknown> = (
  req: Request,
  ctx: BunContext<TUser>,
  next: () => Promise<Response>,
) => Promise<Response>;

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** Bun's Request is a standard Fetch API Request with no framework body
 * parser, so the adapter reads it itself based on Content-Type to keep
 * behavior consistent with the other adapters. */
async function readBody(req: Request): Promise<unknown> {
  if (BODYLESS_METHODS.has(req.method)) return {};

  const contentType = req.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const text = await req.text();
      return text ? JSON.parse(text) : {};
    }
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const form = await req.formData();
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

function toVigilRequest<TUser>(req: Request, ctx: BunContext<TUser>, body: unknown): VigilRequest<TUser> {
  const url = new URL(req.url);
  const query: Record<string, string | string[]> = {};
  for (const key of url.searchParams.keys()) {
    const values = url.searchParams.getAll(key);
    query[key] = values.length > 1 ? values : (values[0] ?? "");
  }

  return {
    method: req.method,
    url: req.url,
    path: url.pathname,
    headers: Object.fromEntries(req.headers) as VigilRequest<TUser>["headers"],
    cookies: parseCookieHeader(req.headers.get("cookie") ?? undefined),
    query,
    body,
    ip: req.headers.get("x-forwarded-for") ?? undefined,
    secure: req.headers.get("x-forwarded-proto") === "https" || url.protocol === "https:",
    user: ctx.user,
  };
}

function toVigilResponse<TUser>(ctx: BunContext<TUser>, setTerminal: (response: Response) => void): VigilResponse {
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
      setTerminal(new Response(null, { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
    json(body) {
      ctx.responseHeaders.set("Content-Type", "application/json");
      setTerminal(new Response(JSON.stringify(body), { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
    send(body) {
      setTerminal(new Response(body ?? null, { status: ctx.responseStatus, headers: ctx.responseHeaders }));
    },
  };
}

/** Wraps a framework-agnostic VigilHandler into Bun middleware. Compose a
 * chain with `composeBun`. */
export function toBun<TUser = unknown>(handler: VigilHandler<TUser>): BunMiddleware<TUser> {
  return async (req, ctx, next) => {
    const body = await readBody(req);
    const vreq = toVigilRequest<TUser>(req, ctx, body);

    let terminal: Response | undefined;
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

/** Chains BunMiddleware (auth steps plus a terminal route handler) into a
 * single `Bun.serve`-compatible `fetch(req)` function, since Bun.serve has
 * no middleware composition of its own. Errors thrown by a step (e.g.
 * `AuthError` from `vigil.requireAuth()`) are converted to a JSON response. */
export function composeBun<TUser = unknown>(
  ...middlewares: BunMiddleware<TUser>[]
): (req: Request) => Promise<Response> {
  return async (req) => {
    const ctx: BunContext<TUser> = { responseStatus: 200, responseHeaders: new Headers() };
    let index = 0;
    const dispatch = async (): Promise<Response> => {
      const middleware = middlewares[index++];
      if (!middleware) return new Response(null, { status: 404 });
      return middleware(req, ctx, dispatch);
    };

    try {
      return await dispatch();
    } catch (err) {
      const status = (err as { status?: number } | undefined)?.status ?? 500;
      return Response.json({ error: (err as Error)?.message ?? "error" }, { status });
    }
  };
}
