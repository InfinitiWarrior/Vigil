import type { CookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import { parseCookieHeader, serializeCookie } from "./cookies.js";

/** A Workers `fetch(request, env, ctx)` handler has no per-request mutable
 * state of its own (unlike Express's `req.user` or Koa's `ctx.state`), so
 * auth state — and the in-progress response, since Fetch API Responses are
 * immutable once built — is threaded through this single context object,
 * shared by `composeCloudflare` across the whole chain of
 * CloudflareMiddleware for one request. */
export interface CloudflareContext<TUser = unknown> {
  user?: TUser;
  csrfToken?: () => string;
  /** @internal accumulated response state; do not set directly. */
  responseStatus: number;
  /** @internal accumulated response state; do not set directly. */
  responseHeaders: Headers;
}

export type CloudflareMiddleware<TUser = unknown> = (
  request: Request,
  ctx: CloudflareContext<TUser>,
  next: () => Promise<Response>,
) => Promise<Response>;

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** A Workers Request is a standard Fetch API Request with no framework body
 * parser, so the adapter reads it itself based on Content-Type to keep
 * behavior consistent with the other adapters. */
async function readBody(request: Request): Promise<unknown> {
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

function toVigilRequest<TUser>(request: Request, ctx: CloudflareContext<TUser>, body: unknown): VigilRequest<TUser> {
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
    ip: request.headers.get("cf-connecting-ip") ?? undefined,
    secure: request.headers.get("x-forwarded-proto") === "https" || url.protocol === "https:",
    user: ctx.user,
  };
}

function toVigilResponse<TUser>(
  ctx: CloudflareContext<TUser>,
  setTerminal: (response: Response) => void,
): VigilResponse {
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

/** Wraps a framework-agnostic VigilHandler into Workers middleware. Compose
 * a chain with `composeCloudflare`. */
export function toCloudflare<TUser = unknown>(handler: VigilHandler<TUser>): CloudflareMiddleware<TUser> {
  return async (request, ctx, next) => {
    const body = await readBody(request);
    const vreq = toVigilRequest<TUser>(request, ctx, body);

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

/** Chains CloudflareMiddleware (auth steps plus a terminal route handler)
 * into a single Workers-compatible `fetch(request, env, ctx)` handler —
 * e.g. `export default { fetch: composeCloudflare(...) }` — since Workers
 * has no middleware composition of its own. Errors thrown by a step (e.g.
 * `AuthError` from `vigil.requireAuth()`) are converted to a JSON response. */
export function composeCloudflare<TUser = unknown>(
  ...middlewares: CloudflareMiddleware<TUser>[]
): (request: Request, env?: unknown, executionCtx?: unknown) => Promise<Response> {
  return async (request) => {
    const ctx: CloudflareContext<TUser> = { responseStatus: 200, responseHeaders: new Headers() };
    let index = 0;
    const dispatch = async (): Promise<Response> => {
      const middleware = middlewares[index++];
      if (!middleware) return new Response(null, { status: 404 });
      return middleware(request, ctx, dispatch);
    };

    try {
      return await dispatch();
    } catch (err) {
      const status = (err as { status?: number } | undefined)?.status ?? 500;
      return Response.json({ error: (err as Error)?.message ?? "error" }, { status });
    }
  };
}
