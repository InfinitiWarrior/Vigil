import type { VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

declare module "hono" {
  interface ContextVariableMap {
    user?: unknown;
    csrfToken?: () => string;
  }
}

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** Hono has no built-in global body parser (unlike Express's conventional
 * `express.json()`), so the adapter parses JSON/form bodies itself based on
 * Content-Type to keep behavior consistent with the other adapters. */
async function readBody(c: Context): Promise<unknown> {
  if (BODYLESS_METHODS.has(c.req.method)) return {};

  const contentType = c.req.header("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) return await c.req.json();
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      return await c.req.parseBody();
    }
  } catch {
    return {};
  }
  return {};
}

async function toVigilRequest<TUser>(c: Context): Promise<VigilRequest<TUser>> {
  const url = new URL(c.req.url);

  return {
    method: c.req.method,
    url: c.req.url,
    path: url.pathname,
    headers: c.req.header() as VigilRequest<TUser>["headers"],
    cookies: getCookie(c),
    query: c.req.query(),
    body: await readBody(c),
    ip: c.req.header("x-forwarded-for"),
    user: c.get("user") as TUser | undefined,
  };
}

function toVigilResponse(c: Context, setTerminal: (response: Response) => void): VigilResponse {
  return {
    status(code) {
      c.status(code as Parameters<Context["status"]>[0]);
    },
    setHeader(name, value) {
      c.header(name, value);
    },
    setCookie(name, value, options) {
      setCookie(c, name, value, options);
    },
    clearCookie(name, options) {
      deleteCookie(c, name, options);
    },
    redirect(url, status) {
      setTerminal(c.redirect(url, status as Parameters<Context["redirect"]>[1]));
    },
    json(body) {
      setTerminal(c.json(body as object));
    },
    send(body) {
      setTerminal(body === undefined ? c.body(null) : c.body(body));
    },
  };
}

/** Wraps a framework-agnostic VigilHandler into Hono middleware. */
export function toHono<TUser = unknown>(handler: VigilHandler<TUser>): MiddlewareHandler {
  return async (c, next) => {
    const vreq = await toVigilRequest<TUser>(c);

    let terminal: Response | undefined;
    const vres = toVigilResponse(c, (response) => {
      terminal = response;
    });

    let nextError: unknown;
    let hasNextError = false;

    await handler(vreq, vres, (err) => {
      hasNextError = err !== undefined;
      nextError = err;
    });

    c.set("user", vreq.user ?? undefined);
    if (vreq.csrfToken) c.set("csrfToken", vreq.csrfToken);

    if (hasNextError) throw nextError;
    if (terminal) return terminal;
    await next();
    return undefined;
  };
}
