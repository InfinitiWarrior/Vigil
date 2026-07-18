import type { CookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import type { Context, Middleware } from "koa";
import { parseCookieHeader } from "./cookies.js";

declare module "koa" {
  interface DefaultState {
    user?: unknown;
    csrfToken?: () => string;
  }
}

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** Koa has no built-in body parser (unlike Express's conventional
 * `express.json()`), so the adapter reads the raw request stream itself
 * based on Content-Type to keep behavior consistent with the other adapters. */
async function readBody(ctx: Context): Promise<unknown> {
  if (BODYLESS_METHODS.has(ctx.method)) return {};

  const contentType = ctx.get("content-type");
  const chunks: Buffer[] = [];
  for await (const chunk of ctx.req) {
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString("utf8");

  try {
    if (contentType.includes("application/json")) return raw ? JSON.parse(raw) : {};
    if (contentType.includes("application/x-www-form-urlencoded")) {
      return Object.fromEntries(new URLSearchParams(raw));
    }
  } catch {
    return {};
  }
  return {};
}

async function toVigilRequest<TUser>(ctx: Context): Promise<VigilRequest<TUser>> {
  return {
    method: ctx.method,
    url: ctx.url,
    path: ctx.path,
    headers: ctx.headers as VigilRequest<TUser>["headers"],
    cookies: parseCookieHeader(ctx.get("cookie")),
    query: ctx.query as VigilRequest<TUser>["query"],
    body: await readBody(ctx),
    ip: ctx.ip,
    secure: ctx.secure,
    user: ctx.state.user as TUser | undefined,
  };
}

function toKoaCookieOptions(options?: CookieOptions) {
  return {
    httpOnly: options?.httpOnly,
    secure: options?.secure,
    sameSite: options?.sameSite,
    path: options?.path,
    domain: options?.domain,
    maxAge: options?.maxAge !== undefined ? options.maxAge * 1000 : undefined,
  };
}

function toVigilResponse(ctx: Context, setTerminal: () => void): VigilResponse {
  return {
    status(code) {
      ctx.status = code;
    },
    setHeader(name, value) {
      ctx.set(name, value);
    },
    setCookie(name, value, options) {
      ctx.cookies.set(name, value, toKoaCookieOptions(options));
    },
    clearCookie(name, options) {
      ctx.cookies.set(name, null, toKoaCookieOptions({ ...options, maxAge: 0 }));
    },
    redirect(url, status) {
      ctx.status = status ?? 302;
      ctx.redirect(url);
      setTerminal();
    },
    json(body) {
      ctx.body = body;
      setTerminal();
    },
    send(body) {
      ctx.body = body;
      setTerminal();
    },
  };
}

function syncBack<TUser>(ctx: Context, vreq: VigilRequest<TUser>): void {
  ctx.state.user = vreq.user ?? undefined;
  if (vreq.csrfToken) ctx.state.csrfToken = vreq.csrfToken;
}

/** Wraps a framework-agnostic VigilHandler into Koa middleware. */
export function toKoa<TUser = unknown>(handler: VigilHandler<TUser>): Middleware {
  return async (ctx, next) => {
    const vreq = await toVigilRequest<TUser>(ctx);

    let terminal = false;
    const vres = toVigilResponse(ctx, () => {
      terminal = true;
    });

    let nextCalled = false;
    let nextError: unknown;
    let hasNextError = false;

    try {
      await handler(vreq, vres, (err) => {
        nextCalled = true;
        hasNextError = err !== undefined;
        nextError = err;
      });
      syncBack(ctx, vreq);
      if (hasNextError) throw nextError;
      if (!terminal && nextCalled) await next();
    } catch (err) {
      syncBack(ctx, vreq);
      throw err;
    }
  };
}
