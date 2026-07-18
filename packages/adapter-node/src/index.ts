import type { IncomingMessage, ServerResponse } from "node:http";
import type { CookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import { parseCookieHeader, serializeCookie } from "./cookies.js";

/** True for a genuine TLS socket (`https.Server`), or when a trusted reverse
 * proxy in front of a plain `http.Server` reports `X-Forwarded-Proto: https`. */
function isSecureRequest(req: IncomingMessage): boolean {
  if ("encrypted" in req.socket && (req.socket as { encrypted?: boolean }).encrypted) return true;
  return req.headers["x-forwarded-proto"] === "https";
}

/** `node:http`'s `IncomingMessage` carries no `user`/`csrfToken` fields of its
 * own (unlike Express/Koa, there's no framework-owned request type to extend
 * via declaration merging), so the adapter tracks them through this shape
 * instead of augmenting Node's global http types. */
export type VigilNodeRequest<TUser = unknown> = IncomingMessage & {
  user?: TUser;
  csrfToken?: () => string;
};

export type NodeHandler = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/** Raw `node:http` has no body parser (unlike Express's conventional
 * `express.json()`), so the adapter reads the request stream itself based
 * on Content-Type to keep behavior consistent with the other adapters. */
async function readBody(req: IncomingMessage): Promise<unknown> {
  if (BODYLESS_METHODS.has(req.method ?? "GET")) return {};

  const contentType = req.headers["content-type"] ?? "";
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
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

function toVigilRequest<TUser>(req: VigilNodeRequest<TUser>, body: unknown): VigilRequest<TUser> {
  const url = new URL(req.url ?? "/", "http://localhost");

  return {
    method: req.method ?? "GET",
    url: req.url ?? "/",
    path: url.pathname,
    headers: req.headers as VigilRequest<TUser>["headers"],
    cookies: parseCookieHeader(req.headers.cookie),
    query: Object.fromEntries(url.searchParams) as VigilRequest<TUser>["query"],
    body,
    ip: req.socket.remoteAddress,
    secure: isSecureRequest(req),
    user: req.user,
  };
}

function appendSetCookie(res: ServerResponse, cookie: string): void {
  const existing = res.getHeader("Set-Cookie");
  const cookies = existing === undefined ? [] : Array.isArray(existing) ? existing.map(String) : [String(existing)];
  cookies.push(cookie);
  res.setHeader("Set-Cookie", cookies);
}

function toVigilResponse(res: ServerResponse, setTerminal: () => void): VigilResponse {
  return {
    status(code) {
      res.statusCode = code;
    },
    setHeader(name, value) {
      res.setHeader(name, value);
    },
    setCookie(name, value, options) {
      appendSetCookie(res, serializeCookie(name, value, options));
    },
    clearCookie(name, options) {
      const clearOptions: CookieOptions = { ...options, maxAge: 0 };
      appendSetCookie(res, serializeCookie(name, "", clearOptions));
    },
    redirect(url, status) {
      res.statusCode = status ?? 302;
      res.setHeader("Location", url);
      res.end();
      setTerminal();
    },
    json(body) {
      if (!res.getHeader("Content-Type")) res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
      setTerminal();
    },
    send(body) {
      res.end(body);
      setTerminal();
    },
  };
}

function syncBack<TUser>(req: VigilNodeRequest<TUser>, vreq: VigilRequest<TUser>): void {
  req.user = vreq.user ?? undefined;
  if (vreq.csrfToken) req.csrfToken = vreq.csrfToken;
}

/** Wraps a framework-agnostic VigilHandler into a raw `node:http` request
 * listener, Connect-style: calls `next(err?)` instead of writing a
 * response when it doesn't terminate the request itself. */
export function toNode<TUser = unknown>(handler: VigilHandler<TUser>): NodeHandler {
  return (req, res, next) => {
    const nreq = req as VigilNodeRequest<TUser>;
    readBody(req)
      .then((body) => {
        const vreq = toVigilRequest<TUser>(nreq, body);
        let terminal = false;
        const vres = toVigilResponse(res, () => {
          terminal = true;
        });

        let nextCalled = false;
        let nextError: unknown;

        return handler(vreq, vres, (err) => {
          nextCalled = true;
          nextError = err;
        }).then(() => {
          syncBack(nreq, vreq);
          if (!terminal && nextCalled) next(nextError);
        });
      })
      .catch((err: unknown) => next(err));
  };
}

/** Chains multiple `NodeHandler`s (e.g. auth middleware followed by a route
 * handler) into a single Connect-style request listener, since raw
 * `node:http` has no middleware composition of its own. */
export function composeNode(...handlers: NodeHandler[]): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    let index = 0;
    const dispatch = (err?: unknown): void => {
      if (err !== undefined) {
        const status = (err as { status?: number } | undefined)?.status ?? 500;
        res.statusCode = status;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: (err as Error)?.message ?? "error" }));
        return;
      }
      const handler = handlers[index++];
      if (!handler) {
        res.statusCode = 404;
        res.end();
        return;
      }
      handler(req, res, dispatch);
    };
    dispatch();
  };
}
