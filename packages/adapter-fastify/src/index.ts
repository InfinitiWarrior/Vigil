import type { CookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";
import { parseCookieHeader, serializeCookie } from "./cookies.js";

declare module "fastify" {
  interface FastifyRequest {
    user?: unknown;
    csrfToken?: () => string;
  }
}

function toVigilRequest<TUser>(request: FastifyRequest): VigilRequest<TUser> {
  const cookies = (request as { cookies?: Record<string, string> }).cookies
    ?? parseCookieHeader(request.headers.cookie);

  return {
    method: request.method,
    url: request.url,
    path: request.url.split("?")[0] ?? request.url,
    headers: request.headers as VigilRequest<TUser>["headers"],
    cookies,
    query: (request.query ?? {}) as VigilRequest<TUser>["query"],
    body: request.body,
    ip: request.ip,
    user: request.user as TUser | undefined,
  };
}

/** Multiple Set-Cookie headers must be sent as an array — this appends to
 * whatever's already queued instead of clobbering it (e.g. a session cookie
 * set alongside a CSRF cookie in the same response). */
function appendSetCookie(reply: FastifyReply, cookie: string): void {
  const existing = reply.getHeader("set-cookie");
  const cookies = existing === undefined ? [] : Array.isArray(existing) ? existing.map(String) : [String(existing)];
  cookies.push(cookie);
  reply.header("set-cookie", cookies);
}

function toVigilResponse(reply: FastifyReply): VigilResponse {
  return {
    status(code) {
      reply.code(code);
    },
    setHeader(name, value) {
      reply.header(name, value);
    },
    setCookie(name, value, options) {
      appendSetCookie(reply, serializeCookie(name, value, options));
    },
    clearCookie(name, options) {
      const clearOptions: CookieOptions = { ...options, maxAge: 0 };
      appendSetCookie(reply, serializeCookie(name, "", clearOptions));
    },
    redirect(url, status) {
      reply.redirect(url, status ?? 302);
    },
    json(body) {
      reply.send(body);
    },
    send(body) {
      reply.send(body);
    },
  };
}

function syncBack<TUser>(request: FastifyRequest, vreq: VigilRequest<TUser>): void {
  request.user = vreq.user ?? undefined;
  if (vreq.csrfToken) request.csrfToken = vreq.csrfToken;
}

/** Wraps a framework-agnostic VigilHandler into a Fastify preHandler hook. */
export function toFastify<TUser = unknown>(handler: VigilHandler<TUser>): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const vreq = toVigilRequest<TUser>(request);
    const vres = toVigilResponse(reply);

    let nextError: unknown;
    let hasNextError = false;

    await handler(vreq, vres, (err) => {
      hasNextError = err !== undefined;
      nextError = err;
    });

    syncBack(request, vreq);
    if (hasNextError) throw nextError;
  };
}
