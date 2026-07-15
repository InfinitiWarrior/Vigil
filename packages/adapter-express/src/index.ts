import type { CookieOptions as VigilCookieOptions, VigilHandler, VigilRequest, VigilResponse } from "@vigil/core";
import type { Request, RequestHandler, Response } from "express";
import { parseCookieHeader } from "./cookies.js";

declare module "express-serve-static-core" {
  interface Request {
    user?: unknown;
    csrfToken?: () => string;
  }
}

function toVigilRequest<TUser>(req: Request): VigilRequest<TUser> {
  const cookies = (req as { cookies?: Record<string, string> }).cookies ?? parseCookieHeader(req.headers.cookie);

  return {
    method: req.method,
    url: req.url,
    path: req.path,
    headers: req.headers as VigilRequest<TUser>["headers"],
    cookies,
    query: req.query as VigilRequest<TUser>["query"],
    body: req.body,
    ip: req.ip,
    user: req.user as TUser | undefined,
  };
}

function toExpressCookieOptions(options?: VigilCookieOptions) {
  return {
    httpOnly: options?.httpOnly,
    secure: options?.secure,
    sameSite: options?.sameSite,
    path: options?.path,
    domain: options?.domain,
    maxAge: options?.maxAge !== undefined ? options.maxAge * 1000 : undefined,
  };
}

function toVigilResponse(res: Response): VigilResponse {
  return {
    status(code) {
      res.status(code);
    },
    setHeader(name, value) {
      res.setHeader(name, value);
    },
    setCookie(name, value, options) {
      res.cookie(name, value, toExpressCookieOptions(options));
    },
    clearCookie(name, options) {
      res.clearCookie(name, toExpressCookieOptions(options));
    },
    redirect(url, status) {
      res.redirect(status ?? 302, url);
    },
    json(body) {
      res.json(body);
    },
    send(body) {
      res.send(body);
    },
  };
}

function syncBack<TUser>(req: Request, vreq: VigilRequest<TUser>): void {
  req.user = vreq.user ?? undefined;
  if (vreq.csrfToken) req.csrfToken = vreq.csrfToken;
}

/** Wraps a framework-agnostic VigilHandler into an Express RequestHandler. */
export function toExpress<TUser = unknown>(handler: VigilHandler<TUser>): RequestHandler {
  return (req, res, next) => {
    const vreq = toVigilRequest<TUser>(req);
    const vres = toVigilResponse(res);

    let nextCalled = false;
    let nextError: unknown;

    handler(vreq, vres, (err) => {
      nextCalled = true;
      nextError = err;
    })
      .then(() => {
        syncBack(req, vreq);
        if (nextCalled) next(nextError);
      })
      .catch((err: unknown) => {
        syncBack(req, vreq);
        next(err);
      });
  };
}
