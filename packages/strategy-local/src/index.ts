import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";

export interface LocalStrategyOptions<TUser> {
  /** Field name to read the identifier (e.g. username or email) from the request body. */
  usernameField?: string;
  /** Field name to read the password from the request body. */
  passwordField?: string;
  verify(username: string, password: string): Promise<AuthResult<TUser>>;
}

export class LocalStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "local";

  private readonly usernameField: string;
  private readonly passwordField: string;
  private readonly verify: LocalStrategyOptions<TUser>["verify"];

  constructor(options: LocalStrategyOptions<TUser>) {
    this.usernameField = options.usernameField ?? "username";
    this.passwordField = options.passwordField ?? "password";
    this.verify = options.verify;
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const body =
      typeof request.body === "object" && request.body !== null ? (request.body as Record<string, unknown>) : {};

    const username = body[this.usernameField];
    const password = body[this.passwordField];

    if (typeof username !== "string" || username.length === 0) {
      return { success: false, reason: `Missing "${this.usernameField}"`, status: 400 };
    }
    if (typeof password !== "string" || password.length === 0) {
      return { success: false, reason: `Missing "${this.passwordField}"`, status: 400 };
    }

    return this.verify(username, password);
  }
}
