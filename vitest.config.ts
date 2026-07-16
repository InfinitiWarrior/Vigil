import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

function pkg(path: string): string {
  return fileURLToPath(new URL(path, import.meta.url));
}

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@vigil/core": pkg("./packages/core/src/index.ts"),
      "@vigil/strategy-local": pkg("./packages/strategy-local/src/index.ts"),
      "@vigil/strategy-jwt": pkg("./packages/strategy-jwt/src/index.ts"),
      "@vigil/strategy-oauth2": pkg("./packages/strategy-oauth2/src/index.ts"),
      "@vigil/strategy-apikey": pkg("./packages/strategy-apikey/src/index.ts"),
      "@vigil/strategy-totp": pkg("./packages/strategy-totp/src/index.ts"),
      "@vigil/strategy-magic-link": pkg("./packages/strategy-magic-link/src/index.ts"),
      "@vigil/adapter-express": pkg("./packages/adapter-express/src/index.ts"),
      "@vigil/adapter-fastify": pkg("./packages/adapter-fastify/src/index.ts"),
      "@vigil/adapter-hono": pkg("./packages/adapter-hono/src/index.ts"),
      "@vigil/session-redis": pkg("./packages/session-redis/src/index.ts"),
      "@vigil/test": pkg("./packages/test/src/index.ts"),
    },
  },
});
