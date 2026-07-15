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
      "@vigil/adapter-express": pkg("./packages/adapter-express/src/index.ts"),
      "@vigil/test": pkg("./packages/test/src/index.ts"),
    },
  },
});
