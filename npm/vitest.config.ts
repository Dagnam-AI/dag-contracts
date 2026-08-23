import { defineConfig } from "vitest/config";

// Hard gate mirroring the Python side (dag-lib's fail_under = 100): the
// contract package must stay at 100% statement AND branch coverage on both
// languages, since the whole point of this package is that they agree.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/component-schema.json", "src/types.ts"],
      reporter: ["text", "html", "json"],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
