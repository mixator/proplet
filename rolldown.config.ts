import { defineConfig } from "rolldown";

import run from "@rollup/plugin-run";

// @ts-ignore
const dev = process.env.ROLLUP_WATCH === "true";

export default defineConfig({
  platform: "node",
  input: {
    node: "./src/node-handler.ts",
    lambda: "./src/lambda-handler.ts",
  },
  output: {
    dir: "./dist",
    // preserveModules: true,
    cleanDir: true,
  },
  watch: {
    buildDelay: 1000,
  },
  plugins: [
    dev &&
      run({
        input: "./src/node-handler.ts",
      }),
  ],
});
