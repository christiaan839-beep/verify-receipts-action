// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Modules and globals that reach the network. The action verifies offline,
// so src/ may not use them; test/ uses them only to block the network.
const networkModules = ["http", "https", "http2", "net", "tls", "dgram", "dns", "undici"].flatMap((m) => [
  m,
  `node:${m}`,
]);

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["**/*.ts"],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // node:test's describe and it return promises the runner awaits.
      "@typescript-eslint/no-floating-promises": [
        "error",
        { allowForKnownSafeCalls: [{ from: "package", package: "node:test", name: ["describe", "it"] }] },
      ],
    },
  },
  {
    files: ["src/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        { paths: networkModules.map((name) => ({ name, message: "The action makes no network calls." })) },
      ],
      "no-restricted-globals": [
        "error",
        { name: "fetch", message: "The action makes no network calls." },
        { name: "WebSocket", message: "The action makes no network calls." },
        { name: "XMLHttpRequest", message: "The action makes no network calls." },
      ],
    },
  },
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly", Buffer: "readonly" },
    },
  },
);
