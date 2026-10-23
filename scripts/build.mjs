// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Bundles src/index.ts and its dependencies into dist/index.js, and writes
// dist/licenses.txt with the licence of every package in the bundle.
// The output is deterministic, so CI can check that dist/ is up to date.
import { readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist");
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);

const result = await build({
  absWorkingDir: root,
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  // Some bundled CommonJS dependencies call require(); give them one.
  banner: { js: 'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);' },
  legalComments: "none",
  metafile: true,
  logLevel: "warning",
});

const packages = new Set();
for (const input of Object.keys(result.metafile.inputs)) {
  const m = /^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//.exec(input);
  if (m) packages.add(m[1]);
}

const sections = [];
for (const dir of [...packages].sort()) {
  const pkg = JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
  const licenceFile = readdirSync(join(root, dir)).find((f) => /^(licen[sc]e|copying)(\.|$)/i.test(f));
  const text = licenceFile ? readFileSync(join(root, dir, licenceFile), "utf8").trim() : "(no licence file in the package)";
  sections.push(`${pkg.name}@${pkg.version}\nLicense: ${pkg.license ?? "unknown"}\n\n${text}`);
}

const vendored = join(root, "third_party", "verifiable-receipts", "LICENSE");
if (existsSync(vendored)) {
  sections.push(
    "verifiable-receipts (vendored verification code in src/vendor/verifiable-receipts)\nLicense: Apache-2.0\n\n" +
      readFileSync(vendored, "utf8").trim(),
  );
}

writeFileSync(join(dist, "licenses.txt"), sections.join("\n\n" + "-".repeat(72) + "\n\n") + "\n");
