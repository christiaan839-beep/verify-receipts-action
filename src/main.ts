// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

/**
 * The action's entry logic: reads the inputs and the files they name,
 * runs the offline checks in verify.ts, and reports through outputs, the
 * job summary and annotations. It makes no network request.
 */
import { appendFile, readFile, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

import * as core from "@actions/core";
import * as glob from "@actions/glob";

import { dedupeKeys, KeyError, parsePublicKeys, type PinnedKey } from "./keys.ts";
import { verifyReceipts, type Report, type SourceFile } from "./verify.ts";

/** Files larger than this are not read. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;
/** Rows shown in each job summary table; the outputs always list every failure. */
const SUMMARY_ROWS = 300;

class InputError extends Error {}

export interface RunOptions {
  /** The time expiry and age checks are made against. Defaults to the current time. */
  now?: Date;
}

function workspace(): string {
  return process.env.GITHUB_WORKSPACE ?? process.cwd();
}

function display(absPath: string): string {
  const rel = relative(workspace(), absPath);
  const shown = rel === "" || rel.startsWith("..") || isAbsolute(rel) ? absPath : rel;
  return shown.split(sep).join("/");
}

function lines(name: string): string[] {
  return core
    .getInput(name)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));
}

function boolInput(name: string, fallback: boolean): boolean {
  const raw = core.getInput(name).trim().toLowerCase();
  if (raw === "") return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new InputError(`input ${name} must be "true" or "false"`);
}

async function expand(patterns: readonly string[]): Promise<string[]> {
  if (patterns.length === 0) return [];
  const globber = await glob.create(patterns.join("\n"), {
    followSymbolicLinks: false,
    matchDirectories: false,
  });
  const found = await globber.glob();
  return [...new Set(found)].sort();
}

type ReadResult = { ok: true; content: string } | { ok: false; reason: string };

async function readLimited(path: string): Promise<ReadResult> {
  try {
    const info = await stat(path);
    if (!info.isFile()) return { ok: false, reason: "not a regular file" };
    if (info.size > MAX_FILE_BYTES) return { ok: false, reason: `file is larger than ${MAX_FILE_BYTES} bytes` };
    return { ok: true, content: await readFile(path, "utf8") };
  } catch {
    return { ok: false, reason: "file could not be read" };
  }
}

async function readRequired(path: string, input: string): Promise<string> {
  const abs = resolve(workspace(), path);
  const r = await readLimited(abs);
  if (!r.ok) throw new InputError(`${input}: ${display(abs)}: ${r.reason}`);
  return r.content;
}

async function keysFrom(textInput: string, fileInput: string): Promise<PinnedKey[]> {
  const keys = parsePublicKeys(core.getInput(textInput), `input ${textInput}`);
  for (const path of lines(fileInput)) {
    keys.push(...parsePublicKeys(await readRequired(path, fileInput), `${fileInput} ${path}`));
  }
  return dedupeKeys(keys);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function entryLabel(index: number | null): string {
  return index === null ? "" : `entry ${index}`;
}

interface Failure {
  file: string;
  entry: number | null;
  reason: string;
}

function table(header: readonly string[], rows: readonly (readonly string[])[]): string {
  const head = `<tr>${header.map((h) => `<th>${h}</th>`).join("")}</tr>`;
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("\n");
  return `<table>\n${head}\n${body}\n</table>\n`;
}

/** Appends the job summary. Every value that came from a file is HTML-escaped. */
async function writeSummary(report: Report, failures: readonly Failure[]): Promise<void> {
  const target = process.env.GITHUB_STEP_SUMMARY;
  if (!target) return;
  const verified = report.results.filter((r) => r.ok).length;
  const parts: string[] = [
    "<h2>Receipt verification</h2>\n",
    `<p>${verified} of ${report.results.length} receipts verified offline; ${failures.length} failures.</p>\n`,
  ];
  if (report.treeHead !== undefined) {
    const h = report.treeHead;
    parts.push(
      `<p>Tree head <code>${escapeHtml(h.file)}</code>: log <code>${escapeHtml(h.logId)}</code>, ` +
        `size ${h.treeSize}, root <code>${h.rootHash.slice(0, 16)}…</code>, signed by <code>${h.key}</code>.</p>\n`,
    );
  }
  const rows = report.results.slice(0, SUMMARY_ROWS).map((r) => [
    `<code>${escapeHtml(r.file)}</code>`,
    entryLabel(r.index),
    r.ok ? "verified" : "<strong>failed</strong>",
    r.ok
      ? escapeHtml(`key ${r.key ?? ""}${r.leafIndex === undefined ? "" : `, leaf ${r.leafIndex}`}`)
      : escapeHtml(r.reason ?? ""),
  ]);
  parts.push(table(["File", "Entry", "Result", "Detail"], rows));
  if (report.results.length > SUMMARY_ROWS) {
    parts.push(`<p>${report.results.length - SUMMARY_ROWS} more receipts are listed in the step outputs.</p>\n`);
  }
  if (report.fileErrors.length > 0) {
    parts.push("<h3>Tree head and proof files</h3>\n");
    parts.push(
      table(
        ["File", "Problem"],
        report.fileErrors.slice(0, SUMMARY_ROWS).map((e) => [`<code>${escapeHtml(e.file)}</code>`, escapeHtml(e.reason)]),
      ),
    );
  }
  await appendFile(target, parts.join(""), "utf8");
}

/** Runs the action. Every failure is reported through @actions/core; it never throws. */
export async function run(options: RunOptions = {}): Promise<void> {
  try {
    const now = options.now ?? new Date();
    const receiptPatterns = lines("receipts");
    if (receiptPatterns.length === 0) throw new InputError("input receipts is required");
    const failOnInvalid = boolInput("fail-on-invalid", true);
    const failOnEmpty = boolInput("fail-on-empty", true);

    const maxAgeRaw = core.getInput("max-age-days").trim();
    let maxAgeDays: number | undefined;
    if (maxAgeRaw !== "") {
      maxAgeDays = Number(maxAgeRaw);
      if (!Number.isSafeInteger(maxAgeDays) || maxAgeDays <= 0) {
        throw new InputError("input max-age-days must be a positive whole number");
      }
    }

    const keys = await keysFrom("public-keys", "public-keys-file");
    if (keys.length === 0) throw new InputError("supply at least one Ed25519 key in public-keys or public-keys-file");

    const treeHeadPath = core.getInput("tree-head").trim();
    const logKeys = await keysFrom("log-public-keys", "log-public-keys-file");
    const proofPatterns = lines("inclusion-proofs");
    let log: { treeHead: SourceFile; keys: PinnedKey[]; proofs: SourceFile[] } | undefined;
    if (treeHeadPath === "") {
      if (logKeys.length > 0 || proofPatterns.length > 0) {
        throw new InputError("log-public-keys and inclusion-proofs need tree-head");
      }
    } else {
      if (logKeys.length === 0) {
        throw new InputError("tree-head needs at least one key in log-public-keys or log-public-keys-file");
      }
      const treeHeadAbs = resolve(workspace(), treeHeadPath);
      const treeHead = { file: display(treeHeadAbs), content: await readRequired(treeHeadPath, "tree-head") };
      const proofs: SourceFile[] = [];
      for (const path of await expand(proofPatterns)) {
        const r = await readLimited(path);
        // An unreadable proof file is reported as invalid JSON in verify.ts.
        proofs.push({ file: display(path), content: r.ok ? r.content : "" });
      }
      log = { treeHead, keys: logKeys, proofs };
    }

    const receiptFiles: SourceFile[] = [];
    const unreadable: Failure[] = [];
    for (const path of await expand(receiptPatterns)) {
      const r = await readLimited(path);
      if (r.ok) receiptFiles.push({ file: display(path), content: r.content });
      else unreadable.push({ file: display(path), entry: null, reason: r.reason });
    }

    const verifyOptions = { keys, now, ...(log && { log }), ...(maxAgeDays !== undefined && { maxAgeDays }) };
    const report = verifyReceipts(receiptFiles, verifyOptions);
    for (const u of unreadable) {
      report.results.push({ file: u.file, index: null, ok: false, reason: u.reason });
    }

    const failures: Failure[] = [
      ...report.results.filter((r) => !r.ok).map((r) => ({ file: r.file, entry: r.index, reason: r.reason ?? "" })),
      ...report.fileErrors.map((e) => ({ file: e.file, entry: null, reason: e.reason })),
    ];
    const verified = report.results.filter((r) => r.ok).length;

    core.setOutput("total", report.results.length);
    core.setOutput("verified", verified);
    core.setOutput("failed", failures.length);
    core.setOutput("failures", JSON.stringify(failures));

    for (const f of failures) {
      const prefix = f.entry === null ? "" : `entry ${f.entry}: `;
      const annotate = failOnInvalid ? core.error : core.warning;
      annotate(prefix + f.reason, { title: "Receipt verification failed", file: f.file });
    }
    await writeSummary(report, failures);

    if (report.results.length === 0) {
      const msg = "no receipt files matched the receipts patterns";
      if (failOnEmpty) core.setFailed(msg);
      else core.warning(msg);
      return;
    }
    core.info(`${verified} of ${report.results.length} receipts verified; ${failures.length} failures`);
    if (failures.length > 0 && failOnInvalid) {
      core.setFailed(`${failures.length} receipt verification failure(s)`);
    }
  } catch (err) {
    if (err instanceof InputError || err instanceof KeyError) {
      core.setFailed(err.message);
    } else {
      core.setFailed(`unexpected error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
