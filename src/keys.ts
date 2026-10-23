// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import { createHash, createPublicKey, type KeyObject } from "node:crypto";

/** A pinned Ed25519 public key and the short name it is reported under. */
export interface PinnedKey {
  key: KeyObject;
  /** "sha256:" and the first 16 hex characters of the SHA-256 of the SPKI DER. */
  fingerprint: string;
}

export class KeyError extends Error {}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

/**
 * Reads every PEM block in `text` and returns the Ed25519 public keys.
 * A private key, a non-Ed25519 key, an unreadable block, or text with no
 * PEM block at all is an error: the action never guesses which key was meant.
 * `source` names the input or file in error messages.
 */
export function parsePublicKeys(text: string, source: string): PinnedKey[] {
  const keys: PinnedKey[] = [];
  let blocks = 0;
  for (const match of text.matchAll(PEM_BLOCK)) {
    blocks++;
    const label = match[1] ?? "";
    if (label.includes("PRIVATE")) {
      throw new KeyError(
        `${source}: block ${blocks} is a private key; pin the matching public key instead (openssl pkey -pubout derives it)`,
      );
    }
    if (label !== "PUBLIC KEY") {
      throw new KeyError(`${source}: block ${blocks} is "${label}", expected "PUBLIC KEY"`);
    }
    let key: KeyObject;
    try {
      key = createPublicKey({ key: match[0], format: "pem" });
    } catch {
      throw new KeyError(`${source}: block ${blocks} is not a readable public key`);
    }
    if (key.asymmetricKeyType !== "ed25519") {
      throw new KeyError(
        `${source}: block ${blocks} is a ${key.asymmetricKeyType ?? "unknown"} key, expected ed25519`,
      );
    }
    keys.push({ key, fingerprint: fingerprint(key) });
  }
  if (blocks === 0 && text.trim() !== "") {
    throw new KeyError(
      `${source}: no PEM "PUBLIC KEY" block found; include the -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- lines`,
    );
  }
  return keys;
}

function fingerprint(key: KeyObject): string {
  const der = key.export({ type: "spki", format: "der" });
  return "sha256:" + createHash("sha256").update(der).digest("hex").slice(0, 16);
}

/** Removes keys that appear more than once, keeping the first. */
export function dedupeKeys(keys: readonly PinnedKey[]): PinnedKey[] {
  const seen = new Set<string>();
  return keys.filter((k) => {
    if (seen.has(k.fingerprint)) return false;
    seen.add(k.fingerprint);
    return true;
  });
}
