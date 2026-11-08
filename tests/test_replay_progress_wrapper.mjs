import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  buildAuthenticatedClosure,
  current071InitialTimeoutMs,
  current080InitialTimeoutMs,
  verifyRealAncestors,
  isMainModule,
} from "../src/rs9/replay_progress_wrapper.mjs";

const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");

test("0.8.0 initial-observation timeout tuple matches the retained 0.7.1 budget", () => {
  for (const [platform, scenario, expected] of [
    ["linux-arm64", "B", 210_000],
    ["linux-x64", "C", 210_000],
    ["linux-x64", "C-signal", 180_000],
  ]) {
    assert.equal(current071InitialTimeoutMs({platform, scenario}), expected);
    assert.equal(current080InitialTimeoutMs({platform, scenario}), expected);
  }
});

test("nested authenticated closure resolves regular ancestors without spawning a process", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nebular080-wrapper-"));
  try {
    const nested = path.join(root, "appearance-matrix-prep1");
    fs.mkdirSync(nested);
    const child = Buffer.from("export const nested = true;\n");
    const entry = Buffer.from("import './appearance-matrix-prep1/generate.mjs';\nexport const entry = true;\n");
    fs.writeFileSync(path.join(nested, "generate.mjs"), child, {mode: 0o600});
    fs.writeFileSync(path.join(root, "native-rc-smoke.mjs"), entry, {mode: 0o600});
    const closure = buildAuthenticatedClosure(
      path.join(root, "native-rc-smoke.mjs"),
      sha256(entry),
      [
        `native-rc-smoke.mjs=${sha256(entry)}`,
        `appearance-matrix-prep1/generate.mjs=${sha256(child)}`,
      ],
    );
    assert.equal(closure.sources.size, 2);

    fs.renameSync(nested, path.join(root, "appearance-matrix-real"));
    fs.symlinkSync("appearance-matrix-real", nested, "dir");
    assert.throws(
      () => verifyRealAncestors(path.join(nested, "generate.mjs"), root),
      /ancestor is unavailable/,
    );
    assert.throws(
      () => buildAuthenticatedClosure(
        path.join(root, "native-rc-smoke.mjs"),
        sha256(entry),
        [
          `native-rc-smoke.mjs=${sha256(entry)}`,
          `appearance-matrix-prep1/generate.mjs=${sha256(child)}`,
        ],
      ),
      /source is unavailable/,
    );
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("0.8.0-sized current closure exercises the authenticated nested resolver without spawning", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nebular080-closure-"));
  const names = [
    "native-rc-smoke.mjs",
    "appearance-matrix-prep1/generate.mjs",
    "build-inputs.mjs",
    "build-settings.mjs",
    "candidate-provenance.mjs",
    "darwin-linkage-validator.mjs",
    "fs-snapshot.mjs",
    "native-launcher.mjs",
    "native-rc-package.mjs",
    "native-runtime.mjs",
    "node-runtime-authority.mjs",
    "platform-targets.mjs",
    "sidecar-common.mjs",
    "sidecar-verify.mjs",
  ];
  const files = new Map();
  const sha1 = bytes => crypto.createHash("sha1").update(
    Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes]),
  ).digest("hex");
  try {
    for (let index = 0; index < names.length; index += 1) {
      const name = names[index];
      const next = names[index + 1];
      const specifier = next === undefined
        ? ""
        : name === "native-rc-smoke.mjs"
          ? "./appearance-matrix-prep1/generate.mjs"
          : name === "appearance-matrix-prep1/generate.mjs"
            ? "../build-inputs.mjs"
            : `./${next}`;
      const bytes = Buffer.from(specifier === ""
        ? `export const member = ${index};\n`
        : `import '${specifier}';\nexport const member = ${index};\n`);
      const filePath = path.join(root, name);
      fs.mkdirSync(path.dirname(filePath), {recursive: true});
      fs.writeFileSync(filePath, bytes, {mode: 0o600});
      files.set(name, {bytes, sha256: sha256(bytes), blob: sha1(bytes), size: bytes.length});
    }
    const current = {
      supportBytes: Buffer.from("support\n"),
      profile: {id: "nebular080", modules: Object.fromEntries(
        [...files].map(([name, pin]) => [name, {
          sha256: pin.sha256, blob: pin.blob, size: pin.size,
        }]),
      )},
    };
    const closure = buildAuthenticatedClosure(
      path.join(root, "native-rc-smoke.mjs"),
      files.get("native-rc-smoke.mjs").sha256,
      [...files].map(([name, pin]) => `${name}=${pin.sha256}`),
      current,
    );
    assert.equal(closure.sources.size, names.length);
    assert.equal(closure.sources.get(path.join(root, "appearance-matrix-prep1/generate.mjs")).length,
      files.get("appearance-matrix-prep1/generate.mjs").size);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});


test("main-module detection preserves symlink invocation and refuses other entries", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nebular080-entry-"));
  try {
    const actual = path.join(root, "wrapper.mjs");
    const alias = path.join(root, "alias.mjs");
    const other = path.join(root, "other.mjs");
    fs.writeFileSync(actual, "export const fixture = true;\n");
    fs.writeFileSync(other, "export const other = true;\n");
    fs.symlinkSync(actual, alias);
    const url = pathToFileURL(actual).href;
    assert.equal(isMainModule(actual, url), true);
    assert.equal(isMainModule(alias, url), true);
    assert.equal(isMainModule(other, url), false);
    assert.equal(isMainModule(path.join(root, "missing.mjs"), url), false);
    assert.equal(isMainModule(undefined, url), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
