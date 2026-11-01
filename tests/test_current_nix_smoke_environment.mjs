import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { registerHooks } from "node:module";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CURRENT071_UPSTREAM_HARNESS_BLOB,
  CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE,
  CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
  CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA,
  CURRENT_NIX_TRANSFORM_IDENTITY,
  RESTORED_INHERITED_ENV_KEYS,
  SUPPORTED_NIX_PLATFORM_SCENARIOS,
  createCurrentNixEnvironmentCarrier,
  deriveCurrentNixSmokeModule,
  gitBlobSha1Hex,
  insertCurrentNixInheritedEnvKeys,
  sha256Hex,
  validateCurrentNixEnvironmentCarrier,
} from "../src/rs9/current_nix_smoke_environment.mjs";

const FIXTURE_PATH = fileURLToPath(
  new URL("./fixtures/current071-native-rc-smoke.mjs.txt", import.meta.url),
);
const FIXTURE_BYTES = fs.readFileSync(FIXTURE_PATH);

const VALID_PROFILE = Object.freeze({
  id: "nebular071",
  commit: "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a",
  tree: "6e3561855f6ee0093fb709488ad976b69bf501d2",
  modules: Object.freeze({
    "native-rc-smoke.mjs": Object.freeze({
      sha256: "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
      blob: "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f",
      size: 30732,
    }),
  }),
});

const VALID_CONTEXT = Object.freeze({
  transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
  profile: VALID_PROFILE,
  platform: "linux-x64",
  scenario: "C",
});

const STUB_DEPENDENCY_SOURCE = `
export const readRegularSnapshot = () => ({ bytes: Buffer.alloc(0), sha256: "0".repeat(64), mode: 0o600 });
export const nativeLauncher = () => ({});
export const verifyPlatformPackage = () => ({});
export const selectPayloadNativeRuntime = () => ({});
`;

async function importHarnessModuleFromBytes(sourceBytes, tag) {
  const virtualDir = fileURLToPath(new URL("./fixtures/", import.meta.url));
  const entryUrl = pathToFileURL(`${virtualDir}virtual-${tag}-native-rc-smoke.mjs`).href;
  const stubNames = new Set([
    "./fs-snapshot.mjs",
    "./native-launcher.mjs",
    "./native-rc-package.mjs",
    "./native-runtime.mjs",
  ]);
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === entryUrl) {
        return { url: entryUrl, shortCircuit: true };
      }
      if (context.parentURL === entryUrl && stubNames.has(specifier)) {
        return {
          url: new URL(`${specifier}?tag=${tag}`, entryUrl).href,
          shortCircuit: true,
        };
      }
      return nextResolve(specifier, context);
    },
    load(url, context, nextLoad) {
      if (url === entryUrl) {
        return { format: "module", source: Buffer.from(sourceBytes), shortCircuit: true };
      }
      if (url.startsWith(pathToFileURL(virtualDir).href) && url.includes(`?tag=${tag}`)) {
        return { format: "module", source: STUB_DEPENDENCY_SOURCE, shortCircuit: true };
      }
      return nextLoad(url, context);
    },
  });
  try {
    return await import(entryUrl);
  } finally {
    hooks.deregister();
  }
}

test("fixture matches pinned upstream 0.7.1 native-rc-smoke.mjs identity", () => {
  assert.equal(FIXTURE_BYTES.length, 30732);
  assert.equal(sha256Hex(FIXTURE_BYTES), CURRENT_NIX_TRANSFORM_IDENTITY.upstreamSha256);
  assert.equal(gitBlobSha1Hex(FIXTURE_BYTES), CURRENT071_UPSTREAM_HARNESS_BLOB);
  assert.equal(CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA, "rs9.current-nix-smoke-environment-transform.v1");
  assert.equal(CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID, "current071-nix-inherited-xdg-fontconfig-v1");
  assert.equal(CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE, "execution-transform-and-observation");
  assert.deepEqual(RESTORED_INHERITED_ENV_KEYS, ["XDG_DATA_DIRS", "FONTCONFIG_FILE"]);
  assert.deepEqual(SUPPORTED_NIX_PLATFORM_SCENARIOS, {
    "linux-arm64": ["B"],
    "linux-x64": ["C", "C-signal"],
  });
});

test("deriveCurrentNixSmokeModule produces exact derived bytes and carrier for allowed Linux scenarios", () => {
  for (const [platform, scenario] of [
    ["linux-arm64", "B"],
    ["linux-x64", "C"],
    ["linux-x64", "C-signal"],
  ]) {
    const derived = deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
      transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
      profile: VALID_PROFILE,
      platform,
      scenario,
    });
    assert.equal(derived.upstreamSha256, CURRENT_NIX_TRANSFORM_IDENTITY.upstreamSha256);
    assert.equal(derived.upstreamBytes, 30732);
    assert.equal(derived.derivedSha256, CURRENT_NIX_TRANSFORM_IDENTITY.derivedSha256);
    assert.equal(derived.derivedBytes.length, 30772);
    assert.equal(derived.derivedBytesLength, 30772);
    const derivedDigest = crypto.createHash("sha256").update(derived.derivedBytes).digest("hex");
    assert.equal(derivedDigest, "15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f");
    const expectedText = FIXTURE_BYTES.toString("utf8").replace(
      CURRENT_NIX_TRANSFORM_IDENTITY.anchor,
      CURRENT_NIX_TRANSFORM_IDENTITY.anchor + CURRENT_NIX_TRANSFORM_IDENTITY.insertion,
    );
    assert.equal(derived.derivedBytes.toString("utf8"), expectedText);
    const validated = validateCurrentNixEnvironmentCarrier(derived.executionTransform, {
      expected: true,
    });
    assert.deepEqual(validated, createCurrentNixEnvironmentCarrier());
  }
});

test("in-memory ESM load of original vs derived module proves two-key restoration and stripping invariants", async () => {
  const originalMod = await importHarnessModuleFromBytes(FIXTURE_BYTES, "original");
  const derivedResult = deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
    transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
    profile: VALID_PROFILE,
    platform: "linux-x64",
    scenario: "C",
  });
  const derivedMod = await importHarnessModuleFromBytes(derivedResult.derivedBytes, "derived");

  assert.equal(originalMod.SMOKE_INHERITED_ENV_KEYS.includes("XDG_DATA_DIRS"), false);
  assert.equal(originalMod.SMOKE_INHERITED_ENV_KEYS.includes("FONTCONFIG_FILE"), false);
  assert.deepEqual(
    derivedMod.SMOKE_INHERITED_ENV_KEYS.slice(0, 2),
    ["XDG_DATA_DIRS", "FONTCONFIG_FILE"],
  );
  assert.deepEqual(
    derivedMod.SMOKE_INHERITED_ENV_KEYS.slice(2),
    originalMod.SMOKE_INHERITED_ENV_KEYS,
  );

  const baseOptions = {
    platform: "linux-x64",
    home: "/tmp/scratch/home",
    temp: "/tmp/scratch/tmp",
    smokeDir: "/tmp/scratch/smoke",
    xdg: {
      config: "/tmp/scratch/xdg/config",
      cache: "/tmp/scratch/xdg/cache",
      data: "/tmp/scratch/xdg/data",
      state: "/tmp/scratch/xdg/state",
      runtime: "/tmp/scratch/xdg/runtime",
    },
  };
  const richEnv = {
    HOME: "/tmp/caller-home",
    PATH: "/usr/bin:/bin",
    DISPLAY: ":99",
    DBUS_SESSION_BUS_ADDRESS: "unix:path=/tmp/dbus",
    WEBKIT_DISABLE_COMPOSITING_MODE: "1",
    WEBKIT_DISABLE_DMABUF_RENDERER: "1",
    LIBGL_ALWAYS_SOFTWARE: "1",
    XDG_DATA_DIRS: "/nix/store/gtk3/share:/nix/store/shared-mime-info/share",
    FONTCONFIG_FILE: "/nix/store/fontconfig/etc/fonts/fonts.conf",
    LD_LIBRARY_PATH: "/nix/store/lib",
    GIO_EXTRA_MODULES: "/nix/store/glib-networking/lib/gio/modules",
    GDK_PIXBUF_MODULE_FILE: "/nix/store/librsvg/loaders.cache",
    GSETTINGS_SCHEMA_DIR: "/nix/store/schemas",
    RS9_GITHUB_READ_TOKEN: "secret-token",
    ACTIONS_RUNTIME_TOKEN: "runtime-token",
  };

  const originalBuilt = originalMod.buildSmokeEnvironment({
    ...baseOptions,
    inheritedEnv: richEnv,
  });
  assert.equal("XDG_DATA_DIRS" in originalBuilt, false);
  assert.equal("FONTCONFIG_FILE" in originalBuilt, false);
  assert.equal("LD_LIBRARY_PATH" in originalBuilt, false);
  assert.equal("RS9_GITHUB_READ_TOKEN" in originalBuilt, false);

  const derivedBuilt = derivedMod.buildSmokeEnvironment({
    ...baseOptions,
    inheritedEnv: richEnv,
  });
  assert.equal(
    derivedBuilt.XDG_DATA_DIRS,
    "/nix/store/gtk3/share:/nix/store/shared-mime-info/share",
  );
  assert.equal(
    derivedBuilt.FONTCONFIG_FILE,
    "/nix/store/fontconfig/etc/fonts/fonts.conf",
  );
  for (const strippedKey of [
    "LD_LIBRARY_PATH",
    "GIO_EXTRA_MODULES",
    "GDK_PIXBUF_MODULE_FILE",
    "GSETTINGS_SCHEMA_DIR",
    "RS9_GITHUB_READ_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
  ]) {
    assert.equal(strippedKey in derivedBuilt, false);
  }
  assert.equal(derivedBuilt.WEBKIT_DISABLE_COMPOSITING_MODE, "1");
  assert.equal(derivedBuilt.WEBKIT_DISABLE_DMABUF_RENDERER, "1");
  assert.equal(derivedBuilt.LIBGL_ALWAYS_SOFTWARE, "1");
  assert.equal(derivedBuilt.TFNF_RELEASE_SMOKE_DIR, "/tmp/scratch/smoke");
  assert.equal(derivedBuilt.GSETTINGS_BACKEND, "memory");

  const emptyEnvBuilt = derivedMod.buildSmokeEnvironment({
    ...baseOptions,
    inheritedEnv: {
      PATH: "/usr/bin",
      XDG_DATA_DIRS: "",
      FONTCONFIG_FILE: "",
    },
  });
  assert.equal("XDG_DATA_DIRS" in emptyEnvBuilt, false);
  assert.equal("FONTCONFIG_FILE" in emptyEnvBuilt, false);
});

test("deriveCurrentNixSmokeModule and insertCurrentNixInheritedEnvKeys reject tampered inputs", () => {
  assert.throws(
    () => deriveCurrentNixSmokeModule(FIXTURE_BYTES),
    /Current Nix environment transform target context is required/,
  );
  assert.throws(
    () => deriveCurrentNixSmokeModule("not-bytes", VALID_CONTEXT),
    /Upstream native-rc-smoke source must be a byte buffer/,
  );
  assert.throws(
    () => deriveCurrentNixSmokeModule(FIXTURE_BYTES.subarray(0, 100), VALID_CONTEXT),
    /Upstream native-rc-smoke source identity mismatch/,
  );
  const flipped = Buffer.from(FIXTURE_BYTES);
  flipped[0] ^= 0xff;
  assert.throws(
    () => deriveCurrentNixSmokeModule(flipped, VALID_CONTEXT),
    /Upstream native-rc-smoke source identity mismatch/,
  );
  assert.throws(
    () => insertCurrentNixInheritedEnvKeys("export const OTHER = 1;\n"),
    /anchor is missing/,
  );
  assert.throws(
    () =>
      insertCurrentNixInheritedEnvKeys(
        CURRENT_NIX_TRANSFORM_IDENTITY.anchor + CURRENT_NIX_TRANSFORM_IDENTITY.anchor,
      ),
    /anchor is duplicated/,
  );
  assert.throws(
    () =>
      deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
        transformId: "wrong-transform-id",
        profile: VALID_PROFILE,
        platform: "linux-x64",
        scenario: "C",
      }),
    /transform identifier is unsupported/,
  );
  assert.throws(
    () =>
      deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
        transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
        profile: { ...VALID_PROFILE, id: "nebular070" },
        platform: "linux-x64",
        scenario: "C",
      }),
    /requires the exact nebular071 profile/,
  );
  assert.throws(
    () =>
      deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
        transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
        profile: { ...VALID_PROFILE, commit: "0".repeat(40) },
        platform: "linux-x64",
        scenario: "C",
      }),
    /requires the exact nebular071 profile/,
  );
  assert.throws(
    () =>
      deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
        transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
        profile: {
          ...VALID_PROFILE,
          modules: {
            "native-rc-smoke.mjs": {
              ...VALID_PROFILE.modules["native-rc-smoke.mjs"],
              sha256: "0".repeat(64),
            },
          },
        },
        platform: "linux-x64",
        scenario: "C",
      }),
    /requires the exact nebular071 profile/,
  );
  for (const [platform, scenario] of [
    ["darwin-arm64", "A"],
    ["linux-arm64", "C"],
    ["linux-x64", "B"],
    ["linux-x64", "A"],
  ]) {
    assert.throws(
      () =>
        deriveCurrentNixSmokeModule(FIXTURE_BYTES, {
          transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
          profile: VALID_PROFILE,
          platform,
          scenario,
        }),
      /scenario or platform is unsupported/,
    );
  }
});

test("validateCurrentNixEnvironmentCarrier enforces closed schema, pins, and non-admitting flags", () => {
  assert.throws(() => validateCurrentNixEnvironmentCarrier(null, {}), /Explicit boolean expectation/);
  assert.equal(validateCurrentNixEnvironmentCarrier(null, { expected: false }), null);
  assert.throws(
    () => validateCurrentNixEnvironmentCarrier(createCurrentNixEnvironmentCarrier(), { expected: false }),
    /Unexpected current Nix environment transform carrier/,
  );
  assert.throws(
    () => validateCurrentNixEnvironmentCarrier(null, { expected: true }),
    /Invalid current Nix environment transform carrier/,
  );

  const base = createCurrentNixEnvironmentCarrier();
  for (const mutated of [
    { ...base, extra: true },
    { ...base, schema: "wrong" },
    { ...base, transform_id: "wrong" },
    { ...base, mode: "default-observation" },
    { ...base, target_module: "other.mjs" },
    { ...base, upstream_sha256: base.executed_derived_sha256 },
    { ...base, upstream_bytes: 30772 },
    { ...base, executed_derived_sha256: base.upstream_sha256 },
    { ...base, executed_derived_bytes: 30732 },
    { ...base, restored_env_keys: ["XDG_DATA_DIRS"] },
    { ...base, restored_env_keys: ["FONTCONFIG_FILE", "XDG_DATA_DIRS"] },
    { ...base, restored_env_keys: ["XDG_DATA_DIRS", "FONTCONFIG_FILE", "LD_LIBRARY_PATH"] },
    { ...base, modified_from_upstream: false },
    { ...base, non_admitting: false },
    { ...base, fhs_origin_proven: true },
    { ...base, native_qualified: true },
    { ...base, causal_attribution_proven: true },
    { ...base, non_admitting: 1 },
  ]) {
    assert.throws(
      () => validateCurrentNixEnvironmentCarrier(mutated, { expected: true }),
      /Invalid current Nix environment transform carrier/,
    );
  }
});
