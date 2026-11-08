// Pure in-memory source derivation for the inactive current-Nix two-key
// inherited environment transform (XDG_DATA_DIRS and FONTCONFIG_FILE).
// The 0.7.1 identity remains the default; the version-isolated 0.8.0 identity
// is selected only by its exact transform/profile tuple below.
//
// Provenance:
//   Upstream repository: Knowledge-Forge-AI/theme-forge-nebular-fusion
//   Upstream commit: f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a (v0.7.1)
//   Upstream tree: 6e3561855f6ee0093fb709488ad976b69bf501d2
//   Upstream path: tools/native-rc-smoke.mjs (30732 bytes, AGPL-3.0-or-later)
//   Upstream SHA-256: 874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69
//   Derived SHA-256: 15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f (30772 bytes)
//
// This module performs no file I/O, process execution, or source-profile
// blessing. The original authenticated closure remains unchanged on disk and in
// source_profile; executed derived bytes are separately bound in the closed
// execution_transform metadata carrier.
import crypto from "node:crypto";

export const TRANSFORM_IDENTITY_SCHEMA = "parent.current-nix-environment-source-transform.v1";
export const CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA = "rs9.current-nix-smoke-environment-transform.v1";
export const CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID = "current071-nix-inherited-xdg-fontconfig-v1";
export const CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID = "current080-nix-inherited-xdg-fontconfig-v1";
export const CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE = "execution-transform-and-observation";
export const CURRENT071_PROFILE_ID = "nebular071";
export const CURRENT071_UPSTREAM_COMMIT = "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a";
export const CURRENT071_UPSTREAM_TREE = "6e3561855f6ee0093fb709488ad976b69bf501d2";
export const CURRENT071_HARNESS_MODULE = "native-rc-smoke.mjs";
export const CURRENT071_UPSTREAM_HARNESS_SHA256 = "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69";
export const CURRENT071_UPSTREAM_HARNESS_BYTES = 30732;
export const CURRENT071_UPSTREAM_HARNESS_BLOB = "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f";
export const CURRENT071_DERIVED_HARNESS_SHA256 = "15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f";
export const CURRENT071_DERIVED_HARNESS_BYTES = 30772;
export const CURRENT080_PROFILE_ID = "nebular080";
export const CURRENT080_UPSTREAM_COMMIT = "516f5a7d8a449946a0246ea23d37991f586dfc2c";
export const CURRENT080_UPSTREAM_TREE = "907163a09d2995c9080074294db54c54af626563";
export const CURRENT080_HARNESS_MODULE = "native-rc-smoke.mjs";
export const CURRENT080_UPSTREAM_HARNESS_SHA256 = "ee2a26e00522f27d49550d3931cdd25e0f9956a0786d487f9af89755cf8bff39";
export const CURRENT080_UPSTREAM_HARNESS_BYTES = 65040;
export const CURRENT080_UPSTREAM_HARNESS_BLOB = "4adeae77bb147cf7969054695a8af6dfeb335736";
export const CURRENT080_DERIVED_HARNESS_SHA256 = "a792af12928867361a39132d0cdb2f0fc1c35444dc698d9c59e53a9038680afe";
export const CURRENT080_DERIVED_HARNESS_BYTES = 65080;
export const SMOKE_INHERITED_ENV_ANCHOR = "export const SMOKE_INHERITED_ENV_KEYS = Object.freeze([\n";
export const CURRENT_NIX_INHERITED_ENV_INSERTION = "  \"XDG_DATA_DIRS\",\n  \"FONTCONFIG_FILE\",\n";
export const RESTORED_INHERITED_ENV_KEYS = Object.freeze(["XDG_DATA_DIRS", "FONTCONFIG_FILE"]);

export const CURRENT_NIX_TRANSFORM_IDENTITY = Object.freeze({
  schema: TRANSFORM_IDENTITY_SCHEMA,
  upstreamSha256: CURRENT071_UPSTREAM_HARNESS_SHA256,
  upstreamBytes: CURRENT071_UPSTREAM_HARNESS_BYTES,
  derivedSha256: CURRENT071_DERIVED_HARNESS_SHA256,
  derivedBytes: CURRENT071_DERIVED_HARNESS_BYTES,
  anchor: SMOKE_INHERITED_ENV_ANCHOR,
  insertion: CURRENT_NIX_INHERITED_ENV_INSERTION,
  upstreamCommit: CURRENT071_UPSTREAM_COMMIT,
  upstreamTree: CURRENT071_UPSTREAM_TREE,
});

export const CURRENT080_NIX_TRANSFORM_IDENTITY = Object.freeze({
  schema: TRANSFORM_IDENTITY_SCHEMA,
  upstreamSha256: CURRENT080_UPSTREAM_HARNESS_SHA256,
  upstreamBytes: CURRENT080_UPSTREAM_HARNESS_BYTES,
  derivedSha256: CURRENT080_DERIVED_HARNESS_SHA256,
  derivedBytes: CURRENT080_DERIVED_HARNESS_BYTES,
  anchor: SMOKE_INHERITED_ENV_ANCHOR,
  insertion: CURRENT_NIX_INHERITED_ENV_INSERTION,
  upstreamCommit: CURRENT080_UPSTREAM_COMMIT,
  upstreamTree: CURRENT080_UPSTREAM_TREE,
});

export const SUPPORTED_NIX_PLATFORM_SCENARIOS = Object.freeze({
  "linux-arm64": Object.freeze(["B"]),
  "linux-x64": Object.freeze(["C", "C-signal"]),
});

const PROFILE_CONTRACTS = Object.freeze({
  [CURRENT071_PROFILE_ID]: Object.freeze({
    id: CURRENT071_PROFILE_ID,
    commit: CURRENT071_UPSTREAM_COMMIT,
    tree: CURRENT071_UPSTREAM_TREE,
    harnessModule: CURRENT071_HARNESS_MODULE,
    upstreamSha256: CURRENT071_UPSTREAM_HARNESS_SHA256,
    upstreamBytes: CURRENT071_UPSTREAM_HARNESS_BYTES,
    upstreamBlob: CURRENT071_UPSTREAM_HARNESS_BLOB,
    derivedSha256: CURRENT071_DERIVED_HARNESS_SHA256,
    derivedBytes: CURRENT071_DERIVED_HARNESS_BYTES,
    transformId: CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
  }),
  [CURRENT080_PROFILE_ID]: Object.freeze({
    id: CURRENT080_PROFILE_ID,
    commit: CURRENT080_UPSTREAM_COMMIT,
    tree: CURRENT080_UPSTREAM_TREE,
    harnessModule: CURRENT080_HARNESS_MODULE,
    upstreamSha256: CURRENT080_UPSTREAM_HARNESS_SHA256,
    upstreamBytes: CURRENT080_UPSTREAM_HARNESS_BYTES,
    upstreamBlob: CURRENT080_UPSTREAM_HARNESS_BLOB,
    derivedSha256: CURRENT080_DERIVED_HARNESS_SHA256,
    derivedBytes: CURRENT080_DERIVED_HARNESS_BYTES,
    transformId: CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID,
  }),
});

export function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function gitBlobSha1Hex(bytes) {
  const header = Buffer.from(`blob ${bytes.length}\0`, "utf8");
  return crypto.createHash("sha1").update(header).update(bytes).digest("hex");
}

export function isSupportedCurrentNixTarget(platform, scenario) {
  if (typeof platform !== "string" || typeof scenario !== "string") return false;
  if (!Object.prototype.hasOwnProperty.call(SUPPORTED_NIX_PLATFORM_SCENARIOS, platform)) return false;
  return SUPPORTED_NIX_PLATFORM_SCENARIOS[platform].includes(scenario);
}

function profileContract(profileId) {
  const contract = PROFILE_CONTRACTS[profileId];
  if (!contract) throw new Error("Current Nix environment transform profile is unsupported");
  return contract;
}

export function validateCurrentNixTransformProfile(profile, expectedProfileId = CURRENT071_PROFILE_ID) {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    throw new Error("Current Nix environment transform requires an authenticated profile object");
  }
  const expected = profileContract(expectedProfileId);
  const pin = profile.modules?.[expected.harnessModule];
  const validPin = Boolean(
    pin && typeof pin === "object"
    && pin.sha256 === expected.upstreamSha256
    && pin.size === expected.upstreamBytes
    && pin.blob === expected.upstreamBlob,
  );
  if (profile.id !== expected.id
      || profile.commit !== expected.commit
      || profile.tree !== expected.tree
      || !validPin) {
    const profileLabel = expected.id === CURRENT071_PROFILE_ID
      ? "nebular071"
      : "authenticated";
    throw new Error(`Current Nix environment transform requires the exact ${profileLabel} profile`);
  }
  return expected;
}

export function validateCurrentNixTransformTarget(context) {
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    throw new Error("Current Nix environment transform target context is required");
  }
  const profileId = context.transformId === CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID
    ? CURRENT071_PROFILE_ID
    : context.transformId === CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID
      ? CURRENT080_PROFILE_ID
      : null;
  if (profileId === null) {
    throw new Error("Current Nix environment transform identifier is unsupported");
  }
  validateCurrentNixTransformProfile(context.profile, profileId);
  if (!isSupportedCurrentNixTarget(context.platform, context.scenario)) {
    throw new Error("Current Nix environment transform scenario or platform is unsupported");
  }
  return profileContract(profileId);
}

export function verifyUpstreamCurrent071SmokeBytes(originalBytes) {
  return verifyUpstreamSmokeBytes(originalBytes, PROFILE_CONTRACTS[CURRENT071_PROFILE_ID]);
}

export function verifyUpstreamCurrent080SmokeBytes(originalBytes) {
  return verifyUpstreamSmokeBytes(originalBytes, PROFILE_CONTRACTS[CURRENT080_PROFILE_ID]);
}

function verifyUpstreamSmokeBytes(originalBytes, expected) {
  if (!Buffer.isBuffer(originalBytes) && !(originalBytes instanceof Uint8Array)) {
    throw new TypeError("Upstream native-rc-smoke source must be a byte buffer");
  }
  const bytes = Buffer.from(originalBytes);
  if (bytes.length !== expected.upstreamBytes
      || sha256Hex(bytes) !== expected.upstreamSha256
      || gitBlobSha1Hex(bytes) !== expected.upstreamBlob) {
    throw new Error("Upstream native-rc-smoke source identity mismatch");
  }
  return bytes;
}

export function insertCurrentNixInheritedEnvKeys(sourceText) {
  if (typeof sourceText !== "string") {
    throw new TypeError("Upstream native-rc-smoke source text must be a string");
  }
  const firstIndex = sourceText.indexOf(SMOKE_INHERITED_ENV_ANCHOR);
  if (firstIndex < 0) {
    throw new Error("Upstream native-rc-smoke inherited environment anchor is missing");
  }
  const secondIndex = sourceText.indexOf(
    SMOKE_INHERITED_ENV_ANCHOR,
    firstIndex + SMOKE_INHERITED_ENV_ANCHOR.length,
  );
  if (secondIndex >= 0) {
    throw new Error("Upstream native-rc-smoke inherited environment anchor is duplicated");
  }
  const splitAt = firstIndex + SMOKE_INHERITED_ENV_ANCHOR.length;
  const derivedText = sourceText.slice(0, splitAt)
    + CURRENT_NIX_INHERITED_ENV_INSERTION
    + sourceText.slice(splitAt);
  return Buffer.from(derivedText, "utf8");
}

export function createCurrentNixEnvironmentCarrier() {
  return createNixEnvironmentCarrier(PROFILE_CONTRACTS[CURRENT071_PROFILE_ID]);
}

export function createCurrent080NixEnvironmentCarrier() {
  return createNixEnvironmentCarrier(PROFILE_CONTRACTS[CURRENT080_PROFILE_ID]);
}

function createNixEnvironmentCarrier(profile) {
  return Object.freeze({
    schema: CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA,
    transform_id: profile.transformId,
    mode: CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE,
    target_module: profile.harnessModule,
    upstream_sha256: profile.upstreamSha256,
    upstream_bytes: profile.upstreamBytes,
    executed_derived_sha256: profile.derivedSha256,
    executed_derived_bytes: profile.derivedBytes,
    restored_env_keys: Object.freeze([...RESTORED_INHERITED_ENV_KEYS]),
    modified_from_upstream: true,
    non_admitting: true,
    fhs_origin_proven: false,
    native_qualified: false,
    causal_attribution_proven: false,
  });
}

function hasExactRestoredKeys(value) {
  if (!Array.isArray(value) || value.length !== RESTORED_INHERITED_ENV_KEYS.length) return false;
  return RESTORED_INHERITED_ENV_KEYS.every((key, index) => value[index] === key);
}

function hasExactCarrierFields(carrier, profile) {
  const expectedEntries = [
    ["schema", CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA],
    ["transform_id", profile.transformId],
    ["mode", CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE],
    ["target_module", profile.harnessModule],
    ["upstream_sha256", profile.upstreamSha256],
    ["upstream_bytes", profile.upstreamBytes],
    ["executed_derived_sha256", profile.derivedSha256],
    ["executed_derived_bytes", profile.derivedBytes],
    ["modified_from_upstream", true],
    ["non_admitting", true],
    ["fhs_origin_proven", false],
    ["native_qualified", false],
    ["causal_attribution_proven", false],
  ];
  const expectedKeys = [...expectedEntries.map(([key]) => key), "restored_env_keys"];
  const expectedKeySet = new Set(expectedKeys);
  const keys = Object.keys(carrier);
  if (keys.length !== expectedKeys.length) return false;
  if (keys.some((key) => !expectedKeySet.has(key))) return false;
  if (!hasExactRestoredKeys(carrier.restored_env_keys)) return false;
  return expectedEntries.every(([key, value]) => Object.is(carrier[key], value));
}

export function validateCurrentNixEnvironmentCarrier(carrier, options) {
  if (!options || typeof options !== "object" || typeof options.expected !== "boolean") {
    throw new TypeError("Explicit boolean expectation is required for transform carrier validation");
  }
  if (!options.expected) {
    if (carrier !== undefined && carrier !== null) {
      throw new Error("Unexpected current Nix environment transform carrier");
    }
    return null;
  }
  const profile = profileContract(options.profileId ?? CURRENT071_PROFILE_ID);
  if (!carrier || typeof carrier !== "object" || Array.isArray(carrier) || !hasExactCarrierFields(carrier, profile)) {
    throw new Error("Invalid current Nix environment transform carrier");
  }
  return createNixEnvironmentCarrier(profile);
}

export function deriveCurrentNixSmokeModule(originalBytes, context) {
  return deriveNixSmokeModule(originalBytes, context, CURRENT071_PROFILE_ID);
}

export function deriveCurrent080NixSmokeModule(originalBytes, context) {
  return deriveNixSmokeModule(originalBytes, context, CURRENT080_PROFILE_ID);
}

function deriveNixSmokeModule(originalBytes, context, profileId) {
  const profile = profileContract(profileId);
  validateCurrentNixTransformTarget(context);
  if (context.transformId !== profile.transformId) {
    throw new Error("Current Nix environment transform profile differs");
  }
  const verifiedUpstream = verifyUpstreamSmokeBytes(originalBytes, profile);
  const derivedBytes = insertCurrentNixInheritedEnvKeys(verifiedUpstream.toString("utf8"));
  if (derivedBytes.length !== profile.derivedBytes
      || sha256Hex(derivedBytes) !== profile.derivedSha256) {
    throw new Error("Derived native-rc-smoke source identity mismatch");
  }
  const executionTransform = validateCurrentNixEnvironmentCarrier(
    createNixEnvironmentCarrier(profile),
    { expected: true, profileId },
  );
  return Object.freeze({
    derivedBytes,
    upstreamSha256: profile.upstreamSha256,
    upstreamBytes: profile.upstreamBytes,
    derivedSha256: profile.derivedSha256,
    derivedBytesLength: profile.derivedBytes,
    executionTransform,
  });
}
