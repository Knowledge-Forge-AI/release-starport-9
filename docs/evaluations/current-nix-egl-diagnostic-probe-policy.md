# Proposed current Linux Nix application diagnostics

Status: ADOPTED on 2026-11-01 with owner approval of the two diagnostic environment settings and one current RS9 campaign. Hosted qualification and publication gates remain required.

## Problem and scope

Both Linux Nix application checks in run 41337094929 aborted while creating an EGL display. The precise graphics cause remains unknown. The accessibility warning is not established as the fatal cause.

Set only EGL_LOG_LEVEL=debug and LIBGL_DEBUG=verbose for the final current-generation Linux Nix application check and its existing non-admitting failure-retention replay and boundary probes, after the existing source, import and released-runtime verifier checks complete. Upstream and the existing derived harness already allow these keys in the Linux application child.

The shared Nix environment and its original prefix remain unchanged. Pre-application network checks, addon loads, FHS checks, GUI discovery, import/verifier commands, CLI/service probes and ldd receive no new settings. Historical, Darwin, package and generic callers keep their defaults.

## Mechanism and boundaries

The shared environment and prefix helpers expose keyword-only, default-false switches that enable only on literal True and always substitute the two fixed values. Only the existing final Nix verifier caller supplies the switch after authenticating current source and fixture capture carriers and only when the existing Nix isolation prefix is present. The pre-existing direct fixture route remains unchanged.

The final application helper also requires the current generation, both capture carriers and a supported Linux architecture. It checks that the incoming prefix begins with the complete original canonical disconnected, unprivileged environment-restoration prefix. It then replaces that exact prefix with the same controls and old environment values plus the fixed pair. The existing FHS suffix is retained. An unexpected prefix fails closed using APPLICATION_SMOKE. Equality assumes the shared environment remains stable between its initial prefix construction and final application check; an in-place change will refuse the newly enabled path.

Default and ineligible calls return their original prefix and already-filtered environment unchanged. No arbitrary prefix arguments are scanned or rewritten. Existing WebKit settings, XDG/fontconfig restoration, source checks, runtime identities, network isolation, privilege controls, timeouts and admission gates remain required.

No packages, pins, FHS definitions, controller, discovery paths, error taxonomy or diagnostic schema change. Existing complete-stream privacy and size checks still control retained text; increased logging may be withheld or exceed existing limits. This is diagnostic preparation and makes no runtime-fix or native-qualification claim.

## Verification, budget and rollback

The original default-path tests remain byte-identical. Additional pure checks cover fixed values, strict switches, source/platform eligibility, exact prefix matching, actual inert environment restoration, generic prefix preservation, root rejection and ordering after the existing verifiers.

The bounded inner-stderr class is already approved. The new environment settings were separately approved on 2026-11-01. At approval, two of three current RS9 campaigns were consumed; the owner authorized the one remaining campaign. No reset or extension was granted.

Rollback restores the three changed source files and removes this document and the new test file. Signing inputs and protected environment settings are outside this patch.
