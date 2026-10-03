# RS9 Staged Nix Candidates (H1 Review)
# Publication outputs (packages, apps, overlay) MUST remain unexposed.
# No guessed nixpkgs lock/hash; fail closed requiring authenticated generated inputs and pinned lock.

{ pkgs ? null, system ? (if pkgs != null then pkgs.stdenv.hostPlatform.system else null), candidateConfig ? null }:
let
  rawConfig = if candidateConfig != null then candidateConfig else builtins.fromJSON (builtins.readFile ./candidate-products.json);
  products = rawConfig.products;

  failClosed = msg: throw ("RS9 Nix Candidate Fail-Closed: " + msg + "; requiring authenticated generated inputs and pinned lock.");

  buildCandidate = productKey:
    if pkgs == null then
      failClosed "Derivation instantiation without pinned authenticated nixpkgs"
    else
      let
        product = products.${productKey} or (failClosed ("Unknown candidate product: " + productKey));
        nodeBuilder = pkgs.callPackage ./node-cli.nix { };
        nebularBuilder = pkgs.callPackage ./nebular.nix { };
      in
      if product.kind == "node-cli" then
        nodeBuilder { inherit product; }
      else if product.kind == "materialized-desktop" then
        nebularBuilder { inherit product; }
      else
        failClosed ("Unsupported product kind: " + product.kind);

  candidatePackages =
    if pkgs == null then {
      "theme-forge-stellar-burst" = failClosed "theme-forge-stellar-burst requires authenticated nixpkgs";
      "theme-forge-stellar-loom" = failClosed "theme-forge-stellar-loom requires authenticated nixpkgs";
      "theme-forge-solar-sail" = failClosed "theme-forge-solar-sail requires authenticated nixpkgs";
      "theme-forge-nebular-fusion" = failClosed "theme-forge-nebular-fusion requires authenticated nixpkgs";
    } else {
      "theme-forge-stellar-burst" = buildCandidate "theme-forge-stellar-burst";
      "theme-forge-stellar-loom" = buildCandidate "theme-forge-stellar-loom";
      "theme-forge-solar-sail" = buildCandidate "theme-forge-solar-sail";
      "theme-forge-nebular-fusion" = buildCandidate "theme-forge-nebular-fusion";
    };

in
{
  schema = "rs9.nix-staged-candidates.v1alpha1";
  status = "pending";
  authenticated = false;
  inherit (rawConfig) generated_at;
  config = rawConfig;
  inherit products;

  # Explicit qualification gate status
  qualification = {
    status = "pending";
    authenticated = false;
    publicationOutputsExposed = false;
    crossPlatformGatesPending = true;
    nativeProofPending = true;
    nebularLinuxClosure = "not-run";
    evidenceNotes = "Complete ELF/FHS closure and file-provider proofs remain unexecuted.";
  };

  # Candidate definitions under nix/, NOT exposed as root publication packages/apps/overlay
  inherit candidatePackages buildCandidate;

  # Convenience accessor for candidate product metadata
  productKeys = builtins.attrNames products;
}
