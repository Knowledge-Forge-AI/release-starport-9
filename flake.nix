{
  description = "RS9 Staged Nix Candidate Suite (H1 Review; Publication Outputs Unexposed)";

  # Fail closed: No guessed nixpkgs lock or ambient channel.
  # Publication outputs (packages, apps, overlay, overlays) MUST remain unexposed
  # while real cross-platform gates and native runtime proofs remain pending.
  inputs = { };

  outputs = { self }: {
    # Candidate definitions under nix/, NOT exposed as root publication packages/apps/overlay.
    candidates = import ./nix { };

    # Explicit gate qualification record
    qualification = {
      status = "pending";
      authenticated = false;
      publicationOutputsExposed = false;
      crossPlatformGatesPending = true;
      nativeProofPending = true;
      nebularLinuxClosure = "not-run";
      unexposedOutputs = [ "packages" "apps" "overlay" "overlays" ];
    };
  };
}
