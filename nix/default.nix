# Direct evaluation without authenticated inputs must fail closed.
{ }:
{
  qualification = {
    status = "pending";
    authenticated = false;
    crossPlatformGatesPending = true;
    nativeProofPending = true;
    nebularLinuxClosure = "not-run";
    publicationOutputsExposed = false;
  };
  candidatePackages = throw "RS9 Nix Candidate Fail-Closed: requiring authenticated generated inputs and pinned lock";
}
