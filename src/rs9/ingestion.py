"""Compatibility composition of reusable ingestion and explicit evidence policy."""
from rs9.errors import ContractError
from rs9.release_core import digest, read_evidence, json_evidence, checksum_entries, authenticate_release
from rs9.profiles import png_size, selection_for_intent, evidence_policy, evaluate_profile


class AuthenticatedInputs:
    """In-process shadow inputs; captured records do not authorize publication."""
    def __init__(self, normalized, record, archives, source, manifests, release_capture, profile_result):
        self.normalized, self.record = normalized, record
        self.archives, self.source, self.manifests = archives, source, manifests
        self.release_capture, self.profile_result = release_capture, profile_result


def authenticate(normalized, evidence, *, bootstrap_manifest=None, approved_manifests=()):
    return _authenticate(normalized, evidence, bootstrap_manifest=bootstrap_manifest,
                         approved_manifests=approved_manifests, require_configuration=True)


def authenticate_shadow(normalized, evidence):
    """Legacy diagnostic input only; cannot bypass the planner configuration gate."""
    return _authenticate(normalized, evidence, require_configuration=False)


def _authenticate(normalized, evidence, *, bootstrap_manifest=None, approved_manifests=(), require_configuration):
    try:
        selection = selection_for_intent(normalized, include_configuration=require_configuration and bootstrap_manifest is None)
        capture = authenticate_release(selection, evidence)
        if require_configuration:
            from rs9.bootstrap import load_bootstrap, require_configuration_authority
            if bootstrap_manifest is not None:
                if load_bootstrap(bootstrap_manifest, capture, approved_manifests=approved_manifests) != normalized:
                    raise ContractError("BOOTSTRAP_BINDING", "Intent differs from approved bootstrap")
            require_configuration_authority(capture, normalized)
        profile, policy, roles = evidence_policy(normalized)
        result = evaluate_profile(capture, profile, normalized, roles=roles)
        legacy = result["sections"].get("legacy_ingestion")
        if legacy is None:
            raise ContractError("SHADOW_PROFILE", "Selected profile has no desktop shadow compatibility view")
        return AuthenticatedInputs(normalized, legacy, capture.archives, capture.source,
                                   capture.manifests, capture, result)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise ContractError("INVALID_EVIDENCE", "Captured evidence does not satisfy the ingestion schema") from None
