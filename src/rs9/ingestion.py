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


def authenticate(normalized, evidence):
    try:
        selection = selection_for_intent(normalized)
        capture = authenticate_release(selection, evidence)
        profile, policy, roles = evidence_policy(normalized)
        result = evaluate_profile(capture, profile, normalized, roles=roles)
        legacy = result["sections"].get("legacy_ingestion")
        if legacy is None:
            raise ContractError("SHADOW_PROFILE", "Selected profile has no desktop shadow compatibility view")
        return AuthenticatedInputs(normalized, legacy, capture.archives, capture.source,
                                   capture.manifests, capture, result)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise ContractError("INVALID_EVIDENCE", "Captured evidence does not satisfy the ingestion schema") from None
