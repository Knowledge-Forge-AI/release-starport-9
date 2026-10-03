"""Tenant capture delegates transport mechanics and selected profile supplements."""
from rs9.github import PublicClient
from rs9.profiles import selection_for_intent, capture_supplemental
from rs9.release_core import capture_release


def fetch(normalized, output, *, client=None):
    client = client or PublicClient()
    capture_release(selection_for_intent(normalized), output, client=client)
    capture_supplemental(normalized, output, client)
    return output
