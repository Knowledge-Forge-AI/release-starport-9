"""Closed source-owned capture generations; selection grants no capability."""
from rs9.errors import ContractError

HISTORICAL_GENERATION = "theme-forge-live1"
CURRENT_GENERATION = "theme-forge-current-202610"
GENERATIONS = (HISTORICAL_GENERATION, CURRENT_GENERATION)


def generation_paths(generation=HISTORICAL_GENERATION):
    """Resolve only reviewed source locations, never caller-supplied paths."""
    if generation == HISTORICAL_GENERATION:
        # Keep the historical controller as owner of its existing constants.
        from rs9.operator import BOOTSTRAP, EXPECTATIONS
        return BOOTSTRAP, EXPECTATIONS
    if generation == CURRENT_GENERATION:
        return ("bootstrap/pre-rs9/theme-forge-current-202610/manifest.json",
                "operators/theme-forge-current-202610/expectations.json")
    raise ContractError("GENERATION_SELECTION", "Unknown capture generation")
