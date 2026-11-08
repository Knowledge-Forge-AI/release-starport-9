"""Small test-only bindings for the existing authenticated smoke fixture."""
import copy


def bind_replay_profile_to_prepared_source(prepared, base_profile):
    """Bind a replay profile to the fixture's authenticated source records.

    The source transport fixture already authenticates its release and fixture
    captures. Its module bytes are controlled test bytes, so the optional
    provenance observer must use those complete source records rather than
    production byte pins. This still exercises source-root, role,
    import-closure, and capture authentication checks.
    """
    profile = copy.deepcopy(base_profile)
    records = prepared.get("records")
    if not isinstance(records, list):
        raise AssertionError("authenticated fixture must expose source records")
    by_path = {row.get("path"): row for row in records if isinstance(row, dict)}
    modules = profile.get("modules")
    if not isinstance(modules, dict):
        raise AssertionError("replay profile must expose module pins")
    for name in modules:
        row = by_path.get("tools/" + name)
        if not isinstance(row, dict):
            raise AssertionError("fixture is missing replay module " + name)
        modules[name] = {key: row[key] for key in ("blob", "sha256", "size")}
    package = by_path.get("package.json")
    if not isinstance(package, dict):
        raise AssertionError("fixture is missing package support row")
    profile["support"] = {key: package[key] for key in ("blob", "sha256", "size")}
    return profile
