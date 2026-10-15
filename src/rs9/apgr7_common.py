"""Closed seven-target results; facts about bytes, installs and writes stay separate."""
import json
import re

from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.security import scan_for_credentials

CHANNELS = ("npm", "pypi", "homebrew", "nix", "pacman", "dnf", "apt")
STATES = {"exact", "published", "publish-ready", "incomplete", "conflict", "unknown",
          "blocked", "reconcile-only", "not-attempted", "handoff-emitted"}
PROFILES = {c: ("apgr-upstream-exact-bytes.v1alpha1" if c in ("npm", "pypi") else
               "apgr-tap-projection.v1alpha1" if c == "homebrew" else
               "apgr-tagged-flake-native.v1alpha1" if c == "nix" else
               "apgr-native-envelope.v1alpha1") for c in CHANNELS}


def stop(code, artifacts, remedy):
    return {"code": code, "artifacts": list(artifacts), "remedy": remedy}


def result(channel, profile, state, *, subjects=(), stops=(), observed_version=None,
           verified_bytes=False, installation=None, publication_receipt=None):
    if channel not in CHANNELS or profile != PROFILES[channel] or state not in STATES:
        raise ContractError("APGR7_RESULT", "Unknown channel, profile or state")
    return {"channel": channel, "profile": profile, "state": state, "subjects": list(subjects),
            "stops": list(stops), "observed_version": observed_version,
            "verified_bytes": verified_bytes, "installation": installation,
            "publication_receipt": publication_receipt}


def roster(rows):
    if (len(rows) != 7 or {r["channel"] for r in rows} != set(CHANNELS)
            or any(r["profile"] != PROFILES[r["channel"]] or r["state"] not in STATES for r in rows)):
        raise ContractError("APGR7_ROSTER", "Exactly seven unique channel results required")
    return {"schema": "rs9.apgr7-roster.v1alpha1", "rows": sorted(rows, key=lambda r: CHANNELS.index(r["channel"]))}


def report_bytes(value):
    body = canonical(value, validate=True)
    text = body.decode()
    scan_for_credentials(text)
    if re.search(r"/(?:Users|home)/[^/\s]+/|[A-Z]:\\Users\\", text):
        raise ContractError("APGR7_PRIVACY", "Private host path in report")
    return body


def failure(channel, error):
    code = error.code if isinstance(error, ContractError) else "APGR7_INTERNAL"
    if not re.fullmatch(r"[A-Z0-9_-]{1,80}", code):
        code = "APGR7_INTERNAL"
    return result(channel, PROFILES[channel], "unknown" if code == "REMOTE_UNKNOWN" else "blocked",
                  stops=[stop(code, [], "Resolve this channel's failed boundary, then prepare again.")])


def strict_json(body):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value
    return json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
