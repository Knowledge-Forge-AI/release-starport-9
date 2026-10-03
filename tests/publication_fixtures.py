"""Synthetic readback and qualification fixtures; no simulated network publisher."""
from rs9.gates import derive_gates, gate
from rs9.observation import observe
from rs9.planner import adapter_output, destination_policy, expected_components, plan
from rs9.profiles import evaluate_profile, PACKAGE_PROFILE, selection_for_intent
from rs9.records import build_semantic_content_identity, record_sha256
from rs9.release_core import authenticate_release
from rs9.qualification import execute_qualification
from rs9.release_core import digest
from tests.release_fixtures import package_evidence


def authorize_fixture_configuration(root, intent, capture):
    """Explicit synthetic exception, never a production or ambient fallback."""
    from rs9.bootstrap import configuration_inventory, load_bootstrap
    from rs9.scratch import canonical
    directory = root / "fixture-bootstrap" / "project"
    directory.mkdir(parents=True)
    (directory / "intent.json").write_bytes(canonical(intent))
    record = capture.record
    manifest = {"schema": "rs9.bootstrap-tenant-manifest.v1alpha1", "bootstrap-pre-rs9": True,
                "release-contains-rs9": False, "scope": "exact-generation", "future-releases": "forbidden",
                "projects": [{"repository": record["repository"]["full_name"], "repository_id": record["repository"]["id"],
                "tag": intent["tag"], "version": intent["version"], "release_id": record["release"]["id"],
                "tag_commit": record["tag"]["commit"], "tag_tree": record["tag"]["tree"],
                "configuration": "project", "config_sha256": record_sha256(configuration_inventory(directory))}]}
    path = directory.parent / "manifest.json"
    path.write_bytes(canonical(manifest))
    load_bootstrap(path, capture, approved_manifests=[digest(path.read_bytes())])
    return path

T0 = "2026-10-03T12:00:00Z"
T1 = "2026-10-03T12:00:01Z"
T2 = "2026-10-03T12:00:02Z"
T3 = "2026-10-03T12:00:03Z"


def fixture(root, *, mode="direct", destination_id="synthetic", scheme="none", repair_contract=None):
    intent = package_evidence(root)
    capture = authenticate_release(selection_for_intent(intent), root)
    authorize_fixture_configuration(root, intent, capture)
    profile = evaluate_profile(capture, PACKAGE_PROFILE, intent)
    adapter = "registry" if scheme == "none" else "pacman"
    identity = build_semantic_content_identity(intent["project"]["id"], intent["version"], "package", adapter,
                                              {row["name"]: row["sha256"] for row in capture.record["payloads"]},
                                              {"configuration": record_sha256(intent)})
    source = {"schema": "rs9.synthetic-package-qualification.v1alpha1", "verdict": "qualified", "blockers": [],
              "evidence": "synthetic-fixture"}
    rendered = {"packages/second.recipe": b"fixture recipe", "packages/index": b"fixture index"}
    for path, data in rendered.items():
        target = root / path
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
    output = adapter_output({"id": destination_id, "adapter": adapter, "mode": mode},
                            {"package": "second-project", "version": "0.6.1", "revision": None if scheme == "none" else 1},
                            identity, [{"path": p, "size": len(b), "sha256": digest(b)} for p, b in rendered.items()],
                            source, implementation={"id": "synthetic-fixture", "version": "1"},
                            source_version="fixture-1", revision_scheme=scheme, repair_contract=repair_contract)
    authority = record_sha256({"schema": "synthetic-license-authority.v1", "status": "resolved", "purpose": "synthetic-fixture"})
    gates = derive_gates(intent, capture, profile, output)
    def verifier(candidate):
        assert {p: (candidate / p).read_bytes() for p in rendered} == rendered
        return [{"id": "synthetic-independent-verifier", "exit_code": 0,
                 "stdout_sha256": digest(b""), "stderr_sha256": digest(b"")}]
    executed = {}
    for gate_id in ("license.authority", "package.render"):
        row = execute_qualification(capture, output, gate_id, root, verifier,
              verifier_id="synthetic-independent-verifier", verifier_source_sha256=digest(__import__("pathlib").Path(__file__).read_bytes()),
              environment={"purpose": "synthetic-fixture"})
        executed[gate_id] = [record_sha256(row)]
    policy = destination_policy(repair_contract=repair_contract["id"] if repair_contract else None,
                                external_evidence=executed)
    gates[1] = gate("license.authority", "pass", "tenant", [{"kind": "profile-result", "sha256": record_sha256(profile)},
                   {"kind": "qualification-record", "sha256": executed["license.authority"][0]}], reason="synthetic-authority")
    gates[2] = gate("package.render", "pass", adapter,
                   [{"kind": "source-manifest", "sha256": output["source_manifest_sha256"]},
                    {"kind": "qualification-record", "sha256": executed["package.render"][0]}], reason="independent-fixture-verification")
    return intent, capture, profile, output, gates, policy


def observation(output, state="absent", *, at=T0, remote=None, revisions=None, contribution=None):
    readback = {"authenticated": True, "transport": "ok", "presence": "absent", "components": {},
                "content_identity_sha256": None, "level": "full"}
    if state in {"exact", "incomplete", "conflict"}:
        readback.update(presence="present", content_identity_sha256=output["content_identity_sha256"],
                        components=expected_components(output))
    if state == "incomplete":
        readback["components"].pop(next(iter(readback["components"])))
    if state == "conflict":
        readback["content_identity_sha256"] = "c" * 64
    if state in {"unknown", "unreachable"}:
        readback.update(authenticated=False, transport=state, presence="unknown", level="none")
    return observe(output["destination"], output["subject"], expected_components(output), output["content_identity_sha256"],
                   readback=readback, source="synthetic-fixture", observed_at=at, remote=remote,
                   revisions=revisions, contribution=contribution)


def make_plan(bundle, state="absent", *, at=T0, evaluation=T0, remote=None):
    intent, capture, profile, output, gates, policy = bundle
    return plan(intent, capture, profile, output, gates, policy, observation(output, state, at=at, remote=remote), evaluated_at=evaluation)
