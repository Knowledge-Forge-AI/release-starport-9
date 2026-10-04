"""Static invariant testing for RS9 hosted candidate GitHub Actions workflow."""
from pathlib import Path
import json
import re
import unittest

from rs9.hosted_contract import generate_matrix_outputs

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/rs9-candidate-tests.yml"


def _parse_yaml(text: str) -> dict:

    in_jobs = False
    jobs: dict[str, Any] = {}
    current_job = None
    current_section = None

    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        m_job = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if m_job:
            current_job = m_job.group(1)
            jobs[current_job] = {"outputs": {}, "strategy": {}, "text": ""}
            current_section = None
            continue
        if current_job:
            jobs[current_job]["text"] += line + "\n"
            m_timeout = re.match(r"^    timeout-minutes:\s*(.+)$", line)
            if m_timeout:
                value = m_timeout.group(1)
                jobs[current_job]["timeout-minutes"] = int(value) if value.isdigit() else value
            m_needs = re.match(r"^    needs:\s*\[(.*?)\]", line)
            if m_needs:
                jobs[current_job]["needs"] = [x.strip() for x in m_needs.group(1).split(",")]
            m_if = re.match(r"^    if:\s*(.*)", line)
            if m_if:
                jobs[current_job]["if"] = m_if.group(1).strip()
            if re.match(r"^\s+outputs:\s*$", line):
                current_section = "outputs"
                continue
            elif re.match(r"^\s+strategy:\s*$", line):
                current_section = "strategy"
                continue
            elif re.match(r"^\s+steps:\s*$", line):
                current_section = "steps"
                continue
            m_out = re.match(r"^\s+([a-zA-Z0-9_]+):\s*(.*)", line)
            if m_out and current_section == "outputs":
                jobs[current_job]["outputs"][m_out.group(1)] = m_out.group(2).strip()
            m_matrix = re.match(r"^\s+matrix:\s*(.*)", line)
            if m_matrix:
                jobs[current_job]["strategy"]["matrix"] = m_matrix.group(1).strip()

    return {"jobs": jobs}


def workflow_contract_errors(text, contract):
    """Check the emitted workflow jobs, artifact names and timeouts against source."""
    jobs = _parse_yaml(text)["jobs"]
    errors = []
    if set(jobs) != set(contract["required_jobs"]):
        errors.append("required-jobs")
    matrices = generate_matrix_outputs(contract)
    matrix_lanes = set()
    for name in ("wheels", "nix", "native"):
        job = jobs.get(name, {})
        if job.get("timeout-minutes") != "${{ matrix.timeout_minutes }}":
            errors.append(name + ":timeout")
        uploads = re.findall(r"(?m)^          name: (.+)$", job.get("text", ""))
        if uploads != ["${{ matrix.artifact_name }}"]:
            errors.append(name + ":artifact")
        for row in json.loads(matrices["matrix_" + name])["include"]:
            lane = row.get("lane", name)
            matrix_lanes.add((lane, row["system"]))
            source = next(l for l in contract["lanes"] if (l["lane"], l["system"]) == (lane, row["system"]))
            if any(row[key] != source[key] for key in ("artifact_name", "timeout_minutes", "runner")):
                errors.append(name + ":matrix-source")
    expected_matrix = {(l["lane"], l["system"]) for l in contract["lanes"]
                       if l["lane"] in {"wheels", "nix", "pacman", "rpm", "deb"}}
    if matrix_lanes != expected_matrix:
        errors.append("matrix-lanes")
    for lane in contract["lanes"]:
        if (lane["lane"], lane["system"]) in expected_matrix:
            continue
        name = lane["lane"]
        job = jobs.get(name, {})
        if job.get("timeout-minutes") != lane["timeout_minutes"]:
            errors.append(name + ":timeout")
        uploads = re.findall(r"(?m)^          name: (.+)$", job.get("text", ""))
        expected = [lane["artifact_name"]] if lane.get("module") else ["hosted-summary"] if name == "summary" else []
        if uploads != expected:
            errors.append(name + ":artifact")
    if set(jobs.get("summary", {}).get("needs", [])) != set(contract["required_jobs"]) - {"summary"}:
        errors.append("summary-needs")
    return errors


class WorkflowStaticTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_permissions_read_only(self):
        self.assertIn("permissions:\n  contents: read", self.text)
        for forbidden in (
            "contents: write",
            "pages: write",
            "packages: write",
            "id-token:",
            "id-token: write",
            "security-events: write",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_triggers_and_branch_restriction(self):
        self.assertIn("push:\n    branches: [main]", self.text)
        self.assertNotIn("pull_request:", self.text)
        self.assertIn("workflow_dispatch:", self.text)
        self.assertNotIn("pull_request_target:", self.text)

    def test_sha_pinned_actions(self):
        uses = re.findall(r"uses:\s*(\S+)", self.text)
        self.assertTrue(uses)
        for action in uses:
            self.assertTrue(
                re.fullmatch(r"[\w-]+/[\w-]+@[0-9a-f]{40}", action),
                f"Action {action} is not pinned to a 40-character SHA",
            )

    def test_checkout_persist_credentials_false(self):
        checkout_count = self.text.count("uses: actions/checkout@")
        persist_count = self.text.count("persist-credentials: false")
        self.assertEqual(checkout_count, persist_count)
        self.assertGreater(checkout_count, 0)

    def test_no_oidc_secrets_or_environments(self):
        for forbidden in ("secrets.", "id-token:", "environment:", "deploy-pages"):
            self.assertNotIn(forbidden, self.text)

    def test_artifact_retention_90_days(self):
        upload_count = self.text.count("uses: actions/upload-artifact@")
        retention_count = self.text.count("retention-days: 90")
        self.assertEqual(upload_count, retention_count)
        self.assertGreater(upload_count, 0)

    def test_bounded_jobs_have_timeouts(self):
        doc = _parse_yaml(self.text)
        jobs = doc.get("jobs", {})
        self.assertTrue(jobs)
        for job_name, job_cfg in jobs.items():
            self.assertIn(
                "timeout-minutes",
                job_cfg,
                f"Job {job_name} lacks bounded timeout-minutes",
            )
            value = job_cfg["timeout-minutes"]
            if isinstance(value, int):
                self.assertLessEqual(value, 120)
            else:
                self.assertEqual(value, "${{ matrix.timeout_minutes }}")

    def test_jobs_artifacts_and_timeouts_match_source_contract(self):
        contract = json.loads((ROOT / "operators/live1/hosted-lanes.json").read_bytes())
        self.assertEqual(workflow_contract_errors(self.text, contract), [])

    def test_workflow_contract_detects_missing_jobs_artifacts_and_timeouts(self):
        contract = json.loads((ROOT / "operators/live1/hosted-lanes.json").read_bytes())
        for before, after, error in (
            ("  pins:\n", "  renamed-pins:\n", "required-jobs"),
            ("name: candidate-pins-generation", "name: wrong-pins-generation", "pins:artifact"),
            ("timeout-minutes: ${{ matrix.timeout_minutes }}", "timeout-minutes: 120", "wheels:timeout"),
        ):
            self.assertIn(error, workflow_contract_errors(self.text.replace(before, after, 1), contract))

    def test_matrix_from_source_config_job_outputs(self):
        doc = _parse_yaml(self.text)
        jobs = doc.get("jobs", {})
        self.assertIn("config", jobs)
        config_outputs = jobs["config"].get("outputs", {})
        self.assertIn("matrix_wheels", config_outputs)
        self.assertIn("matrix_nix", config_outputs)
        self.assertIn("matrix_native", config_outputs)

        for job_name in ("wheels", "nix", "native"):
            matrix_expr = jobs[job_name]["strategy"]["matrix"]
            self.assertIn(f"needs.config.outputs.matrix_{job_name}", str(matrix_expr))

    def test_summary_aggregates_use_not_cancelled(self):
        doc = _parse_yaml(self.text)
        summary = doc["jobs"]["summary"]
        self.assertIn("always()", summary.get("if", ""))
        needs = summary.get("needs", [])
        for required_need in ("config", "unit", "pins", "authenticate", "wheels", "nix", "native", "foundation3", "observe"):
            self.assertIn(required_need, needs)

    def test_observe_job_is_independent(self):
        doc = _parse_yaml(self.text)
        observe = doc["jobs"]["observe"]
        needs = observe.get("needs", [])
        self.assertEqual(needs, ["config","authenticate"])

    def test_unit_static_lane_included(self):
        doc = _parse_yaml(self.text)
        self.assertIn("unit", doc["jobs"])


if __name__ == "__main__":
    unittest.main()
