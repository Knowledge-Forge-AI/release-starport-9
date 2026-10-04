"""Authenticated Burst loader records and target-native clean-client proofs."""
import json
from pathlib import Path
import re

from rs9.burst_native import BURST_CLOSED_PREBUILDS, BURST_PRODUCT_ID
from rs9.errors import ContractError
from rs9.hosted_burst import validate_load_receipt
from rs9.hosted_platforms import platform_contract
from rs9.scratch import canonical


def release_load_record(capture, system):
    """Select identities from the already authenticated complete release manifest."""
    contract = platform_contract(system)
    payloads = capture.record.get("payloads", [])
    if capture.record.get("repository", {}).get("full_name") != "Knowledge-Forge-AI/" + BURST_PRODUCT_ID:
        raise ContractError("BURST_NATIVE_TARGET", "Burst authenticated capture required")
    if len(payloads) != 1:
        raise ContractError("BURST_NATIVE_TARGET", "One authenticated Burst release payload required")
    members = capture.manifests[payloads[0]["id"]]["members"]
    def identity(path):
        rows = [row for row in members if row["path"] == path]
        if (len(rows) != 1 or rows[0].get("type") != "file"
                or not re.fullmatch(r"[0-9a-f]{64}", rows[0].get("sha256", ""))):
            raise ContractError("BURST_NATIVE_TARGET", "Authenticated regular target and loader identities required")
        return {"path": path, "sha256": rows[0]["sha256"]}
    return {"platform_specific": True, "target_system": system,
            "target_native_addon": identity(BURST_CLOSED_PREBUILDS[contract.native_prebuild_key]),
            "native_loader": identity("package/dist/directory-snapshot-native.js")}


def verify_client_burst(client, record, system, scratch, *, user):
    """Read and exercise the installed payload inside the disconnected client."""
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=False)
    scratch.chmod(0o777)
    code = (
        "import json,sys;from pathlib import Path;sys.path.insert(0,'/rs9-source');"
        "from rs9.hosted_burst import verify_burst_payload;"
        "record=json.loads(sys.argv[1]);"
        "result=verify_burst_payload('/usr/lib/theme-forge-stellar-burst',record,sys.argv[2],"
        "Path(sys.argv[3]),layout_prefix='');print(json.dumps(result))"
    )
    result = client.exec(["python3", "-c", code, canonical(record).decode(), system, str(scratch)], user=user)
    if result.exit_code or not result.executed or len(result.stdout_bytes) > 4096:
        raise ContractError("BURST_NATIVE_LOAD", "Installed client Burst loader failed",
                            details={"exit_code": result.exit_code, "stdout_sha256": result.stdout_sha256,
                                     "stderr_sha256": result.stderr_sha256})
    try:
        receipt = json.loads(result.stdout_bytes)
    except (ValueError, UnicodeError):
        raise ContractError("BURST_NATIVE_LOAD", "Bounded installed client load receipt required") from None
    if not isinstance(receipt, dict) or receipt.pop("status", None) != "pass" or receipt.pop("proof", None) != "installed-released-loader-self-test":
        raise ContractError("BURST_NATIVE_LOAD", "Installed client loader success required")
    return validate_load_receipt(receipt, record["target_native_addon"], system,
                                 expected_addon_path=record["target_native_addon"]["path"].removeprefix("package/"))
