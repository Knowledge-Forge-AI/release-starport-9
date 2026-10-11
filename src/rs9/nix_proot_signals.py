"""Independent raw signal stages plus a separate, non-remapping wait diagnostic."""
import json
import platform
import secrets
import signal
import subprocess
import time

from rs9.nix_proot_launch import DIAGNOSTIC_ERRORS, classify_failure, diagnostic_failure
from rs9.nix_proot_wait import diagnostic_guest_run


def probe_signals(rt, external_sigterm, reap):
    name = "proot-args-exit-signals"
    python = [rt.facts["python"], "-I", "-S", "-B", "-c"]
    stages = []

    def row(stage, run, passed, reason, **details):
        cause = classify_failure(run)
        launch_reason = cause.pop("reason")
        if passed:
            cause["error_class"] = "none"
        else:
            cause["launch_reason"] = launch_reason
        stages.append({"stage": stage, "status": "pass" if passed else "fail",
                       **({"reason": reason or launch_reason} if not passed else {}),
                       "details": {**cause, **details, "raw_returncode": run.returncode}})

    args = ["arg with space", "--flag=value", "semi;colon", "quote'test", "new\nline", "", "$HOME", "*"]
    run = rt.run(name, [*python, "import sys,json;print(json.dumps(sys.argv[1:]))", *args], timeout=30)
    try:
        forwarded = json.loads(run.stdout) == args
    except (ValueError, UnicodeError):
        forwarded = False
    row("arguments", run, not run.error and run.returncode == 0 and forwarded,
        "argument-forwarding-mismatch" if run.returncode == 0 and not run.error else None)
    verified = []
    for code in (0, 7, 42, 255):
        run = rt.run(name, [*python, f"import sys;sys.exit({code})"], timeout=30)
        passed = not run.error and run.returncode == code
        if passed:
            verified.append(code)
        row("exit-" + str(code), run, passed,
            "deliberate-exit-255-misreported" if code == 255 else "exit-code-propagation-failed", expected_exit=code)

    signal_code = ("import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_DFL);"
                   "os.kill(os.getpid(),signal.SIGTERM);time.sleep(5)")
    run = rt.run(name, [*python, signal_code], timeout=30)
    raw_signal_status = run.returncode
    row("raw-signal-death", run, not run.error and run.returncode in {-signal.SIGTERM, 128 + signal.SIGTERM},
        "guest-signal-status-not-propagated")
    # Fresh separate arms distinguish true signal death from an ordinary 255.
    # The runtime/wrapper itself retains the raw status, even when PRoot loses it.
    for label, code, kind, expected in (("wait-signal-death", signal_code, "signaled", 15),
                                       ("wait-deliberate-255", "import sys;sys.exit(255)", "exited", 255)):
        try:
            run, diagnostic = diagnostic_guest_run(rt, label, [*python, code])
        except DIAGNOSTIC_ERRORS as error:
            failure = diagnostic_failure(label, error)
            stages.append({"stage": label, "status": "fail", "reason": failure["reason"], "details": failure})
            continue
        record = diagnostic.get("record") or {}
        observed = record.get("signal") if kind == "signaled" else record.get("exit_code")
        passed = (not run.error and diagnostic.get("status") == "valid" and
                  diagnostic.get("compatible_status") is True and record.get("kind") == kind and observed == expected)
        extra = {}
        if (kind == "signaled" and not run.error and diagnostic.get("status") == "valid"
                and diagnostic.get("signal_status_collapsed") is True and observed == 15 and run.returncode == 255):
            extra["signal_status_token"] = "observed-signal-status-collapse"
            extra["diagnostic_token"] = "observed-signal-status-collapse"
        row(label, run, passed, diagnostic.get("reason") or "guest-wait-evidence-incomplete", wait=diagnostic, **extra)

    native_prefix_sigterm = None
    if platform.system() == "Linux":
        start = time.monotonic()
        try:
            result = rt.runner([*rt.prefix, *python, signal_code], env=rt.host_env(), capture_output=True, timeout=30)
            from rs9.nix_proot import Run
            run_native = Run(result.returncode, result.stdout, result.stderr, time.monotonic() - start, None)
        except OSError:
            from rs9.nix_proot import Run
            run_native = Run(None, b"", b"", time.monotonic() - start, "spawn-failed")
        except subprocess.TimeoutExpired:
            from rs9.nix_proot import Run
            run_native = Run(None, b"", b"", time.monotonic() - start, "timeout")
        native_passed = not run_native.error and run_native.returncode in {-signal.SIGTERM, 128 + signal.SIGTERM}
        receipt = {"status": "pass" if native_passed else "fail", **classify_failure(run_native)}
        if native_passed:
            receipt.pop("reason", None)
            receipt["error_class"] = "none"
        native_prefix_sigterm = {
            "arm": "native-prefix-self-sigterm",
            "status": "pass" if native_passed else "fail",
            "raw_returncode": run_native.returncode,
            "receipt": receipt,
            "qualification_authority": False,
            "claim_patched": False,
        }
    else:
        native_prefix_sigterm = {
            "arm": "native-prefix-self-sigterm",
            "status": "unavailable",
            "reason": "linux-native-prefix-unavailable-on-provider",
            "qualification_authority": False,
            "claim_patched": False,
        }

    nonce = secrets.token_hex(16)
    orphan_code = ("import subprocess,sys;subprocess.Popen([sys.executable,'-I','-S','-B','-c',"
                   "'import time;time.sleep(600)',sys.argv[1]]);import os;os._exit(0)")
    run = rt.run(name, [*python, orphan_code, nonce], timeout=30)
    survivors = reap(nonce.encode())
    row("orphan", run, not run.error and run.returncode == 0 and not survivors,
        "orphaned-tracee-survived" if survivors else None, orphaned_tracees=survivors,
        cleanup_scope="created-process-group-and-proot-kill-on-exit", nonce_match_has_kill_authority=False)
    external = external_sigterm(rt, name)
    stages.append({"stage": "external-sigterm", **external})
    failed = next((r for r in stages if r["status"] != "pass"), None)
    details = {"stages": stages, "exit_codes_verified": verified, "guest_signal_exit_code": raw_signal_status,
               "raw_proot_signal_status": raw_signal_status, "orphaned_tracees": survivors,
               "external_sigterm": external["details"], "status_mapping_enabled": False,
               "native_prefix_sigterm": native_prefix_sigterm}
    if failed:
        # Keep historical top-level failure details while retaining later stages.
        details.update(failed["details"])
        return {"name": name, "status": "fail", "reason": failed.get("reason"), "details": details}
    return {"name": name, "status": "pass", "details": details}
