"""Observation-only PRoot summaries; no signal repair or sandbox qualification."""


def signal_observations(details):
    """Separate a validated guest wait from outer delivery and the group control."""
    observations = []
    for stage in details.get("stages", [])[:16]:
        if stage.get("stage") != "wait-signal-death":
            continue
        data = stage.get("details", {})
        wait = data.get("wait", {})
        record = wait.get("record") or {}
        if (data.get("raw_returncode") == 255 and wait.get("status") == "valid" and
                wait.get("signal_status_collapsed") is True and wait.get("status_mapped") is False and
                record.get("kind") == "signaled" and record.get("signal") == 15):
            observations.append("validated-guest-sigterm-host-exit-255")
    outer = details.get("external_sigterm", {})
    layers = outer.get("observed_layers", {})
    survival = outer.get("layer_survival", {})
    complete = (layers.get("status") == "observed" and layers.get("scan_incomplete") is False and
                layers.get("limit_exceeded") is False and survival.get("status") == "completed")
    if complete:
        survivors = {r.get("pid") for r in survival.get("records", [])[:64] if r.get("survived") is True}
        proot = [p for p in layers.get("layers", [])[:64] if p.get("basename_class") == "proot"]
        if any(p.get("sigterm", {}).get("ignored") is True and p.get("pid") in survivors for p in proot):
            observations.append("proot-sigterm-ignored-and-surviving")
        if outer.get("delivery_scope") == "outer-process" and outer.get("guest_handler_observed") is False:
            observations.append("outer-delivery-handler-unobserved")
    group = outer.get("process_group_control", {})
    if group.get("delivery_scope") == "process-group" and group.get("guest_handler_observed") is True:
        observations.append("group-control-handler-observed")
    return {"basis": "validated-wait-and-observed-layer-state", "observations": sorted(observations),
            "forwarding_cause": "unresolved", "status_mapped": False, "qualification_authority": False}


def webkit_conditions(web, sandboxed):
    """Existing gate predicates only; helper stderr cannot become an app failure cause."""
    failed = []
    if len(web) != len(sandboxed):
        failed.append("web-process-not-bwrap-child")
    if any(w.get("no_new_privs") != 1 for w in web):
        failed.append("no-new-privs-not-1")
    if any(w.get("seccomp") != 2 for w in web):
        failed.append("seccomp-not-2")
    return {"failed_conditions": failed, "sandbox_cause": "unresolved",
            "helper_probe_is_application_spawn": False, "sandbox_api_call_observed": False}
