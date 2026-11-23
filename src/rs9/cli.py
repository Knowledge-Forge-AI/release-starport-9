"""Small, bounded command-line interface for Release Starport 9.

This module deliberately owns only the source-facing CLI boundary.  It calls
the existing contract loader and normalizer; it does not discover projects,
contact destinations, inspect authentication state, or perform publication.
The explicit existing-repository GitHub family delegates its bounded remote
protocol to ``rs9.github_cli``.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

CLI_SCHEMA = "rs9.cli.v1alpha1"
DIST_NAME = "release-starport-9"
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")


class _UsageError(Exception):
    """Internal signal for a closed, non-echoing argparse error."""


class _HelpDisplayed(Exception):
    """Internal signal after argparse has written help text."""


class _OutputFailure(Exception):
    """Internal signal for a closed output-stream failure."""


class _HelpOutputFailure(Exception):
    """Internal signal for a help writer failure before argparse exits."""


class _InstanceOperationalFailure(Exception):
    """Closed signal carrying a validated local instance result."""

    def __init__(self, code: str, outcome: str, result: Mapping[str, Any]) -> None:
        super().__init__(code)
        self.code = code
        self.outcome = outcome
        self.result = result


class _NullWriter:
    """Minimal no-op text stream used after a stdio channel fails."""

    encoding = "utf-8"
    errors = "strict"

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class _ArgumentParser(argparse.ArgumentParser):
    """Argument parser that never includes an invalid token in an error."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        raise _UsageError

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if message:
            self._print_message(message, sys.stdout if status == 0 else sys.stderr)
        if status == 0:
            raise _HelpDisplayed
        raise _UsageError

    def _print_message(self, message: str, file: TextIO | None = None) -> None:
        if not message:
            return
        stream = sys.stdout if file is None else file
        try:
            # The only argparse message admitted by this parser is help text,
            # which is always directed to stdout.  Keep that classification
            # explicit even when argparse passes an explicit file object.
            _write_text(stream, message, stdout=True)
        except _OutputFailure:
            raise _HelpOutputFailure from None


def _add_json_option(parser: argparse.ArgumentParser) -> None:
    # ``SUPPRESS`` lets ``rs9 --json doctor`` and ``rs9 doctor --json`` share
    # one destination without a subparser default overwriting the root value.
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="write a stable JSON envelope",
    )


def _add_instance_plan_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    parser.add_argument("--consumer", dest="consumer_id", metavar="CONSUMER_ID", required=True)
    parser.add_argument("--project", metavar="PROJECT", required=True)
    parser.add_argument("--destinations", metavar="FILE", required=True)
    parser.add_argument("--version", dest="release_version", metavar="RELEASE_VERSION", required=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="rs9",
        description="Release Starport 9 offline contract tools",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        dest="show_version",
        help="show the installed RS9 distribution version",
    )
    _add_json_option(parser)

    commands = parser.add_subparsers(
        dest="command",
        parser_class=_ArgumentParser,
    )

    doctor = commands.add_parser(
        "doctor",
        help="report local Python and gh executable capabilities",
        description="Report local capabilities without reading auth or remote state.",
    )
    _add_json_option(doctor)

    project = commands.add_parser(
        "project",
        help="validate or prepare an offline project intent",
        description="Offline project contract operations only.",
    )
    _add_json_option(project)
    project_commands = project.add_subparsers(
        dest="project_command",
        parser_class=_ArgumentParser,
    )

    validate = project_commands.add_parser(
        "validate",
        help="validate a project contract",
    )
    validate.add_argument("project", metavar="PROJECT")
    validate.add_argument("--destinations", metavar="FILE")
    _add_json_option(validate)

    intent = project_commands.add_parser(
        "intent",
        help="prepare a normalized offline project intent",
    )
    intent.add_argument("project", metavar="PROJECT")
    intent.add_argument("--destinations", metavar="FILE", required=True)
    intent.add_argument("--version", dest="release_version", metavar="RELEASE_VERSION", required=True)
    _add_json_option(intent)

    adapter = commands.add_parser(
        "adapter",
        help="render one offline adapter candidate",
        description="Offline adapter candidate operations only.",
    )
    _add_json_option(adapter)
    adapter_commands = adapter.add_subparsers(
        dest="adapter_command",
        parser_class=_ArgumentParser,
    )

    homebrew = adapter_commands.add_parser(
        "homebrew",
        help="render one Homebrew formula candidate",
        description="Offline Homebrew formula rendering only.",
    )
    _add_json_option(homebrew)
    homebrew_commands = homebrew.add_subparsers(
        dest="homebrew_command",
        parser_class=_ArgumentParser,
    )

    homebrew_render = homebrew_commands.add_parser(
        "render",
        help="render one reviewable Homebrew formula",
    )
    homebrew_render.add_argument("--normalized", required=True, metavar="FILE")
    homebrew_render.add_argument("--payload-facts", required=True, metavar="FILE")
    homebrew_render.add_argument("--variant", required=True, choices=("cli-archive",), metavar="VARIANT")
    homebrew_render.add_argument("--output", required=True, metavar="DIRECTORY")
    _add_json_option(homebrew_render)

    instance = commands.add_parser(
        "instance",
        help="configure or plan a local publisher-root instance",
        description="Local publisher-root and explicit existing-repository GitHub operations.",
    )
    _add_json_option(instance)
    instance_commands = instance.add_subparsers(
        dest="instance_command",
        parser_class=_ArgumentParser,
    )

    instance_init = instance_commands.add_parser(
        "init",
        help="create or inspect a local publisher-root instance",
    )
    instance_init.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    instance_init.add_argument("--id", dest="instance_id", metavar="INSTANCE_ID", required=True)
    instance_init.add_argument("--template", default="github-homebrew-projection", metavar="TEMPLATE_ID")
    instance_init.add_argument("--template-version", default="v1alpha1", metavar="TEMPLATE_VERSION")
    instance_init.add_argument("--publisher-repository", metavar="OWNER/REPO", required=True)
    instance_init.add_argument("--publisher-branch", metavar="BRANCH", required=True)
    instance_init.add_argument("--runner", default="ubuntu-24.04", metavar="RUNNER")
    instance_init.add_argument("--environment", default="rs9-publish", metavar="ENVIRONMENT")
    instance_init.add_argument("--operator-binding", default="github-actions-oidc", metavar="BINDING")
    _add_json_option(instance_init)

    instance_register = instance_commands.add_parser(
        "register",
        help="register one validated consumer locally",
    )
    instance_register.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    instance_register.add_argument("--id", dest="consumer_id", metavar="CONSUMER_ID", required=True)
    instance_register.add_argument("--project", metavar="PROJECT", required=True)
    instance_register.add_argument("--destinations", metavar="FILE", required=True)
    instance_register.add_argument("--destination", dest="destination_id", metavar="DESTINATION_ID", required=True)
    instance_register.add_argument("--package", dest="package_id", metavar="PACKAGE_ID", required=True)
    _add_json_option(instance_register)

    instance_plan = instance_commands.add_parser(
        "plan",
        help="prepare an offline publisher-root desired-state plan",
    )
    _add_instance_plan_inputs(instance_plan)
    _add_json_option(instance_plan)

    instance_plan_upgrade = instance_commands.add_parser(
        "plan-upgrade", help="review changed consumer inputs against an existing registration",
    )
    _add_instance_plan_inputs(instance_plan_upgrade)
    _add_json_option(instance_plan_upgrade)

    instance_apply_upgrade = instance_commands.add_parser(
        "apply-upgrade", help="apply or resume one reviewed local consumer upgrade",
    )
    _add_instance_plan_inputs(instance_apply_upgrade)
    instance_apply_upgrade.add_argument("--plan", type=Path, required=True, metavar="FILE")
    instance_apply_upgrade.add_argument(
        "--dry-run", action="store_true", help="verify the saved review and publisher state without writing",
    )
    _add_json_option(instance_apply_upgrade)

    instance_github = instance_commands.add_parser(
        "github",
        help="inspect or apply an existing GitHub instance",
        description="Explicit existing-repository GitHub instance operations.",
    )
    _add_json_option(instance_github)
    github_commands = instance_github.add_subparsers(
        dest="github_command",
        parser_class=_ArgumentParser,
    )

    github_doctor = github_commands.add_parser(
        "doctor",
        help="report local GitHub transport and engine-artifact capabilities",
    )
    github_doctor.add_argument("--engine-wheel", metavar="PATH")
    _add_json_option(github_doctor)

    github_plan = github_commands.add_parser(
        "plan",
        help="read a fresh GitHub state and write one new plan file",
    )
    github_plan.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_plan.add_argument("--engine-wheel", metavar="PATH", required=True)
    github_plan.add_argument("--output", metavar="PLAN", required=True)
    _add_json_option(github_plan)

    github_apply = github_commands.add_parser(
        "apply",
        help="apply one explicit existing-repository plan",
    )
    github_apply.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_apply.add_argument("--plan", dest="plan_path", metavar="PLAN", required=True)
    github_apply.add_argument("--engine-wheel", metavar="PATH", required=True)
    github_apply.add_argument("--operation-id", metavar="OPERATION_ID")
    _add_json_option(github_apply)

    github_resume = github_commands.add_parser(
        "resume",
        help="perform explicit read-only remote recovery for one journal",
    )
    github_resume.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_resume.add_argument("--operation-id", required=True, metavar="OPERATION_ID")
    github_resume.add_argument("--engine-wheel", metavar="PATH", required=True)
    github_resume.add_argument("--prior-result", metavar="RESULT")
    _add_json_option(github_resume)

    github_provision_plan = github_commands.add_parser(
        "provision-plan",
        help="read fresh GitHub state and write one repository-provisioning plan",
    )
    github_provision_plan.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_provision_plan.add_argument("--engine-wheel", metavar="PATH", required=True)
    github_provision_plan.add_argument("--output", metavar="PLAN", required=True)
    github_provision_plan.add_argument("--operation-id", metavar="OPERATION_ID", required=True)
    _add_json_option(github_provision_plan)

    github_provision_apply = github_commands.add_parser(
        "provision-apply",
        help="apply one exact repository-provisioning plan",
    )
    github_provision_apply.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_provision_apply.add_argument("--plan", dest="plan_path", metavar="PLAN", required=True)
    github_provision_apply.add_argument("--engine-wheel", metavar="PATH", required=True)
    github_provision_apply.add_argument("--operation-id", metavar="OPERATION_ID", required=True)
    _add_json_option(github_provision_apply)

    github_provision_resume = github_commands.add_parser(
        "provision-resume",
        help="perform read-only repository-provisioning recovery",
    )
    github_provision_resume.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    github_provision_resume.add_argument("--operation-id", metavar="OPERATION_ID", required=True)
    github_provision_resume.add_argument("--engine-wheel", metavar="PATH", required=True)
    _add_json_option(github_provision_resume)

    return parser


def distribution_version() -> str:
    """Return matching installed metadata or the source-checkout fallback.

    A different installed distribution can be visible while ``PYTHONPATH``
    selects this checkout.  Its version must not be reported for this source.
    """

    try:
        distribution = importlib.metadata.distribution(DIST_NAME)
    except importlib.metadata.PackageNotFoundError:
        return "unreleased"
    try:
        installed_cli = Path(distribution.locate_file("rs9/cli.py")).resolve()
        current_cli = Path(__file__).resolve()
    except (OSError, RuntimeError):
        return "unreleased"
    if installed_cli != current_cli:
        return "unreleased"
    return distribution.version


def _envelope(command: str, *, result: Any = None, error: dict[str, str] | None = None) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "schema": CLI_SCHEMA,
        "command": command,
        "ok": error is None,
    }
    if error is None:
        envelope["result"] = result
    else:
        if result is not None:
            envelope["result"] = result
        envelope["error"] = error
    return envelope


def _neutralize_fd(fd: int) -> None:
    """Point a standard stream fd at devnull so finalization cannot fail."""

    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        pass
    else:
        try:
            os.dup2(null_fd, fd)
        except OSError:
            pass
        finally:
            if null_fd != fd:
                try:
                    os.close(null_fd)
                except OSError:
                    pass


def _neutralize_output(stream_name: str, stream: TextIO | None) -> None:
    """Make a failed stdio channel safe for the rest of this process."""

    fd = 1 if stream_name == "stdout" else 2
    original = getattr(sys, f"__{stream_name}__", None)
    is_process_stream = stream is None or stream is original
    if is_process_stream:
        _neutralize_fd(fd)
    replacement = _NullWriter()
    setattr(sys, stream_name, replacement)


def _write_text(stream: TextIO | None, text: str, *, stdout: bool) -> None:
    stream_name = "stdout" if stdout else "stderr"
    if stream is None:
        _neutralize_output(stream_name, stream)
        raise _OutputFailure from None
    try:
        stream.write(text)
        stream.flush()
    except BrokenPipeError:
        _neutralize_output(stream_name, stream)
        raise _OutputFailure from None
    except (OSError, UnicodeError, ValueError, AttributeError):
        _neutralize_output(stream_name, stream)
        raise _OutputFailure from None


def _write_envelope(command: str, *, result: Any = None, error: dict[str, str] | None = None,
                    stream: TextIO, stdout: bool) -> None:
    payload = _envelope(command, result=result, error=error)
    _write_text(
        stream,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        stdout=stdout,
    )


def _emit_error(command: str, code: str, message: str, *, json_output: bool,
                result: Any = None) -> None:
    # Error messages are intentionally closed.  The current contract engine
    # already avoids echoing values, but the CLI must retain that property if a
    # future validator adds a more detailed diagnostic.
    if json_output:
        _write_envelope(
            command,
            result=result,
            error={"code": code, "message": message},
            stream=sys.stderr,
            stdout=False,
        )
    else:
        _write_text(sys.stderr, f"Error [{code}]: {message}\n", stdout=False)


def _report_error(command: str, code: str, message: str, *, status: int, json_output: bool,
                  result: Any = None) -> int:
    try:
        _emit_error(command, code, message, json_output=json_output, result=result)
    except _OutputFailure:
        return 3
    return status


def _contract_error_info(error: BaseException) -> tuple[str, str] | None:
    """Recognize the current engine's ContractError without importing it early."""

    try:
        from rs9.errors import ContractError
    except ImportError:
        return None
    if not isinstance(error, ContractError):
        return None
    code = getattr(error, "code", "CONTRACT_REJECTED")
    if not isinstance(code, str) or not code.isascii() or not code.replace("_", "").isalnum():
        code = "CONTRACT_REJECTED"
    return code, "Contract input rejected."


def _run_doctor() -> dict[str, Any]:
    """Read only interpreter capability and executable presence from PATH."""

    try:
        import tomllib
    except ImportError:
        tomllib_available = False
    else:
        tomllib_available = callable(getattr(tomllib, "loads", None))

    return {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "tomllib": tomllib_available,
        },
        # ``which`` checks executable availability only; no gh process is run,
        # so auth/config/token files and remote state are never consulted.
        "gh": {"available": shutil.which("gh") is not None},
    }


def _run_validate(project: str, destinations: str | None) -> dict[str, Any]:
    from rs9.contract import load_destinations, load_project
    from rs9.validator import cross_validate

    project_map = load_project(project)
    destinations_validated = destinations is not None
    if destinations_validated:
        destinations_doc = load_destinations(destinations)
        cross_validate(project_map, destinations_doc)
    return {
        "status": "valid",
        "projectValidated": True,
        "destinationsValidated": destinations_validated,
    }


def _run_intent(project: str, destinations: str, version: str) -> dict[str, Any]:
    from rs9.contract import normalize

    normalized = json.loads(normalize(project, destinations, version).decode("utf-8"))
    return {
        "intent": normalized,
        "remoteState": "unknown",
        "publicationAuthority": False,
    }


def _run_adapter_homebrew_render(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.installed_homebrew import render_homebrew_output

    stdin = getattr(sys.stdin, "buffer", sys.stdin)
    return render_homebrew_output(
        normalized_source=args.normalized,
        payload_facts_source=args.payload_facts,
        variant=args.variant,
        output_dir=args.output,
        engine={"distribution": DIST_NAME, "version": distribution_version()},
        stdin=stdin,
    )


def _run_instance_init(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.instance import init_instance

    # The command binds the version observed by this running engine.  There is
    # deliberately no CLI engine-version override that could make an installed
    # command claim a different distribution identity.
    result = dict(init_instance(
        args.publisher_root,
        instance_id=args.instance_id,
        publisher_repository=args.publisher_repository,
        publisher_branch=args.publisher_branch,
        engine_version=distribution_version(),
        template_id=args.template,
        template_version=args.template_version,
        runner=args.runner,
        environment=args.environment,
        operator_binding=args.operator_binding,
    ))
    _require_instance_success(result)
    return result


def _run_instance_register(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.instance import register_consumer

    runtime_version = distribution_version()
    result = dict(register_consumer(
        args.publisher_root,
        consumer_id=args.consumer_id,
        project=args.project,
        destinations=args.destinations,
        destination_id=args.destination_id,
        package_id=args.package_id,
        version_provider=lambda: runtime_version,
    ))
    _require_instance_success(result)
    return result


def _run_instance_plan(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.instance import plan_instance

    runtime_version = distribution_version()
    review_upgrade = args.instance_command == "plan-upgrade"
    result = dict(plan_instance(
        args.publisher_root,
        consumer_id=args.consumer_id,
        project=args.project,
        destinations=args.destinations,
        version=args.release_version,
        review_upgrade=review_upgrade,
    ))
    engine = result.get("engine")
    if (not isinstance(engine, dict) or engine.get("distribution") != DIST_NAME
            or engine.get("version") != runtime_version):
        result["configuredEngine"] = engine if isinstance(engine, dict) else {"distribution": DIST_NAME}
        result["runtimeEngine"] = {"distribution": DIST_NAME, "version": runtime_version}
        raise _InstanceOperationalFailure("ENGINE_VERSION_MISMATCH", "engine-mismatch", result)
    result["runtimeEngine"] = {"distribution": DIST_NAME, "version": runtime_version}
    if review_upgrade:
        return result
    _require_instance_plan_success(result)
    return result


def _run_instance_apply_upgrade(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.errors import ContractError
    from rs9.github_cli import _safe_read_json
    from rs9.instance import apply_consumer_upgrade

    envelope = _safe_read_json(args.plan, error_code="UPGRADE_PLAN")
    result = envelope.get("result")
    if (envelope.get("schema") != "rs9.cli.v1alpha1" or envelope.get("ok") is not True
            or envelope.get("command") != "instance.plan-upgrade" or not isinstance(result, dict)):
        raise ContractError("UPGRADE_PLAN", "An upgrade review JSON envelope is required")
    reviewed = dict(result)
    reviewed.pop("runtimeEngine", None)
    return dict(apply_consumer_upgrade(
        args.publisher_root, consumer_id=args.consumer_id, project=args.project,
        destinations=args.destinations, version=args.release_version,
        reviewed_plan=reviewed, runtime_version=distribution_version(), dry_run=args.dry_run,
    ))


def _run_instance_github_doctor(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.github_cli import doctor_instance_github_cli

    return doctor_instance_github_cli(engine_wheel=args.engine_wheel)


def _run_instance_github_plan(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.github_cli import plan_instance_github_cli

    result = plan_instance_github_cli(
        args.publisher_root,
        engine_wheel=args.engine_wheel,
        output=args.output,
    )
    if result.get("outcome") not in {"create", "noop"}:
        raise _InstanceOperationalFailure(
            "GITHUB_RESULT", f"plan-{_instance_outcome(result.get('outcome'))}", result,
        )
    return result


def _run_instance_github_apply(args: argparse.Namespace) -> dict[str, Any]:
    from rs9 import github_cli

    try:
        result = github_cli.apply_instance_github_cli(
            args.publisher_root,
            plan_path=args.plan_path,
            engine_wheel=args.engine_wheel,
            operation_id=args.operation_id,
        )
    except github_cli._OperationFailure as failure:
        raise _InstanceOperationalFailure(
            "GITHUB_OPERATION", "remote-uncertain", failure.result,
        ) from None
    decision = result.get("decision")
    status = result.get("status")
    if not ((decision == "noop" and status == "completed")
            or (decision == "completed" and status == "completed")):
        raise _InstanceOperationalFailure("GITHUB_RESULT", f"remote-{decision}", result)
    return result


def _run_instance_github_resume(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.github_cli import resume_instance_github_cli

    result = resume_instance_github_cli(
        args.publisher_root,
        operation_id=args.operation_id,
        engine_wheel=args.engine_wheel,
        prior_result=args.prior_result,
    )
    decision = result.get("decision")
    status = result.get("status")
    if not ((decision == "closed" and status == "closed")
            or (decision == "completed" and status == "completed")):
        raise _InstanceOperationalFailure("GITHUB_RESULT", f"remote-{decision}", result)
    return result


def _run_instance_github_provision_plan(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.provision_cli import plan_instance_github_provision_cli

    return plan_instance_github_provision_cli(
        args.publisher_root,
        engine_wheel=args.engine_wheel,
        output=args.output,
        operation_id=args.operation_id,
    )


def _run_instance_github_provision_apply(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.provision_cli import apply_instance_github_provision_cli

    result = apply_instance_github_provision_cli(
        args.publisher_root,
        plan_path=args.plan_path,
        engine_wheel=args.engine_wheel,
        operation_id=args.operation_id,
    )
    if result.get("status") != "completed":
        raise _InstanceOperationalFailure(
            "GITHUB_PROVISION_RESULT", "provision-held", result,
        )
    return result


def _run_instance_github_provision_resume(args: argparse.Namespace) -> dict[str, Any]:
    from rs9.provision_cli import resume_instance_github_provision_cli

    result = resume_instance_github_provision_cli(
        args.publisher_root,
        operation_id=args.operation_id,
        engine_wheel=args.engine_wheel,
    )
    if result.get("status") not in {"closed", "completed"}:
        raise _InstanceOperationalFailure(
            "GITHUB_PROVISION_RESULT", "provision-held", result,
        )
    return result


def _instance_outcome(value: Any) -> str:
    allowed = {
        "blocked", "bootstrap-required", "create", "drift", "failed", "interrupted",
        "missing", "noop", "stale", "unsafe", "uncertain", "unknown",
    }
    return value if isinstance(value, str) and value in allowed else "state"


def _operation_id_for_error(result: Mapping[str, Any]) -> str | None:
    candidates: list[Any] = [result.get("operation_id")]
    for key in ("coordinator", "resume"):
        nested = result.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested.get("operation_id"))
    for value in candidates:
        if isinstance(value, str) and _OPERATION.fullmatch(value) is not None:
            return value
    return None


def _require_instance_success(result: Mapping[str, Any]) -> None:
    outcome = result.get("outcome")
    if outcome not in {"created", "noop"}:
        raise _InstanceOperationalFailure("INSTANCE_STATE", _instance_outcome(outcome), result)


def _require_instance_plan_success(result: Mapping[str, Any]) -> None:
    local = result.get("local")
    if (not isinstance(local, dict) or local.get("state") != "noop"
            or local.get("input_state") != "exact"):
        outcome = local.get("state") if isinstance(local, dict) else "state"
        raise _InstanceOperationalFailure("INSTANCE_STATE", _instance_outcome(outcome), result)


def _command_name(args: argparse.Namespace) -> str:
    if args.command == "doctor":
        return "doctor"
    if args.command == "project" and args.project_command == "validate":
        return "project.validate"
    if args.command == "project" and args.project_command == "intent":
        return "project.intent"
    if args.command == "adapter" and args.adapter_command == "homebrew":
        if args.homebrew_command == "render":
            return "adapter.homebrew.render"
    if args.command == "instance" and args.instance_command == "init":
        return "instance.init"
    if args.command == "instance" and args.instance_command == "register":
        return "instance.register"
    if args.command == "instance" and args.instance_command == "plan":
        return "instance.plan"
    if args.command == "instance" and args.instance_command == "plan-upgrade":
        return "instance.plan-upgrade"
    if args.command == "instance" and args.instance_command == "apply-upgrade":
        return "instance.apply-upgrade"
    if args.command == "instance" and args.instance_command == "github":
        if args.github_command == "doctor":
            return "instance.github.doctor"
        if args.github_command == "plan":
            return "instance.github.plan"
        if args.github_command == "apply":
            return "instance.github.apply"
        if args.github_command == "resume":
            return "instance.github.resume"
        if args.github_command == "provision-plan":
            return "instance.github.provision-plan"
        if args.github_command == "provision-apply":
            return "instance.github.provision-apply"
        if args.github_command == "provision-resume":
            return "instance.github.provision-resume"
    return "cli"


def _json_requested(argv: Sequence[str]) -> bool:
    return "--json" in argv


def _human_success(command: str, result: Any) -> None:
    if command == "doctor":
        python_info = result["python"]
        gh_state = "available" if result["gh"]["available"] else "unavailable"
        tomllib_state = "available" if python_info["tomllib"] else "unavailable"
        text = (
            f"Python: {python_info['implementation']} {python_info['version']} (tomllib {tomllib_state})\n"
            f"gh executable: {gh_state}\n"
        )
    elif command == "project.validate":
        if result["destinationsValidated"]:
            text = "Project contract and destination routing: valid.\n"
        else:
            text = "Project contract: valid.\n"
    elif command == "project.intent":
        text = "Offline project intent: prepared. Use --json for normalized intent.\n"
    elif command == "adapter.homebrew.render":
        text = "Homebrew formula render: written. Use --json for details.\n"
    elif command == "instance.init":
        text = f"Publisher instance: {result['outcome']}.\n"
    elif command == "instance.register":
        text = f"Consumer registration: {result['outcome']}.\n"
    elif command == "instance.plan":
        text = "Offline instance plan: prepared. Use --json for details.\n"
    elif command == "instance.plan-upgrade":
        text = f"Offline consumer upgrade: {result['outcome']}. Use --json for details.\n"
    elif command == "instance.apply-upgrade":
        subject = "Local consumer upgrade check" if result.get("dryRun") else "Local consumer upgrade"
        text = f"{subject}: {result['outcome']}. Use --json for details.\n"
    elif command == "instance.github.doctor":
        text = "GitHub instance doctor: complete.\n"
    elif command == "instance.github.plan":
        text = f"GitHub instance plan: written ({result['outcome']}, {result['remoteState']}).\n"
    elif command == "instance.github.apply":
        text = f"GitHub instance apply: {result['decision']}.\n"
    elif command == "instance.github.resume":
        text = f"GitHub instance resume: {result['decision']}.\n"
    elif command == "instance.github.provision-plan":
        text = f"GitHub repository-provisioning plan: written ({result['decision']}).\n"
    elif command == "instance.github.provision-apply":
        text = f"GitHub repository provisioning: {result['decision']}.\n"
    elif command == "instance.github.provision-resume":
        text = f"GitHub repository-provisioning resume: {result['decision']}.\n"
    else:
        text = ""
    _write_text(sys.stdout, text, stdout=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline CLI and return the documented process exit code."""

    selected_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    json_output = _json_requested(selected_argv)
    try:
        args = parser.parse_args(selected_argv)
    except _HelpDisplayed:
        return 0
    except _HelpOutputFailure:
        return _report_error(
            "cli", "OUTPUT_ERROR", "Output unavailable.", status=3, json_output=json_output
        )
    except _UsageError:
        return _report_error(
            "cli", "USAGE_ERROR", "Invalid command line.", status=2, json_output=json_output
        )

    json_output = bool(getattr(args, "json", False))
    if args.show_version:
        if args.command is not None:
            return _report_error(
                "cli", "USAGE_ERROR", "Invalid command line.", status=2, json_output=json_output
            )
        try:
            version = distribution_version()
        except Exception:  # noqa: BLE001 - metadata failures are closed as internal errors
            return _report_error(
                "version", "INTERNAL_ERROR", "Internal CLI error.", status=3, json_output=json_output
            )
        try:
            if json_output:
                _write_envelope("version", result={"version": version}, stream=sys.stdout, stdout=True)
            else:
                _write_text(sys.stdout, version + "\n", stdout=True)
        except _OutputFailure:
            return 3
        return 0

    if args.command is None or (args.command == "project" and args.project_command is None) \
            or (args.command == "adapter" and (args.adapter_command is None
                                                or (args.adapter_command == "homebrew"
                                                    and args.homebrew_command is None))) \
            or (args.command == "instance" and (args.instance_command is None
                                                  or (args.instance_command == "github"
                                                      and args.github_command is None))):
        return _report_error(
            "cli", "USAGE_ERROR", "Invalid command line.", status=2, json_output=json_output
        )

    command = _command_name(args)
    try:
        if command == "doctor":
            result = _run_doctor()
        elif command == "project.validate":
            result = _run_validate(args.project, args.destinations)
        elif command == "project.intent":
            result = _run_intent(args.project, args.destinations, args.release_version)
        elif command == "adapter.homebrew.render":
            result = _run_adapter_homebrew_render(args)
        elif command == "instance.init":
            result = _run_instance_init(args)
        elif command == "instance.register":
            result = _run_instance_register(args)
        elif command in {"instance.plan", "instance.plan-upgrade"}:
            result = _run_instance_plan(args)
        elif command == "instance.apply-upgrade":
            result = _run_instance_apply_upgrade(args)
        elif command == "instance.github.doctor":
            result = _run_instance_github_doctor(args)
        elif command == "instance.github.plan":
            result = _run_instance_github_plan(args)
        elif command == "instance.github.apply":
            result = _run_instance_github_apply(args)
        elif command == "instance.github.resume":
            result = _run_instance_github_resume(args)
        elif command == "instance.github.provision-plan":
            result = _run_instance_github_provision_plan(args)
        elif command == "instance.github.provision-apply":
            result = _run_instance_github_provision_apply(args)
        elif command == "instance.github.provision-resume":
            result = _run_instance_github_provision_resume(args)
        else:
            return _report_error(
                command, "USAGE_ERROR", "Invalid command line.", status=2, json_output=json_output
            )
    except _InstanceOperationalFailure as failure:
        if failure.code == "ENGINE_VERSION_MISMATCH":
            message = "Instance engine mismatch requires review."
        elif failure.code in {"GITHUB_RESULT", "GITHUB_OPERATION", "GITHUB_PROVISION_RESULT"}:
            operation_id = _operation_id_for_error(failure.result)
            if operation_id is not None and not json_output:
                message = f"GitHub operation requires review (operation {operation_id})."
            elif failure.outcome.startswith("plan-"):
                message = f"GitHub instance plan requires review ({failure.outcome[5:]})."
            else:
                message = "GitHub operation requires review."
        else:
            message = f"Instance state requires review ({failure.outcome})."
        return _report_error(
            command,
            failure.code,
            message,
            status=1,
            json_output=json_output,
            result=failure.result,
        )
    except Exception as error:  # noqa: BLE001 - closed boundary, no traceback or exception text
        contract_info = _contract_error_info(error)
        if contract_info is not None:
            code, message = contract_info
            return _report_error(command, code, message, status=1, json_output=json_output)
        if isinstance(error, (OSError, UnicodeError)):
            return _report_error(
                command, "ENVIRONMENT_ERROR", "Local environment unavailable.", status=3, json_output=json_output
            )
        return _report_error(command, "INTERNAL_ERROR", "Internal CLI error.", status=3, json_output=json_output)

    try:
        if json_output:
            _write_envelope(command, result=result, stream=sys.stdout, stdout=True)
        else:
            _human_success(command, result)
    except _OutputFailure:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
