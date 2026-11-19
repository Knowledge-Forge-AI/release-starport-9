"""Private CLI adapter for the bounded RS9 repository-provisioning API.

This module is the private composition adapter behind the canonical
``rs9 instance github provision-*`` family.  It is not a separate installed
``rs9-provision`` script or public Python API.  It provides the smallest
command boundary needed for that family while keeping the accepted reader,
journal, outer provisioner, and bootstrap modules as their owners.

The command boundary never infers absence, asks ``gh`` for authentication
state, retries a mutation, or deletes a repository.  A plan is read-only; an
apply is the only operation that constructs mutation transports; resume is
read-only and never constructs a writer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable, TextIO

from rs9 import instance_github, instance_github_bootstrap, instance_provision, provision_journal
from rs9.engine_binding import DIST_NAME, verify_engine_wheel
from rs9.errors import ContractError
from rs9.github_cli import _engine_view, _safe_read_json, write_plan_exclusive
from rs9.github_provision import GitHubProvisionTransport
from rs9.github_provision_reader import GitHubProvisionReadTransport
from rs9.github_reader import GITHUB_HOST, GitHubReadTransport
from rs9.github_writer import GitHubWriteTransport


CLI_SCHEMA = "rs9.cli.v1alpha1"
SCHEMA_PLAN = "rs9.instance-github-provision-cli-plan.v1alpha1"
SCHEMA_RESULT = "rs9.instance-github-provision-cli-result.v1alpha1"
SCHEMA_RESUME = "rs9.instance-github-provision-cli-resume.v1alpha1"
_OPERATION = re.compile(r"[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_MAX_CORE_OPERATION_BYTES = 96


class _UsageError(Exception):
    """Closed parser error that never echoes an invalid argument."""


class _HelpDisplayed(Exception):
    """Internal argparse signal after help has been written."""


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _UsageError

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if message:
            self._print_message(message, sys.stdout if status == 0 else sys.stderr)
        if status == 0:
            raise _HelpDisplayed
        raise _UsageError


class _NoMutationWriter:
    """Writer placeholder for a fresh no-op result."""

    def _reject(self) -> None:
        raise ContractError("PROVISION_WRITER", "A no-op must not invoke a writer")

    def create_repository(self, *_args: Any, **_kwargs: Any) -> Any:
        self._reject()

    def put_bootstrap_readme(self, *_args: Any, **_kwargs: Any) -> Any:
        self._reject()

    def create_target_ref(self, *_args: Any, **_kwargs: Any) -> Any:
        self._reject()


def _reject(code: str, message: str = "Provision CLI contract rejected") -> None:
    raise ContractError(code, message)


def _operation(value: Any, *, context: str = "operation") -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        _reject("PROVISION_OPERATION", f"Invalid {context}")
    return value


def _observation_operation_id(operation_id: str) -> str:
    """Derive a bounded, distinct read ID without truncating the plan ID."""

    candidate = operation_id + "-observe"
    if len(candidate.encode("ascii")) <= _MAX_CORE_OPERATION_BYTES:
        return candidate
    digest = hashlib.sha256(operation_id.encode("ascii")).hexdigest()[:16]
    prefix_bytes = _MAX_CORE_OPERATION_BYTES - len(digest) - 1
    return operation_id[:prefix_bytes] + "-" + digest


def _binding_for(
    engine_wheel: str | Path,
    supplied: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if supplied is not None:
        return _engine_view(supplied)
    if not isinstance(engine_wheel, (str, Path)):
        _reject("ENGINE_ARTIFACT")
    return _engine_view(verify_engine_wheel(engine_wheel))


def _source_from_local(publisher_root: str, binding: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the local instance snapshot to the exact engine artifact view."""

    try:
        local = instance_github._local_snapshot(publisher_root)
    except ContractError:
        raise
    except Exception:
        _reject("PROVISION_LOCAL")
    identity = local.get("identity") if isinstance(local, Mapping) else None
    if not isinstance(identity, Mapping):
        _reject("PROVISION_LOCAL")
    expected_engine = {"distribution": DIST_NAME, "version": binding["version"]}
    if identity.get("engine") != expected_engine:
        _reject("ENGINE_VERSION_MISMATCH")
    try:
        source = {
            "instance_id": identity["instance_id"],
            "repository": local["repository"],
            "branch": local["branch"],
            "engine": {
                "distribution": DIST_NAME,
                "version": binding["version"],
                "artifact_sha256": binding["artifact_sha256"],
            },
            "template": dict(identity["template"]),
            "adapter": dict(identity["adapter"]),
            "manifest_sha256": identity["manifest_sha256"],
            "desired_state_sha256": identity["desired_state_sha256"],
        }
    except (KeyError, TypeError, ValueError):
        _reject("PROVISION_LOCAL")
    # ``observe`` and ``plan`` own source validation.  Calling the bounded
    # observation path is preferable to duplicating its closed schema here.
    return source


def _validate_resume_engine_binding(
    publisher_root: str,
    operation_id: str,
    binding: Mapping[str, Any],
) -> None:
    """Check the journal's persisted source-engine digest before readback."""

    journal = provision_journal.load(publisher_root, operation_id)
    expected = provision_journal.record_sha256({
        "distribution": DIST_NAME,
        "version": binding["version"],
        "artifact_sha256": binding["artifact_sha256"],
    })
    if journal.record["engine_sha256"] != expected:
        _reject("ENGINE_ARTIFACT_MISMATCH")


def _reader_record() -> dict[str, str]:
    return {
        "host": GITHUB_HOST,
        "transport": instance_provision.SCHEMA_PROTOCOL,
    }


def _make_reader(
    reader: Any | None,
) -> tuple[Any, GitHubReadTransport | None]:
    if reader is not None:
        return reader, None
    coordinator_reader = GitHubReadTransport()
    return GitHubProvisionReadTransport(coordinator_reader), coordinator_reader


def _make_handoff(
    publisher_root: str,
    *,
    reader: Any,
    coordinator_reader: GitHubReadTransport | None,
    binding: Mapping[str, Any],
    handoff: Callable[..., Mapping[str, Any]] | None,
) -> Callable[..., Mapping[str, Any]]:
    if handoff is not None:
        if not callable(handoff):
            _reject("PROVISION_HANDOFF")
        return handoff
    if coordinator_reader is None or type(reader) is not GitHubProvisionReadTransport:
        _reject("PROVISION_HANDOFF")
    bootstrap_reader = instance_github_bootstrap.GitHubAnchoredBootstrapReader(
        coordinator_reader, reader,
    )
    installed_engine = {
        "distribution": DIST_NAME,
        "version": binding["version"],
        "artifact_sha256": binding["artifact_sha256"],
    }
    return instance_github_bootstrap.make_anchored_bootstrap_handoff(
        publisher_root,
        reader=bootstrap_reader,
        writer_factory=lambda node: GitHubWriteTransport(
            repository_node_id=node,
            allow_mutation=True,
        ),
        installed_engine=installed_engine,
    )


def _wrap_plan(plan: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    checked = instance_provision.validate_plan(plan)
    return {
        "schema": SCHEMA_PLAN,
        "engine": _engine_view(binding),
        "reader": _reader_record(),
        "plan_sha256": provision_journal.record_sha256(checked),
        "plan": checked,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def validate_plan_wrapper(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed wrapper persisted by the plan command."""

    keys = {
        "schema", "engine", "reader", "plan_sha256", "plan",
        "publicationAuthority", "qualified", "publicationEnabled",
    }
    if not isinstance(value, Mapping) or set(value) != keys or value["schema"] != SCHEMA_PLAN:
        _reject("PROVISION_PLAN")
    engine = _engine_view(value["engine"])
    if value["reader"] != _reader_record():
        _reject("PROVISION_PLAN")
    if value["publicationAuthority"] is not False or value["qualified"] is not False \
            or value["publicationEnabled"] is not False:
        _reject("PROVISION_AUTHORITY")
    plan = instance_provision.validate_plan(value["plan"])
    expected = provision_journal.record_sha256(plan)
    if value["plan_sha256"] != expected:
        _reject("PROVISION_PLAN")
    return {
        "schema": SCHEMA_PLAN,
        "engine": engine,
        "reader": dict(value["reader"]),
        "plan_sha256": expected,
        "plan": plan,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def _wrap_result(
    result: Mapping[str, Any],
    binding: Mapping[str, Any],
    *,
    schema: str = SCHEMA_RESULT,
) -> dict[str, Any]:
    checked = instance_provision.validate_result(result)
    return {
        "schema": schema,
        "engine": _engine_view(binding),
        "result": checked,
        "decision": checked["decision"],
        "status": checked["status"],
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def plan_instance_github_provision_cli(
    publisher_root: str,
    *,
    engine_wheel: str | Path,
    output: str | Path,
    operation_id: str,
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Read remote state, bind one plan, and write it without replacement."""

    operation_id = _operation(operation_id)
    binding = _binding_for(engine_wheel, _binding)
    source = _source_from_local(publisher_root, binding)
    reader, _coordinator_reader = _make_reader(_reader)
    observation = instance_provision.observe(
        source,
        reader,
        operation_id=_observation_operation_id(operation_id),
    )
    plan = instance_provision.plan(source, observation, operation_id=operation_id)
    checked = instance_provision.validate_plan(plan)
    if checked["decision"] not in {"create", "adopt-exact", "noop"}:
        _reject("PROVISION_PLAN_NOT_APPLICABLE")
    wrapper = _wrap_plan(checked, binding)
    write_plan_exclusive(output, wrapper)
    return {
        "schema": SCHEMA_PLAN,
        "decision": checked["decision"],
        "reason": checked["reason"],
        "plan_sha256": wrapper["plan_sha256"],
        "observation_sha256": checked["observation_sha256"],
        "artifact_sha256": binding["artifact_sha256"],
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def apply_instance_github_provision_cli(
    publisher_root: str,
    *,
    plan_path: str | Path,
    engine_wheel: str | Path,
    operation_id: str,
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
    _writer: Any | None = None,
    _handoff: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rebind local/engine custody, then invoke the accepted outer apply."""

    wrapper = validate_plan_wrapper(_safe_read_json(plan_path))
    operation_id = _operation(operation_id)
    binding = _binding_for(engine_wheel, _binding)
    if wrapper["engine"] != _engine_view(binding):
        _reject("ENGINE_ARTIFACT_MISMATCH")
    plan = wrapper["plan"]
    if plan["operation_id"] != operation_id:
        _reject("PROVISION_BINDING")
    source = _source_from_local(publisher_root, binding)
    if source != plan["source"]:
        _reject("PROVISION_BINDING")
    if plan["decision"] not in {"create", "adopt-exact", "noop"}:
        _reject("PROVISION_PLAN_NOT_APPLICABLE")
    reader, coordinator_reader = _make_reader(_reader)
    if plan["decision"] == "noop":
        writer = _NoMutationWriter()
        handoff = None
    else:
        writer = _writer if _writer is not None else GitHubProvisionTransport(allow_mutation=True)
        handoff = _make_handoff(
            publisher_root,
            reader=reader,
            coordinator_reader=coordinator_reader,
            binding=binding,
            handoff=_handoff,
        )
    try:
        result = instance_provision.apply(
            publisher_root,
            plan,
            reader=reader,
            writer=writer,
            handoff=handoff,
        )
    except ContractError:
        raise
    except Exception:
        _reject("PROVISION_APPLY")
    return _wrap_result(result, binding)


def resume_instance_github_provision_cli(
    publisher_root: str,
    *,
    operation_id: str,
    engine_wheel: str | Path,
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Perform accepted read-only recovery; never construct a writer."""

    operation_id = _operation(operation_id)
    binding = _binding_for(engine_wheel, _binding)
    _source_from_local(publisher_root, binding)
    _validate_resume_engine_binding(publisher_root, operation_id, binding)
    reader, _coordinator_reader = _make_reader(_reader)
    result = instance_provision.resume(
        publisher_root,
        operation_id=operation_id,
        reader=reader,
    )
    return _wrap_result(result, binding, schema=SCHEMA_RESUME)


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="rs9-provision",
        description="Private bounded RS9 GitHub repository-provisioning adapter",
    )
    parser.add_argument("--json", action="store_true", help="write a stable JSON envelope")
    commands = parser.add_subparsers(dest="command")
    instance = commands.add_parser("instance")
    instance_commands = instance.add_subparsers(dest="instance_command", parser_class=_Parser)
    github = instance_commands.add_parser("github")
    provision = github.add_subparsers(dest="github_command")
    plan = provision.add_parser("provision-plan", help="read remote state and write one immutable plan")
    plan.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    plan.add_argument("--engine-wheel", required=True, metavar="PATH")
    plan.add_argument("--output", required=True, metavar="PLAN")
    plan.add_argument("--operation-id", required=True, metavar="OPERATION_ID")
    plan.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    apply = provision.add_parser("provision-apply", help="apply one exact immutable plan")
    apply.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    apply.add_argument("--plan", dest="plan_path", required=True, metavar="PLAN")
    apply.add_argument("--engine-wheel", required=True, metavar="PATH")
    apply.add_argument("--operation-id", required=True, metavar="OPERATION_ID")
    apply.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    resume = provision.add_parser("provision-resume", help="perform read-only recovery for one operation")
    resume.add_argument("publisher_root", metavar="PUBLISHER_ROOT")
    resume.add_argument("--operation-id", required=True, metavar="OPERATION_ID")
    resume.add_argument("--engine-wheel", required=True, metavar="PATH")
    resume.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    return parser


def _command_name(args: argparse.Namespace) -> str:
    if (getattr(args, "command", None) == "instance"
            and getattr(args, "instance_command", None) == "github"):
        value = getattr(args, "github_command", None)
        if value in {"provision-plan", "provision-apply", "provision-resume"}:
            return "instance.github." + value
    return "cli"


def _envelope(command: str, *, result: Any = None, error: Mapping[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"schema": CLI_SCHEMA, "command": command, "ok": error is None}
    if result is not None:
        value["result"] = result
    if error is not None:
        value["error"] = dict(error)
    return value


def _write(stream: TextIO, value: str) -> None:
    try:
        stream.write(value)
        stream.flush()
    except (BrokenPipeError, OSError, UnicodeError, ValueError):
        raise SystemExit(3) from None


def _message(code: str) -> str:
    return {
        "PROVISION_PLAN_NOT_APPLICABLE": "Provision plan requires review before it can be used.",
        "PROVISION_RESULT_HELD": "Provision operation remains held for review.",
        "ENGINE_ARTIFACT_MISMATCH": "Engine artifact does not match the saved plan.",
        "ENGINE_VERSION_MISMATCH": "Local instance engine does not match the selected engine.",
        "PROVISION_BINDING": "Provision input no longer matches the saved binding.",
        "PROVISION_APPLY": "Provision apply requires review.",
        "PROVISION_HANDOFF": "Provision continuation is unavailable.",
    }.get(code, "Provision CLI contract rejected.")


def _safe_error_code(error: BaseException) -> str:
    value = getattr(error, "code", "PROVISION_REJECTED")
    return value if isinstance(value, str) and _ERROR_CODE.fullmatch(value) is not None else "PROVISION_REJECTED"


def _emit_error(command: str, code: str, *, json_output: bool, result: Any = None) -> int:
    message = _message(code)
    if json_output:
        _write(sys.stderr, json.dumps(
            _envelope(command, result=result, error={"code": code, "message": message}),
            ensure_ascii=False, sort_keys=True, indent=2,
        ) + "\n")
    else:
        _write(sys.stderr, f"Error [{code}]: {message}\n")
    return 1


def _emit_success(command: str, result: Mapping[str, Any], *, json_output: bool) -> int:
    if json_output:
        _write(sys.stdout, json.dumps(
            _envelope(command, result=result), ensure_ascii=False, sort_keys=True, indent=2,
        ) + "\n")
        return 0
    if command.endswith("provision-plan"):
        text = f"Provision plan: written ({result['decision']}).\n"
    elif command.endswith("provision-apply"):
        text = f"Provision apply: {result['decision']}.\n"
    else:
        text = f"Provision resume: {result['decision']}.\n"
    _write(sys.stdout, text)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    selected = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in selected
    parser = _build_parser()
    try:
        args = parser.parse_args(selected)
    except _HelpDisplayed:
        return 0
    except _UsageError:
        return _emit_error("cli", "USAGE_ERROR", json_output=json_output)
    json_output = bool(getattr(args, "json", False)) or json_output
    command = _command_name(args)
    if command == "cli":
        return _emit_error(command, "USAGE_ERROR", json_output=json_output)
    try:
        if command.endswith("provision-plan"):
            result = plan_instance_github_provision_cli(
                args.publisher_root,
                engine_wheel=args.engine_wheel,
                output=args.output,
                operation_id=args.operation_id,
            )
            return _emit_success(command, result, json_output=json_output)
        if command.endswith("provision-apply"):
            result = apply_instance_github_provision_cli(
                args.publisher_root,
                plan_path=args.plan_path,
                engine_wheel=args.engine_wheel,
                operation_id=args.operation_id,
            )
            if result["status"] != "completed":
                return _emit_error(command, "PROVISION_RESULT_HELD", json_output=json_output, result=result)
            return _emit_success(command, result, json_output=json_output)
        result = resume_instance_github_provision_cli(
            args.publisher_root,
            operation_id=args.operation_id,
            engine_wheel=args.engine_wheel,
        )
        if result["status"] not in {"closed", "completed"}:
            return _emit_error(command, "PROVISION_RESULT_HELD", json_output=json_output, result=result)
        return _emit_success(command, result, json_output=json_output)
    except ContractError as error:
        return _emit_error(command, _safe_error_code(error), json_output=json_output)
    except (OSError, UnicodeError):
        return _emit_error(command, "ENVIRONMENT_ERROR", json_output=json_output)
    except Exception:
        return _emit_error(command, "INTERNAL_ERROR", json_output=json_output)


__all__ = [
    "CLI_SCHEMA", "SCHEMA_PLAN", "SCHEMA_RESULT", "SCHEMA_RESUME",
    "apply_instance_github_provision_cli", "main", "plan_instance_github_provision_cli",
    "resume_instance_github_provision_cli", "validate_plan_wrapper",
]


if __name__ == "__main__":
    raise SystemExit(main())
