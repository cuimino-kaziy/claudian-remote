"""Structured command-line entry point for the Claudian Remote lifecycle."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from .checkpoint import CheckpointStore
from .human_gates import HumanGateController
from .inspect import Inspector, InspectionProbe, LocalInspectionProbe
from .model import COMMANDS, LifecycleResult, blocked_not_implemented
from .plan import PlanBuilder, PlanError


DEFAULT_STATE_DIR = (
    Path.home() / "Library" / "Application Support" / "Claudian Remote" / "lifecycle"
)


class LifecycleArgumentError(ValueError):
    pass


class LifecycleArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise LifecycleArgumentError("invalid_lifecycle_arguments")


@dataclass
class LifecycleServices:
    inspection_probe: InspectionProbe
    gate_probes: Mapping[str, Any]

    @classmethod
    def local(cls) -> "LifecycleServices":
        return cls(inspection_probe=LocalInspectionProbe(), gate_probes={})


def build_parser() -> argparse.ArgumentParser:
    parser = LifecycleArgumentParser(prog="claudian-remote-lifecycle")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("inspect")
    plan = subcommands.add_parser("plan")
    plan.add_argument("--snapshot", type=Path)
    plan.add_argument("--mode", choices=("local_tailscale", "remote_vps", "local_lan"), required=True)
    plan.add_argument("--vault-id")
    plan.add_argument("--endpoint-audience")

    status = subcommands.add_parser("status")
    status.add_argument("--operation-id", required=True)
    resume = subcommands.add_parser("resume")
    resume.add_argument("--operation-id", required=True)

    for name in ("install", "update", "uninstall", "purge"):
        command = subcommands.add_parser(name)
        command.add_argument("--plan-id", required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--plan-id")
    rollback = subcommands.add_parser("rollback")
    rollback.add_argument("--operation-id", required=True)
    revoke = subcommands.add_parser("revoke-device")
    revoke.add_argument("--device-id", required=True)
    subcommands.add_parser("diagnose")
    subcommands.add_parser("export-diagnostics")
    return parser


def _load_snapshot(path: Path | None, inspector: Inspector) -> dict[str, Any]:
    if path is None:
        return inspector.snapshot()
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PlanError("invalid_inspection_snapshot")
    return value


def dispatch(
    args: argparse.Namespace,
    *,
    services: LifecycleServices,
) -> LifecycleResult:
    command = str(args.command)
    inspector = Inspector(services.inspection_probe)
    checkpoints = CheckpointStore(args.state_dir)

    if command == "inspect":
        snapshot = inspector.snapshot()
        reasons = snapshot["support"]["reason_codes"]
        return LifecycleResult(
            command=command,
            state="ready" if not reasons else "blocked",
            code="inspection_ready" if not reasons else reasons[0],
            message="Read-only inspection completed; no system state was changed.",
            data={"snapshot": snapshot, "mutation_performed": False},
        )

    if command == "plan":
        snapshot = _load_snapshot(args.snapshot, inspector)
        plan = PlanBuilder().build(
            snapshot,
            mode=args.mode,
            vault_id=args.vault_id,
            endpoint_audience=args.endpoint_audience,
        )
        state = "blocked" if plan["blockers"] else "prepared"
        code = plan["blockers"][0] if plan["blockers"] else "plan_prepared"
        return LifecycleResult(
            command=command,
            state=state,
            code=code,
            message="Deterministic plan created without changing system state.",
            plan_id=plan["plan_id"],
            data={"plan": plan, "mutation_performed": False},
        )

    if command == "status":
        try:
            checkpoint = checkpoints.read(args.operation_id)
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No lifecycle checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                data={"mutation_performed": False},
            )
        return LifecycleResult(
            command=command,
            state=checkpoint["state"],
            code="operation_status",
            message="Lifecycle checkpoint loaded.",
            operation_id=args.operation_id,
            plan_id=checkpoint["plan_id"],
            gate=checkpoint.get("active_gate"),
            data={"phase": checkpoint["phase"], "completed_phases": checkpoint["completed_phases"]},
        )

    if command == "resume":
        try:
            controller = HumanGateController(checkpoints, services.gate_probes)
            outcome = controller.verify_and_resume(args.operation_id)
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No resumable lifecycle checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                data={"mutation_performed": False},
            )
        if not outcome["verified"]:
            return LifecycleResult(
                command=command,
                state="blocked",
                code="human_action_required",
                message="The required external action has not passed its verification probe.",
                operation_id=args.operation_id,
                gate=outcome["gate"],
                data={"mutation_performed": False},
            )
        checkpoint = outcome["checkpoint"]
        return LifecycleResult(
            command=command,
            state="prepared",
            code="resume_prepared",
            message="External gate verification passed; the operation is prepared to continue.",
            operation_id=args.operation_id,
            plan_id=checkpoint["plan_id"],
            data={"phase": checkpoint["phase"], "mutation_performed": False},
        )

    plan_id = getattr(args, "plan_id", None)
    return blocked_not_implemented(command, plan_id=plan_id)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    services: LifecycleServices | None = None,
) -> int:
    output = stdout or sys.stdout
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = dispatch(args, services=services or LifecycleServices.local())
    except Exception:
        command = "inspect"
        if argv:
            command = next((item for item in argv if item in COMMANDS), command)
        result = LifecycleResult(
            command=command,
            state="blocked",
            code="invalid_lifecycle_input",
            message="Lifecycle input was rejected; no system state was changed.",
            data={"mutation_performed": False},
        )
    output.write(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    output.write("\n")
    return 0 if result.state in {"ready", "prepared", "rolled_back"} else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
