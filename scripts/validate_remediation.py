import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from check_invariants import check_workflow_invariants


ALLOWED_PATHS = {
    "Dockerfile",
    "docker-compose.yml",
    ".github/workflows/aiheal-showcase.yml",
}
HADOLINT_BLOCKED_CODES = {"DL3008", "DL3009", "DL3015", "DL3020", "DL3023", "DL3025"}


def normalize_workflow_mapping(parsed: object) -> dict:
    if not isinstance(parsed, dict):
        return {}
    if "on" not in parsed and True in parsed:
        parsed = dict(parsed)
        parsed["on"] = parsed[True]
    return parsed


def warn_skip(tool_name: str) -> None:
    print(f"warning: {tool_name} not found; skipping {tool_name} validation.", file=sys.stderr)


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def validate_hadolint(content: str) -> None:
    if shutil.which("hadolint") is None:
        warn_skip("hadolint")
        return

    with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as handle:
        handle.write(content)
        temp_path = Path(handle.name)

    try:
        result = run_command(["hadolint", "--no-fail", "--format", "json", str(temp_path)])
        if result.returncode != 0:
            raise RuntimeError(f"hadolint failed: {result.stderr.strip() or result.stdout.strip()}")

        findings = json.loads(result.stdout or "[]")
        blocked = [
            finding
            for finding in findings
            if str(finding.get("level", "")).lower() == "error"
            or str(finding.get("code", "")) in HADOLINT_BLOCKED_CODES
        ]
        if blocked:
            details = ", ".join(
                f"{finding.get('code', 'unknown')} ({finding.get('level', 'unknown')})"
                for finding in blocked
            )
            raise RuntimeError(f"Dockerfile failed hadolint policy checks: {details}")
    finally:
        temp_path.unlink(missing_ok=True)


def validate_actionlint(content: str) -> None:
    if shutil.which("actionlint") is None:
        warn_skip("actionlint")
        return

    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(content)
        temp_path = Path(handle.name)

    try:
        result = run_command(
            ["actionlint", "-no-color", "-format", "{{json .}}", str(temp_path)]
        )
        if result.stdout.strip():
            raise RuntimeError(f"Workflow failed actionlint checks: {result.stdout.strip()}")
        if result.returncode != 0:
            raise RuntimeError(
                f"actionlint failed: {result.stderr.strip() or 'non-zero exit without output'}"
            )
    finally:
        temp_path.unlink(missing_ok=True)


def validate_dockerfile(content: str) -> None:
    if "FROM " not in content:
        raise RuntimeError("Dockerfile must contain at least one FROM instruction.")
    if "ENTRYPOINT" not in content and "CMD" not in content:
        raise RuntimeError("Dockerfile must define ENTRYPOINT or CMD.")
    validate_hadolint(content)


def validate_yaml(path: str, content: str) -> None:
    parsed = normalize_workflow_mapping(yaml.safe_load(content) or {})
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{path} must parse to a YAML mapping.")

    if path.endswith("aiheal-showcase.yml"):
        if "jobs" not in parsed:
            raise RuntimeError("Workflow file must define jobs.")
        if "on" not in parsed:
            raise RuntimeError("Workflow file must define triggers in 'on'.")
        validate_actionlint(content)

    if path == "docker-compose.yml":
        if "services" not in parsed:
            raise RuntimeError("docker-compose.yml must define services.")
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            handle.write(content)
            temp_path = Path(handle.name)
        try:
            result = run_command(["docker", "compose", "-f", str(temp_path), "config", "-q"])
            if result.returncode != 0:
                raise RuntimeError(
                    f"docker-compose.yml failed docker compose config validation: {result.stderr.strip() or result.stdout.strip()}"
                )
        finally:
            temp_path.unlink(missing_ok=True)


def validate_plan(plan: dict, root: Path = Path(".")) -> None:
    changes = plan.get("changes", [])
    if not isinstance(changes, list) or not changes:
        raise RuntimeError("Remediation plan must contain at least one file change.")

    for change in changes:
        path = change.get("path")
        content = change.get("content")

        if path not in ALLOWED_PATHS:
            raise RuntimeError(f"Unsupported remediation path: {path}")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(f"Empty content for remediation path: {path}")

        if path == "Dockerfile":
            validate_dockerfile(content)
            continue

        validate_yaml(path, content)
        if path.endswith("aiheal-showcase.yml"):
            old_content = (root / path).read_text() if (root / path).exists() else ""
            violations = check_workflow_invariants(old_content, content)
            if violations:
                raise RuntimeError("\n".join(violations))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    validate_plan(plan)


if __name__ == "__main__":
    main()
