import re

import yaml


FORBIDDEN_RUN_PATTERNS = (
    re.compile(r"(curl|wget)[^|\n]*\|\s*(sh|bash)"),
    re.compile(r"eval\s*\$\("),
    re.compile(r">\s*/dev/tcp/"),
)

SECRET_REF_PATTERN = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
PINNED_ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
PERMISSION_RANK = {"none": 0, "read": 1, "write": 2}


def _normalize_workflow(parsed: object) -> dict:
    if not isinstance(parsed, dict):
        return {}
    if "on" not in parsed and True in parsed:
        parsed = dict(parsed)
        parsed["on"] = parsed[True]
    return parsed


def _load_workflow(yaml_text: str) -> dict:
    parsed = yaml.safe_load(yaml_text) or {}
    return _normalize_workflow(parsed)


def _permission_level(value: object) -> int:
    if isinstance(value, str):
        return PERMISSION_RANK.get(value.strip().lower(), 0)
    return 0


def _normalize_permissions(value: object) -> tuple[str | None, dict[str, int]]:
    if value is None:
        return None, {}
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"write-all", "read-all"}:
            return normalized, {}
        return None, {}
    if not isinstance(value, dict):
        return None, {}
    return None, {str(key): _permission_level(item) for key, item in value.items()}


def _compare_permissions(scope: str, old_value: object, new_value: object) -> list[str]:
    violations = []
    old_special, old_permissions = _normalize_permissions(old_value)
    new_special, new_permissions = _normalize_permissions(new_value)

    if new_special == "write-all":
        violations.append(f"{scope}: permissions cannot be set to write-all.")
        return violations

    if new_special == "read-all" and old_special not in {"read-all", "write-all"}:
        violations.append(f"{scope}: permissions widened to read-all.")
        return violations

    for key in sorted(set(old_permissions) | set(new_permissions)):
        old_level = old_permissions.get(key, 0)
        new_level = new_permissions.get(key, 0)
        if new_level > old_level:
            old_name = next(name for name, rank in PERMISSION_RANK.items() if rank == old_level)
            new_name = next(name for name, rank in PERMISSION_RANK.items() if rank == new_level)
            violations.append(
                f"{scope}: permissions for {key} widened from {old_name} to {new_name}."
            )

    return violations


def _collect_uses(node: object) -> list[str]:
    uses = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                uses.append(value.strip())
            else:
                uses.extend(_collect_uses(value))
    elif isinstance(node, list):
        for item in node:
            uses.extend(_collect_uses(item))
    return uses


def _collect_runs(node: object) -> list[str]:
    runs = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "run" and isinstance(value, str):
                runs.append(value)
            else:
                runs.extend(_collect_runs(value))
    elif isinstance(node, list):
        for item in node:
            runs.extend(_collect_runs(item))
    return runs


def check_workflow_invariants(old_yaml: str, new_yaml: str) -> list[str]:
    old_workflow = _load_workflow(old_yaml)
    new_workflow = _load_workflow(new_yaml)
    violations = []

    violations.extend(
        _compare_permissions(
            "top-level workflow",
            old_workflow.get("permissions"),
            new_workflow.get("permissions"),
        )
    )

    old_jobs = old_workflow.get("jobs", {})
    new_jobs = new_workflow.get("jobs", {})
    if isinstance(old_jobs, dict) and isinstance(new_jobs, dict):
        for job_name in sorted(set(old_jobs) | set(new_jobs)):
            old_job = old_jobs.get(job_name, {}) if isinstance(old_jobs.get(job_name, {}), dict) else {}
            new_job = new_jobs.get(job_name, {}) if isinstance(new_jobs.get(job_name, {}), dict) else {}
            violations.extend(
                _compare_permissions(
                    f"job {job_name}",
                    old_job.get("permissions"),
                    new_job.get("permissions"),
                )
            )

    old_secrets = set(SECRET_REF_PATTERN.findall(old_yaml))
    new_secrets = set(SECRET_REF_PATTERN.findall(new_yaml))
    for secret_name in sorted(new_secrets - old_secrets):
        violations.append(f"workflow secrets cannot gain new reference secrets.{secret_name}.")

    for action in _collect_uses(new_workflow):
        if action.startswith("actions/"):
            continue
        if not PINNED_ACTION_PATTERN.match(action):
            violations.append(f"third-party action must be pinned by 40-char SHA: {action}")

    old_runs = set(_collect_runs(old_workflow))
    new_runs = set(_collect_runs(new_workflow))
    for run_block in sorted(new_runs - old_runs):
        for pattern in FORBIDDEN_RUN_PATTERNS:
            if pattern.search(run_block):
                violations.append(
                    f"new run block contains forbidden command pattern: {pattern.pattern}"
                )
                break

    return violations
