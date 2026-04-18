import argparse
import json
import os
import re
from pathlib import Path

import yaml


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def add_issue(
    issues: list,
    issue_id: str,
    severity: str,
    file_path: str,
    title: str,
    evidence: str,
    recommendation: str,
    source: str = "showcase",
) -> None:
    issues.append(
        {
            "id": issue_id,
            "severity": severity,
            "file": file_path,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
            "source": source,
        }
    )


def sanitize_log(text: str, max_lines: int = 200, max_line_len: int = 500) -> str:
    stripped = ANSI_ESCAPE_RE.sub("", text)
    lines = stripped.splitlines()
    sanitized_lines = []

    for line in lines[:max_lines]:
        if len(line) > max_line_len:
            sanitized_lines.append(f"{line[:max_line_len]} ...[truncated]")
        else:
            sanitized_lines.append(line)

    if len(lines) > max_lines:
        sanitized_lines.append(f"... [{len(lines) - max_lines} more lines truncated]")

    body = "\n".join(sanitized_lines)
    return f"<untrusted_runtime_log>\n{body}\n</untrusted_runtime_log>"


def normalize_workflow_mapping(parsed: object) -> dict:
    if not isinstance(parsed, dict):
        return {}
    if "on" not in parsed and True in parsed:
        parsed = dict(parsed)
        parsed["on"] = parsed[True]
    return parsed


def dockerfile_instruction_tokens(content: str) -> list[tuple[str, str]]:
    instructions = []
    for line in content.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split(None, 1)[0].upper()
        instructions.append((token, stripped))
    return instructions


def inspect_dockerfile(issues: list, advisory_issues: list) -> None:
    dockerfile = Path("Dockerfile")
    if not dockerfile.exists():
        add_issue(
            issues,
            "missing_dockerfile",
            "high",
            "Dockerfile",
            "Dockerfile is missing",
            "The repository does not contain a Dockerfile.",
            "Create a buildable Dockerfile for the showcase pipeline.",
        )
        return

    content = dockerfile.read_text()
    instructions = dockerfile_instruction_tokens(content)
    from_lines = [line for token, line in instructions if token == "FROM"]

    if any("golang:rc-stretch" in line.lower() for line in from_lines):
        add_issue(
            advisory_issues,
            "legacy_base_image",
            "high",
            "Dockerfile",
            "Legacy Docker base image",
            "Dockerfile uses golang:rc-stretch, which is obsolete.",
            "Move to a stable, supported multi-stage build.",
        )

    if len(from_lines) < 2:
        add_issue(
            advisory_issues,
            "single_stage_build",
            "medium",
            "Dockerfile",
            "Single-stage build",
            "Dockerfile builds and runs in one stage.",
            "Use multi-stage Docker builds to reduce runtime size and attack surface.",
        )

    if not any(token == "USER" for token, _ in instructions):
        add_issue(
            advisory_issues,
            "root_runtime",
            "medium",
            "Dockerfile",
            "Container runs as root",
            "Dockerfile does not switch to a non-root user.",
            "Add a dedicated runtime user.",
        )

    if not any(token == "HEALTHCHECK" for token, _ in instructions):
        add_issue(
            advisory_issues,
            "missing_healthcheck",
            "low",
            "Dockerfile",
            "No runtime healthcheck in Dockerfile",
            "Dockerfile does not expose a HEALTHCHECK instruction.",
            "Add a simple HTTP healthcheck or move it to Compose.",
        )


def inspect_compose(issues: list, advisory_issues: list) -> None:
    compose = Path("docker-compose.yml")
    if not compose.exists():
        return

    content = compose.read_text()
    parsed = yaml.safe_load(content) or {}
    services = parsed.get("services", {}) if isinstance(parsed, dict) else {}

    if content.lstrip().startswith("version:"):
        add_issue(
            advisory_issues,
            "obsolete_compose_version",
            "low",
            "docker-compose.yml",
            "Obsolete compose version key",
            "Compose file still uses the top-level version field.",
            "Remove the version field for modern Docker Compose.",
        )

    has_healthcheck = any(
        isinstance(service, dict) and "healthcheck" in service
        for service in services.values()
    ) if isinstance(services, dict) else False

    if not has_healthcheck:
        add_issue(
            advisory_issues,
            "missing_compose_healthcheck",
            "medium",
            "docker-compose.yml",
            "Missing compose healthcheck",
            "docker-compose.yml does not define a healthcheck for the app container.",
            "Add a simple healthcheck tied to the HTTP endpoint.",
        )


def inspect_workflow(issues: list, advisory_issues: list) -> None:
    workflow = Path(".github/workflows/aiheal-showcase.yml")
    if not workflow.exists():
        add_issue(
            issues,
            "missing_workflow",
            "high",
            ".github/workflows/aiheal-showcase.yml",
            "GitHub Actions showcase workflow is missing",
            "The self-healing workflow file is not present.",
            "Create a workflow that diagnoses, heals and verifies Docker/pipeline issues.",
        )
        return

    content = workflow.read_text()
    parsed = normalize_workflow_mapping(yaml.safe_load(content) or {})
    on_section = parsed.get("on", {}) if isinstance(parsed, dict) else {}
    jobs = parsed.get("jobs", {}) if isinstance(parsed, dict) else {}

    if not isinstance(on_section, dict) or "workflow_dispatch" not in on_section:
        add_issue(
            advisory_issues,
            "manual_trigger_missing",
            "medium",
            ".github/workflows/aiheal-showcase.yml",
            "Manual trigger is missing",
            "The workflow cannot be triggered directly from GitHub Actions UI or gh CLI.",
            "Add workflow_dispatch to make the showcase easy to run.",
        )

    has_upload_artifact = False
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if isinstance(step, dict) and "upload-artifact" in str(step.get("uses", "")):
                    has_upload_artifact = True
                    break
            if has_upload_artifact:
                break

    if not has_upload_artifact:
        add_issue(
            advisory_issues,
            "artifact_publishing_missing",
            "medium",
            ".github/workflows/aiheal-showcase.yml",
            "Artifacts are not published",
            "The workflow does not persist diagnosis or remediation outputs.",
            "Upload findings, patches and reports as workflow artifacts.",
        )


def inspect_verification(issues: list, verification_path: Path, logs_path: Path) -> None:
    if verification_path.exists():
        verification = json.loads(verification_path.read_text())
        if not verification.get("success", False):
            add_issue(
                issues,
                "runtime_verification_failed",
                "high",
                str(verification_path),
                "Runtime verification failed",
                sanitize_log(str(verification.get("summary", "Verification failed."))),
                "Repair Docker or pipeline configuration so the service can build and answer HTTP checks.",
            )

    if logs_path.exists():
        logs = logs_path.read_text()
        if "permission denied" in logs.lower():
            add_issue(
                issues,
                "docker_permission_error",
                "medium",
                str(logs_path),
                "Docker permission issue detected",
                sanitize_log(logs),
                "Ensure the workflow runs on a Docker-capable runner.",
            )


def merge_security_handoff(issues: list, handoff_path: Path) -> None:
    if not handoff_path.exists():
        return

    payload = json.loads(handoff_path.read_text())
    targeted_findings = payload.get("targeted_findings")
    if targeted_findings is None:
        targeted_findings = payload.get("aiheal_handoff", {}).get("targeted_findings", [])

    if not isinstance(targeted_findings, list):
        return

    docker_findings = [
        finding
        for finding in targeted_findings
        if isinstance(finding, dict) and finding.get("path_scope") == "docker"
    ]
    if not docker_findings:
        return

    # Collapse many CVEs into one consolidated issue so the remediation-plan
    # prompt stays small. The planner only needs a directive (bump base image)
    # plus representative examples, not 40 individual CVE descriptions.
    by_scanner: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in docker_findings:
        scanner = str(finding.get("scanner", "unknown"))
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1

    sample = docker_findings[:5]
    sample_lines = [
        f"- {str(f.get('scanner', '')):12} {str(f.get('rule_id', '')):20} "
        f"{str(f.get('severity', '')):8} :: "
        f"{str(f.get('recommended_fix') or f.get('explanation') or '')[:120]}"
        for f in sample
    ]
    evidence = "\n".join(
        [
            f"Total docker-scope findings: {len(docker_findings)}",
            f"By scanner: {by_scanner}",
            f"By severity: {by_severity}",
            "Sample (first 5):",
            *sample_lines,
        ]
    )

    summary_gate = str(payload.get("gate") or "").lower() or "warn"
    suggestion = (
        "Container image has multiple HIGH/CRITICAL CVEs reported by the scanners. "
        "Remediate by updating the Dockerfile base image and/or pinning package "
        "versions; do not modify Go source code."
    )
    add_issue(
        issues,
        "security:docker:consolidated",
        "high" if summary_gate == "block" else "medium",
        "Dockerfile",
        "Container image exposes multiple docker-scope vulnerabilities",
        evidence,
        suggestion,
        source="security_scan",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", required=True)
    parser.add_argument("--logs", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--security-handoff", required=False)
    args = parser.parse_args()

    issues = []
    advisory_issues = []
    inspect_dockerfile(issues, advisory_issues)
    inspect_compose(issues, advisory_issues)
    inspect_workflow(issues, advisory_issues)
    inspect_verification(issues, Path(args.verification), Path(args.logs))
    if args.security_handoff:
        merge_security_handoff(issues, Path(args.security_handoff))

    output = {
        "status": "blocking_issues_found" if issues else "clean",
        "issues_found": bool(issues),
        "issue_count": len(issues),
        "blocking_issue_count": len(issues),
        "advisory_issue_count": len(advisory_issues),
        "issues": issues,
        "advisory_issues": advisory_issues,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as handle:
            handle.write(f"issues_found={'true' if issues else 'false'}\n")
            handle.write(f"blocking_issues_found={'true' if issues else 'false'}\n")

    print(f"blocking_issues_found={'true' if issues else 'false'}")


if __name__ == "__main__":
    main()
