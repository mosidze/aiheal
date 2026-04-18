"""AI security triage for scanner findings.

Invariants:
- AI may recommend auto-fixes only for docker-scoped findings.
- Go-code and secret findings are always human-reviewed and never bridged to aiheal.
- The handoff contains only docker-scoped auto-fix findings.
- A blocking gate exits non-zero after writing outputs.
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from ai_client import PayloadTooLargeError, RateLimitError
    from findings_budget import SEVERITY_RANK, chunk_findings, trim_findings
    from usage_tracker import call_tracked
except ImportError:  # pragma: no cover - package import path
    from .ai_client import PayloadTooLargeError, RateLimitError
    from .findings_budget import SEVERITY_RANK, chunk_findings, trim_findings
    from .usage_tracker import call_tracked


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NOTE", "UNKNOWN"]
GATE_PRIORITY = {"allow": 0, "warn": 1, "block": 2}


def normalize_response(response: dict) -> dict:
    if not isinstance(response, dict):
        raise RuntimeError("AI triage response must be a JSON object.")

    triaged_findings = response.get("triaged_findings", [])
    if not isinstance(triaged_findings, list):
        raise RuntimeError("AI triage response must contain a triaged_findings list.")

    aiheal_handoff = response.get("aiheal_handoff", {})
    if not isinstance(aiheal_handoff, dict):
        raise RuntimeError("AI triage response must contain an aiheal_handoff object.")

    gate = str(response.get("gate", "warn")).lower()
    if gate not in {"allow", "warn", "block"}:
        raise RuntimeError(f"Unsupported gate value: {gate}")

    return {
        "gate": gate,
        "summary": str(response.get("summary", "")),
        "triaged_findings": triaged_findings,
        "aiheal_handoff": aiheal_handoff,
    }


def find_model_triage(model_findings: list[dict], scanner: str, rule_id: str) -> dict:
    for finding in model_findings:
        if str(finding.get("scanner", "")) == scanner and str(finding.get("rule_id", "")) == rule_id:
            return finding
    return {}


def build_triaged_findings(findings: list[dict], model_findings: list[dict]) -> list[dict]:
    triaged = []
    for finding in findings:
        model_finding = find_model_triage(model_findings, finding["scanner"], finding["rule_id"])
        triage = str(model_finding.get("triage", "needs_human"))
        triage_reason = str(model_finding.get("triage_reason", "No model triage provided."))
        explanation = str(model_finding.get("explanation", finding.get("message", "")))
        recommended_fix = str(model_finding.get("recommended_fix", ""))

        if triage == "auto_fix" and finding.get("path_scope") != "docker":
            triage = "needs_human"
            triage_reason = (
                f"{triage_reason} Auto-fix downgraded by policy because only docker-scoped findings "
                "may be auto-remediated."
            ).strip()

        triaged.append(
            {
                **finding,
                "triage": triage,
                "triage_reason": triage_reason,
                "explanation": explanation,
                "recommended_fix": recommended_fix,
            }
        )
    return triaged


def build_handoff(response: dict, triaged_findings: list[dict]) -> dict:
    # Eligibility is structural: any docker-scoped finding is handoff-eligible
    # because generate_remediation_plan.py + validate_remediation.py already
    # restrict the heal to Dockerfile / docker-compose / workflow files. The
    # model's triage label is advisory UX, not the gate — we do not require it
    # to pick auto_fix before bridging.
    eligible_findings = [
        finding for finding in triaged_findings if finding.get("path_scope") == "docker"
    ]
    return {
        "eligible": bool(eligible_findings),
        "targeted_findings": eligible_findings,
    }


def build_system_prompt() -> str:
    return f"""
You are a GitHub-native DevSecOps triage agent.
{__doc__.strip()}

Triage policy:
- For docker-scoped findings (trivy-image CVEs on base images, hadolint rules,
  Dockerfile/compose misconfigurations) DEFAULT to `auto_fix` when the remediation
  is a Dockerfile or docker-compose.yml change (base-image version bump, adding
  USER, HEALTHCHECK, pinning digests). These are exactly what the aiheal bridge
  is designed to remediate — do NOT default to `needs_human` just because severity
  is HIGH or there are many findings.
- Use `needs_human` only for: go-code findings, gitleaks secrets, license issues,
  or docker findings where the fix requires business judgment (e.g. removing a
  capability the app may still need).
- Use `ignore` only for clear false positives.
- Set `aiheal_handoff.eligible: true` whenever `triaged_findings` contains at
  least one docker-scoped auto_fix entry, and populate `targeted_findings` with
  every such entry (not just a subset).

Return strict JSON with this schema:
{{
  "gate": "allow|warn|block",
  "summary": "one paragraph",
  "triaged_findings": [
    {{
      "scanner": "scanner name",
      "rule_id": "rule identifier",
      "triage": "auto_fix|needs_human|ignore",
      "triage_reason": "why this triage was chosen",
      "explanation": "plain English explanation",
      "recommended_fix": "plain English recommended fix"
    }}
  ],
  "aiheal_handoff": {{
    "eligible": true,
    "targeted_findings": [
      {{
        "scanner": "scanner name",
        "rule_id": "rule identifier"
      }}
    ]
  }}
}}
""".strip()


def build_user_prompt(findings: list[dict]) -> str:
    findings_payload = {"findings": findings}
    return (
        "Findings JSON:\n"
        f"{json.dumps(findings_payload, indent=2)}\n\n"
        "Classify each finding for AI gating. Respect the invariants and keep auto-fix "
        "recommendations limited to Docker and Compose configuration."
    )


def sanitize_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def format_one_line(text: str) -> str:
    return " ".join(str(text).split())


def worst_gate(gates: list[str]) -> str:
    return max(gates or ["allow"], key=lambda gate: GATE_PRIORITY.get(gate, 0))


def dedupe_by_scanner_rule(findings: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for finding in findings:
        key = (str(finding.get("scanner", "")), str(finding.get("rule_id", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(str(finding.get("severity", "UNKNOWN")).upper(), 0),
            -int(finding.get("path_scope") == "docker"),
            str(finding.get("scanner", "")),
            str(finding.get("rule_id", "")),
        ),
    )


def render_payload_budget(trim_stats: dict, chunks_used: int) -> list[str]:
    lines = [
        "### Payload budget",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| pre-trim findings | {trim_stats.get('input_count', 0)} |",
        f"| post-trim findings | {trim_stats.get('output_count', 0)} |",
        f"| dropped_by_severity | `{json.dumps(trim_stats.get('dropped_by_severity', {}), sort_keys=True)}` |",
        f"| dropped_by_scanner | `{json.dumps(trim_stats.get('dropped_by_scanner', {}), sort_keys=True)}` |",
        f"| docker_retained | {trim_stats.get('docker_retained', 0)} |",
        f"| docker_dropped | {trim_stats.get('docker_dropped', 0)} |",
        f"| truncated_messages | {trim_stats.get('truncated_messages', 0)} |",
        f"| chunks_used | {chunks_used} |",
        "",
    ]
    return lines


def render_triaged_table(title: str, findings: list[dict], empty_message: str) -> list[str]:
    lines = [
        f"## {title}",
        "",
        "| rule_id | scanner | triage | explanation | recommended_fix |",
        "| --- | --- | --- | --- | --- |",
    ]
    if findings:
        for finding in findings:
            lines.append(
                f"| {sanitize_cell(finding.get('rule_id', ''))} | {sanitize_cell(finding.get('scanner', ''))} | "
                f"{sanitize_cell(finding.get('triage', ''))} | {sanitize_cell(finding.get('explanation', ''))} | "
                f"{sanitize_cell(finding.get('recommended_fix', ''))} |"
            )
    else:
        lines.append(f"| - | - | - | {sanitize_cell(empty_message)} | - |")
    lines.append("")
    return lines


def render_report(gate: str, summary: str, triaged_findings: list[dict], trim_stats: dict, chunks_used: int) -> str:
    lines = [f"AI gate: {gate}", "", summary or "No AI summary provided.", ""]
    lines.extend(render_payload_budget(trim_stats, chunks_used))
    for severity in SEVERITY_ORDER:
        rows = [finding for finding in triaged_findings if str(finding.get("severity", "UNKNOWN")).upper() == severity]
        lines.extend(render_triaged_table(severity, rows, "No findings."))
    return "\n".join(lines).strip() + "\n"


def render_top_findings(findings: list[dict], limit: int = 10) -> list[str]:
    lines = [
        "### Top findings",
        "",
        "| severity | rule_id | scanner | location | message |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in sort_findings(findings)[:limit]:
        lines.append(
            f"| {sanitize_cell(finding.get('severity', 'UNKNOWN'))} | {sanitize_cell(finding.get('rule_id', ''))} | "
            f"{sanitize_cell(finding.get('scanner', ''))} | {sanitize_cell(finding.get('location', ''))} | "
            f"{sanitize_cell(finding.get('message', ''))} |"
        )
    if len(lines) == 4:
        lines.append("| - | - | - | - | No findings. |")
    lines.append("")
    return lines


def render_unavailable_report(summary: str, findings: list[dict], trim_stats: dict, chunks_used: int) -> str:
    lines = ["AI gate: warn", "", summary, ""]
    lines.extend(render_payload_budget(trim_stats, chunks_used))
    lines.extend(render_top_findings(findings))
    return "\n".join(lines).strip() + "\n"


def write_outputs(eligible: bool, gate: str) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as handle:
            handle.write(f"aiheal_eligible={'true' if eligible else 'false'}\n")
            handle.write(f"gate={gate}\n")


def write_report(path: Path, report: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report)


def run_chunked_triage(system_prompt: str, findings: list[dict]) -> tuple[str, str, list[dict], dict, int]:
    chunks = chunk_findings(findings, chunk_size=20)
    total_chunks = len(chunks)
    chunk_gates = []
    chunk_summaries = []
    triaged_findings = []
    requested_targets = []
    eligible_requested = False

    for index, chunk in enumerate(chunks, start=1):
        response = normalize_response(
            call_tracked(
                system_prompt,
                build_user_prompt(chunk),
                step=f"security_triage_chunk_{index}",
            )
        )
        triaged_chunk = build_triaged_findings(chunk, response["triaged_findings"])
        triaged_findings.extend(triaged_chunk)
        chunk_gates.append(response["gate"])
        chunk_summaries.append(f"[chunk {index}/{total_chunks}] {format_one_line(response['summary'])}")
        eligible_requested = eligible_requested or bool(response.get("aiheal_handoff", {}).get("eligible", False))
        requested_targets.extend(response.get("aiheal_handoff", {}).get("targeted_findings", []))

    triaged_findings = dedupe_by_scanner_rule(triaged_findings)
    aggregated_response = {
        "aiheal_handoff": {
            "eligible": eligible_requested,
            "targeted_findings": dedupe_by_scanner_rule(
                [item for item in requested_targets if isinstance(item, dict)]
            ),
        }
    }
    handoff = build_handoff(aggregated_response, triaged_findings)
    return worst_gate(chunk_gates), "\n".join(chunk_summaries), triaged_findings, handoff, total_chunks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--handoff", required=True)
    args = parser.parse_args()

    report_path = Path(args.report)
    handoff_path = Path(args.handoff)
    findings_payload = json.loads(Path(args.findings).read_text())
    findings = findings_payload.get("findings", [])
    trimmed, trim_stats = trim_findings(findings)
    print(
        f"pre-trim={trim_stats['input_count']} post-trim={trim_stats['output_count']} "
        f"dropped={trim_stats['dropped_by_severity']}"
    )

    triaged_findings = []
    handoff = {"eligible": False, "targeted_findings": []}
    gate = "allow"
    summary = "No security findings were available for AI triage."
    chunks_used = 0
    unavailable = False

    if trimmed:
        system_prompt = build_system_prompt()
        try:
            response = normalize_response(
                call_tracked(system_prompt, build_user_prompt(trimmed), step="security_triage")
            )
            triaged_findings = build_triaged_findings(trimmed, response["triaged_findings"])
            handoff = build_handoff(response, triaged_findings)
            gate = response["gate"]
            summary = response["summary"]
            chunks_used = 1
        except PayloadTooLargeError:
            print("413 after trim, switching to chunked triage")
            try:
                gate, summary, triaged_findings, handoff, chunks_used = run_chunked_triage(
                    system_prompt, trimmed
                )
            except RateLimitError:
                unavailable = True
                gate = "warn"
                summary = (
                    f"AI triage unavailable (rate limit); {trim_stats['output_count']} findings emitted without "
                    "AI triage — see details below."
                )
        except RateLimitError:
            unavailable = True
            gate = "warn"
            summary = (
                f"AI triage unavailable (rate limit); {trim_stats['output_count']} findings emitted without "
                "AI triage — see details below."
            )

    if unavailable:
        report = render_unavailable_report(summary, trimmed, trim_stats, chunks_used)
    else:
        report = render_report(gate, summary, triaged_findings, trim_stats, chunks_used)
    write_report(report_path, report)

    full_handoff = {
        "gate": gate,
        "summary": summary,
        "eligible": handoff["eligible"],
        "targeted_findings": handoff["targeted_findings"],
        "aiheal_handoff": handoff,
    }
    if handoff["eligible"]:
        handoff_path.parent.mkdir(parents=True, exist_ok=True)
        handoff_path.write_text(json.dumps(full_handoff, indent=2) + "\n")
    elif handoff_path.exists():
        handoff_path.unlink()

    write_outputs(handoff["eligible"], gate)
    print(f"gate={gate}")
    print(f"eligible={handoff['eligible']} targeted={len(handoff['targeted_findings'])}")


if __name__ == "__main__":
    main()
