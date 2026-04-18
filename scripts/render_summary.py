import argparse
import json
import os
from pathlib import Path


def load_json(path: str | None) -> dict:
    if not path:
        return {}
    file_path = Path(path)
    if not file_path.exists():
        return {}
    return json.loads(file_path.read_text())


def load_jsonl(path: str | None) -> list[dict]:
    if not path:
        return []
    file_path = Path(path)
    if not file_path.exists():
        return []
    return [json.loads(line) for line in file_path.read_text().splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--pre", required=True)
    parser.add_argument("--post", required=True)
    parser.add_argument("--state", required=False)
    parser.add_argument("--usage", required=False)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = load_json(args.findings)
    plan = load_json(args.plan)
    pre = load_json(args.pre)
    post = load_json(args.post)
    state = load_json(args.state)
    usage_records = load_jsonl(args.usage)
    run_id = os.getenv("GITHUB_RUN_ID", "local")

    lines = [
        "# GitHub Actions Self-Healing Showcase",
        "",
        f"- Blocking findings detected: {findings.get('blocking_issue_count', 0)}",
        f"- Advisory findings detected: {findings.get('advisory_issue_count', 0)}",
        f"- Pre-heal verification: {'PASS' if pre.get('success') else 'FAIL'}",
        f"- Post-heal verification: {'PASS' if post.get('success') else 'FAIL'}",
        f"- Workflow file changed: {'YES' if state.get('workflow_touched') else 'NO'}",
        "",
        "## AI remediation summary",
        "",
        plan.get("summary", "No AI remediation plan was generated."),
        "",
        "## Touched files",
        "",
    ]

    touched_files = state.get("files_touched", [])
    if touched_files:
        for path in touched_files:
            lines.append(f"- {path}")
    else:
        lines.append("- None")

    lines.extend(["", "## Token usage", ""])
    if usage_records:
        total_tokens = sum(int(record.get("total_tokens", 0) or 0) for record in usage_records)
        lines.append(f"- Total tokens: {total_tokens}")
        for record in usage_records:
            lines.append(
                f"- {record.get('step', 'unknown')}: total={record.get('total_tokens', 0)} "
                f"(prompt={record.get('prompt_tokens', 0)}, completion={record.get('completion_tokens', 0)}), "
                f"model={record.get('model', '')}"
            )
    else:
        lines.append("- No AI usage recorded.")

    lines.extend(
        [
            "",
            "## Memory record",
            "",
            f"- [artifacts/heal_history/{run_id}.json](artifacts/heal_history/{run_id}.json)",
            "",
            "## Blocking Findings",
            "",
        ]
    )

    for issue in findings.get("issues", []):
        lines.append(f"- [{issue['severity']}] {issue['title']} ({issue['file']})")

    if findings.get("advisory_issues"):
        lines.extend(["", "## Advisory Findings", ""])
        for issue in findings.get("advisory_issues", []):
            lines.append(f"- [{issue['severity']}] {issue['title']} ({issue['file']})")

    if state.get("workflow_touched"):
        lines.extend(
            [
                "",
                "## Verification Note",
                "",
                "- Workflow changes were syntax-validated in this run, but GitHub Actions can only execute them on the next run.",
            ]
        )

    Path(args.output).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
