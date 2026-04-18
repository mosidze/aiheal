import argparse
import json
import os
from datetime import datetime, timezone
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


def collect_targeted_findings(plan: dict) -> list[str]:
    targeted = []
    for item in plan.get("targeted_findings", []):
        if isinstance(item, dict):
            finding_id = item.get("id")
            if finding_id:
                targeted.append(str(finding_id))
        elif item:
            targeted.append(str(item))
    return targeted


def append_index_record(index_path: Path, record: dict) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("a") as handle:
        handle.write(json.dumps(record) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--pre", required=True)
    parser.add_argument("--post", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--usage", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = load_json(args.findings)
    plan = load_json(args.plan)
    pre = load_json(args.pre)
    post = load_json(args.post)
    state = load_json(args.state)
    usage_records = load_jsonl(args.usage)

    output = {
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "model": (usage_records[-1].get("model") if usage_records else "") or os.getenv("AI_MODEL", ""),
        "iteration": int(os.getenv("AIHEAL_ITERATION", "0") or 0),
        "findings_blocking": [issue.get("id") for issue in findings.get("issues", []) if issue.get("id")],
        "findings_advisory": [issue.get("id") for issue in findings.get("advisory_issues", []) if issue.get("id")],
        "plan_summary": str(plan.get("summary", "")),
        "targeted_findings": collect_targeted_findings(plan),
        "files_touched": [str(path) for path in state.get("files_touched", [])],
        "preheal_passed": bool(pre.get("success", False)),
        "postheal_passed": bool(post.get("success", False)),
        "tokens_total": sum(int(record.get("total_tokens", 0) or 0) for record in usage_records),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n")
    append_index_record(
        output_path.parent / "INDEX.jsonl",
        {
            "run_id": output["run_id"],
            "timestamp": output["timestamp"],
            "postheal_passed": output["postheal_passed"],
            "tokens_total": output["tokens_total"],
        },
    )


if __name__ == "__main__":
    main()
