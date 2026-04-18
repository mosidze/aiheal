import argparse
import json
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--patch", required=True)
    args = parser.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    workflow_touched = False
    files_touched = []

    for change in plan.get("changes", []):
        path = Path(change["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(change["content"])
        files_touched.append(str(path))
        if str(path).startswith(".github/workflows/"):
            workflow_touched = True

    diff = subprocess.run(
        ["git", "diff", "--", "Dockerfile", "docker-compose.yml", ".github/workflows"],
        capture_output=True,
        text=True,
        check=False,
    )
    Path(args.patch).write_text(diff.stdout)
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/remediation_state.json").write_text(
        json.dumps(
            {
                "workflow_touched": workflow_touched,
                "files_touched": files_touched,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
