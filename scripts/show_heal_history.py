import argparse
import json
from pathlib import Path


def load_records(directory: Path) -> list[dict]:
    if not directory.exists():
        return []

    records = []
    for path in directory.glob("*.json"):
        try:
            records.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    records.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    return records


def format_files(record: dict) -> str:
    files = record.get("files_touched", [])
    if not files:
        return "-"
    return ",".join(str(path) for path in files)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--dir", default="artifacts/heal_history")
    args = parser.parse_args()

    records = load_records(Path(args.dir))
    if not records:
        print("No heal records yet.")
        return

    print("run_id | timestamp | iter | preheal | postheal | tokens | files")
    for record in records[: args.limit]:
        print(
            " | ".join(
                [
                    str(record.get("run_id", "")),
                    str(record.get("timestamp", "")),
                    str(record.get("iteration", 0)),
                    "PASS" if record.get("preheal_passed") else "FAIL",
                    "PASS" if record.get("postheal_passed") else "FAIL",
                    str(record.get("tokens_total", 0)),
                    format_files(record),
                ]
            )
        )


if __name__ == "__main__":
    main()
