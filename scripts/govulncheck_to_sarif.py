import argparse
import json
from pathlib import Path


def load_stream(path: Path) -> tuple[dict, list[dict]]:
    osvs: dict = {}
    findings: list[dict] = []
    if not path.exists():
        return osvs, findings
    text = path.read_text().strip()
    if not text:
        return osvs, findings
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)
    while idx < length:
        item, end = decoder.raw_decode(text, idx)
        idx = end
        while idx < length and text[idx].isspace():
            idx += 1
        if not isinstance(item, dict):
            continue
        normalized = {str(key).lower(): value for key, value in item.items()}
        osv = normalized.get("osv")
        finding = normalized.get("finding")
        if isinstance(osv, dict):
            osv_id = osv.get("id") or normalized.get("id")
            if osv_id:
                osvs[str(osv_id)] = osv
        if isinstance(finding, dict):
            findings.append(finding)
    return osvs, findings


def extract_location(finding: dict) -> str:
    trace = finding.get("trace", [])
    if trace:
        frame = trace[-1]
        if isinstance(frame, dict):
            for key in ("package", "function", "module"):
                value = frame.get(key)
                if value:
                    return str(value)
    for key in ("package", "module"):
        value = finding.get(key)
        if value:
            return str(value)
    return ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    osvs, findings = load_stream(Path(args.input))
    rules = []
    results = []
    seen_rules = set()

    for finding in findings:
        vuln_id = str(finding.get("osv") or finding.get("id") or "govulncheck")
        osv = osvs.get(vuln_id, {})
        message = str(
            finding.get("message")
            or osv.get("summary")
            or osv.get("details")
            or f"govulncheck finding for {vuln_id}"
        )
        location = extract_location(finding)

        if vuln_id not in seen_rules:
            rules.append(
                {
                    "id": vuln_id,
                    "name": vuln_id,
                    "shortDescription": {"text": str(osv.get("summary", vuln_id))},
                    "properties": {"security-severity": "8.0"},
                }
            )
            seen_rules.add(vuln_id)

        results.append(
            {
                "ruleId": vuln_id,
                "level": "error",
                "message": {"text": message},
                "properties": {"security-severity": "8.0"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location},
                        }
                    }
                ]
                if location
                else [],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "govulncheck",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    Path(args.output).write_text(json.dumps(sarif, indent=2) + "\n")


if __name__ == "__main__":
    main()
