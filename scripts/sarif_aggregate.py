import argparse
import json
from pathlib import Path


KNOWN_SCANNERS = {"trivy-image", "trivy-fs", "gosec", "govulncheck", "gitleaks", "zap"}


def normalize_scanner(path: Path, driver_name: str) -> str:
    stem = path.stem
    if stem.startswith("sarif-"):
        stem = stem.removeprefix("sarif-")
    if stem in KNOWN_SCANNERS:
        return stem

    normalized = driver_name.strip().lower().replace(" ", "-")
    if normalized == "owasp-zap":
        return "zap"
    return normalized or "unknown"


def map_severity(result: dict, rule: dict | None) -> str:
    properties = result.get("properties", {})
    rule_properties = (rule or {}).get("properties", {})
    security_severity = properties.get("security-severity", rule_properties.get("security-severity"))
    if security_severity is not None:
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = 0.0
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "INFO"

    level = str(result.get("level", "")).lower()
    if level == "error":
        return "HIGH"
    if level == "warning":
        return "MEDIUM"
    if level == "note":
        return "LOW"
    return "INFO"


def extract_location(result: dict) -> str:
    locations = result.get("locations", [])
    if locations:
        physical = locations[0].get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        uri = artifact.get("uri")
        if uri:
            return str(uri)

    logical_locations = result.get("logicalLocations", [])
    if logical_locations:
        name = logical_locations[0].get("fullyQualifiedName")
        if name:
            return str(name)

    return ""


def classify_path_scope(scanner: str, location: str) -> str:
    normalized_location = location.lower()
    if scanner == "trivy-image" or normalized_location.endswith("dockerfile"):
        return "docker"
    if scanner in {"gosec", "govulncheck"}:
        return "go_code"
    if scanner == "trivy-fs" and (
        normalized_location.endswith(".go") or normalized_location in {"go.mod", "go.sum"}
    ):
        return "go_code"
    if scanner == "gitleaks":
        return "secret"
    return "other"


def truncate_message(message: str, limit: int = 1000) -> str:
    if len(message) <= limit:
        return message
    return f"{message[:limit]}...[truncated]"


def aggregate_file(path: Path) -> list[dict]:
    payload = json.loads(path.read_text())
    findings = []

    for run in payload.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        scanner = normalize_scanner(path, str(driver.get("name", "")))
        rules_by_id = {
            str(rule.get("id")): rule
            for rule in driver.get("rules", [])
            if isinstance(rule, dict) and rule.get("id")
        }

        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", "unknown"))
            rule = rules_by_id.get(rule_id)
            location = extract_location(result)
            message = (
                result.get("message", {}).get("text")
                or result.get("message", {}).get("markdown")
                or ""
            )
            findings.append(
                {
                    "scanner": scanner,
                    "rule_id": rule_id,
                    "severity": map_severity(result, rule),
                    "location": location,
                    "message": truncate_message(str(message)),
                    "path_scope": classify_path_scope(scanner, location),
                }
            )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    aggregated = []
    scanners = set()

    if input_dir.exists():
        for sarif_path in sorted(input_dir.glob("*.sarif")):
            file_findings = aggregate_file(sarif_path)
            aggregated.extend(file_findings)
            scanners.update(finding["scanner"] for finding in file_findings)

    output = {
        "findings": aggregated,
        "meta": {
            "scanners": sorted(scanners),
            "count": len(aggregated),
        },
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
