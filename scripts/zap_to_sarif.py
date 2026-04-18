import argparse
import json
from pathlib import Path


RISK_LEVELS = {
    "informational": ("note", "3.0"),
    "low": ("note", "3.0"),
    "medium": ("warning", "6.0"),
    "high": ("error", "8.0"),
}


def normalize_alerts(payload: dict) -> list[dict]:
    alerts = []
    for site in payload.get("site", []):
        alerts.extend(site.get("alerts", []))
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    if input_path.exists():
        payload = json.loads(input_path.read_text())
    else:
        payload = {"site": []}
    alerts = normalize_alerts(payload)
    rules = []
    results = []
    seen_rules = set()

    for alert in alerts:
        rule_id = str(alert.get("alertRef") or alert.get("pluginid") or alert.get("name") or "zap-alert")
        risk = str(alert.get("riskdesc") or alert.get("risk") or "informational").split()[0].lower()
        level, security_severity = RISK_LEVELS.get(risk, ("note", "3.0"))
        if rule_id not in seen_rules:
            rules.append(
                {
                    "id": rule_id,
                    "name": str(alert.get("name", rule_id)),
                    "shortDescription": {"text": str(alert.get("name", rule_id))},
                    "properties": {"security-severity": security_severity},
                }
            )
            seen_rules.add(rule_id)

        instances = alert.get("instances", [])
        target_uri = ""
        if instances:
            target_uri = str(instances[0].get("uri", ""))

        result_properties = {"security-severity": security_severity}
        if target_uri:
            result_properties["targetUri"] = target_uri

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": str(alert.get("desc", alert.get("name", rule_id)))},
                "properties": result_properties,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "docker-compose.yml"},
                        }
                    }
                ],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP-ZAP",
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
