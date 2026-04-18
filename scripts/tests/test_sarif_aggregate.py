import json
from pathlib import Path

from sarif_aggregate import main


def test_sarif_aggregate_normalizes_and_classifies(tmp_path):
    input_dir = tmp_path / "sarif"
    input_dir.mkdir()

    (input_dir / "sarif-trivy-image.sarif").write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Trivy", "rules": []}},
                        "results": [
                            {
                                "ruleId": "CVE-1",
                                "level": "error",
                                "message": {"text": "Docker issue"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "Dockerfile"}
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    (input_dir / "sarif-gosec.sarif").write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "gosec", "rules": []}},
                        "results": [
                            {
                                "ruleId": "G401",
                                "level": "warning",
                                "message": {"text": "Go issue"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "service.go"}
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    (input_dir / "sarif-gitleaks.sarif").write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "gitleaks", "rules": []}},
                        "results": [
                            {
                                "ruleId": "secret-1",
                                "level": "note",
                                "message": {"text": "Secret found"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": ".env"}
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )

    output_path = tmp_path / "findings.json"
    import sys

    old_argv = sys.argv
    sys.argv = [
        "sarif_aggregate.py",
        "--input-dir",
        str(input_dir),
        "--output",
        str(output_path),
    ]
    try:
        main()
    finally:
        sys.argv = old_argv

    payload = json.loads(output_path.read_text())
    findings = {(item["scanner"], item["rule_id"]): item for item in payload["findings"]}
    assert findings[("trivy-image", "CVE-1")]["path_scope"] == "docker"
    assert findings[("gosec", "G401")]["path_scope"] == "go_code"
    assert findings[("gitleaks", "secret-1")]["path_scope"] == "secret"
    assert payload["meta"]["count"] == 3


def test_sarif_aggregate_handles_trivy_without_sarif_prefix(tmp_path):
    import sys

    input_dir = tmp_path / "sarif"
    input_dir.mkdir()

    for name in ("trivy-image.sarif", "trivy-fs.sarif"):
        (input_dir / name).write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "tool": {"driver": {"name": "Trivy", "rules": []}},
                            "results": [
                                {
                                    "ruleId": f"CVE-{name}",
                                    "level": "error",
                                    "message": {"text": "finding"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "/usr/lib/pkg"}
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            )
        )

    output_path = tmp_path / "out.json"
    old_argv = sys.argv
    sys.argv = ["sarif_aggregate.py", "--input-dir", str(input_dir), "--output", str(output_path)]
    try:
        main()
    finally:
        sys.argv = old_argv

    payload = json.loads(output_path.read_text())
    scopes = {item["scanner"]: item["path_scope"] for item in payload["findings"]}
    assert scopes["trivy-image"] == "docker"
    assert scopes["trivy-fs"] == "other"
