import json
from pathlib import Path

import pytest

from ai_security_triage import main


def run_main(args: list[str]) -> None:
    import sys

    old_argv = sys.argv
    sys.argv = ["ai_security_triage.py", *args]
    try:
        main()
    finally:
        sys.argv = old_argv


def test_ai_security_triage_downgrades_non_docker_and_filters_handoff(
    tmp_path, monkeypatch, sample_security_findings
):
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    handoff_path = tmp_path / "handoff.json"
    findings_path.write_text(json.dumps(sample_security_findings))

    monkeypatch.setattr(
        "ai_security_triage.call_tracked",
        lambda system_prompt, user_prompt, step: {
            "gate": "warn",
            "summary": "Triage summary",
            "triaged_findings": [
                {
                    "scanner": "trivy-image",
                    "rule_id": "CVE-DOCKER-1",
                    "triage": "auto_fix",
                    "triage_reason": "Safe Docker change",
                    "explanation": "Update the base image.",
                    "recommended_fix": "Bump the base image tag.",
                },
                {
                    "scanner": "gosec",
                    "rule_id": "G401",
                    "triage": "auto_fix",
                    "triage_reason": "Model suggested code change",
                    "explanation": "Replace weak crypto.",
                    "recommended_fix": "Change the crypto primitive.",
                },
                {
                    "scanner": "gitleaks",
                    "rule_id": "git-secret",
                    "triage": "needs_human",
                    "triage_reason": "Rotate the secret.",
                    "explanation": "Secret rotation required.",
                    "recommended_fix": "Rotate the credential.",
                },
            ],
            "aiheal_handoff": {
                "eligible": True,
                "targeted_findings": [
                    {"scanner": "trivy-image", "rule_id": "CVE-DOCKER-1"},
                    {"scanner": "gosec", "rule_id": "G401"},
                ],
            },
        },
    )

    run_main(
        [
            "--findings",
            str(findings_path),
            "--report",
            str(report_path),
            "--handoff",
            str(handoff_path),
        ]
    )

    handoff = json.loads(handoff_path.read_text())
    assert handoff["eligible"] is True
    assert [item["rule_id"] for item in handoff["targeted_findings"]] == ["CVE-DOCKER-1"]

    report = report_path.read_text()
    assert "## HIGH" in report
    assert "## MEDIUM" in report
    assert "## LOW" in report
    assert "CVE-DOCKER-1" in report
    assert "G401" in report
    assert "git-secret" in report
    assert "needs_human" in report


def test_ai_security_triage_block_exits_zero(tmp_path, monkeypatch, sample_security_findings):
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    handoff_path = tmp_path / "handoff.json"
    findings_path.write_text(json.dumps(sample_security_findings))

    monkeypatch.setattr(
        "ai_security_triage.call_tracked",
        lambda system_prompt, user_prompt, step: {
            "gate": "block",
            "summary": "Block deployment",
            "triaged_findings": [],
            "aiheal_handoff": {"eligible": False, "targeted_findings": []},
        },
    )

    run_main(
        [
            "--findings",
            str(findings_path),
            "--report",
            str(report_path),
            "--handoff",
            str(handoff_path),
        ]
    )

    assert report_path.exists()
    assert "block" in report_path.read_text().lower()
