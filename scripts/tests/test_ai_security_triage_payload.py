import json

from ai_client import PayloadTooLargeError, RateLimitError
from ai_security_triage import main


def run_main(args: list[str]) -> None:
    import sys

    old_argv = sys.argv
    sys.argv = ["ai_security_triage.py", *args]
    try:
        main()
    finally:
        sys.argv = old_argv


def build_findings(count: int) -> dict:
    findings = []
    for index in range(count):
        findings.append(
            {
                "scanner": "trivy-image" if index % 2 == 0 else "gosec",
                "rule_id": f"RULE-{index}",
                "severity": "HIGH" if index % 3 == 0 else "MEDIUM",
                "location": f"path/{index}",
                "message": f"message-{index}",
                "path_scope": "docker" if index % 2 == 0 else "go_code",
            }
        )
    return {"findings": findings, "meta": {"count": count}}


def test_ai_security_triage_chunks_after_payload_too_large(tmp_path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    handoff_path = tmp_path / "handoff.json"
    payload = build_findings(25)
    for finding in payload["findings"]:
        finding["path_scope"] = "docker"
        finding["scanner"] = "trivy-image"
    findings_path.write_text(json.dumps(payload))
    returned_rule_ids = []

    def fake_call_tracked(system_prompt, user_prompt, step):
        if step == "security_triage":
            raise PayloadTooLargeError("payload too large")
        chunk_findings_payload = json.loads(user_prompt.split("Findings JSON:\n", 1)[1].split("\n\nClassify each", 1)[0])
        chosen_finding = chunk_findings_payload["findings"][0]
        returned_rule_ids.append(chosen_finding["rule_id"])
        if step == "security_triage_chunk_1":
            return {
                "gate": "warn",
                "summary": "Chunk one summary",
                "triaged_findings": [
                    {
                        "scanner": "trivy-image",
                        "rule_id": chosen_finding["rule_id"],
                        "triage": "auto_fix",
                        "triage_reason": "Docker fix",
                        "explanation": "Update package",
                        "recommended_fix": "Bump package",
                    }
                ],
                "aiheal_handoff": {
                    "eligible": True,
                    "targeted_findings": [{"scanner": "trivy-image", "rule_id": chosen_finding["rule_id"]}],
                },
            }
        return {
            "gate": "allow",
            "summary": "Chunk two summary",
            "triaged_findings": [
                {
                    "scanner": "trivy-image",
                    "rule_id": chosen_finding["rule_id"],
                    "triage": "auto_fix",
                    "triage_reason": "Docker fix",
                    "explanation": "Update base image",
                    "recommended_fix": "Bump base image",
                }
            ],
            "aiheal_handoff": {
                "eligible": True,
                "targeted_findings": [{"scanner": "trivy-image", "rule_id": chosen_finding["rule_id"]}],
            },
        }

    monkeypatch.setattr("ai_security_triage.call_tracked", fake_call_tracked)

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
    assert handoff["gate"] == "warn"
    assert handoff["eligible"] is True
    handoff_rule_ids = {item["rule_id"] for item in handoff["targeted_findings"]}
    assert handoff_rule_ids == {f"RULE-{i}" for i in range(25)}
    assert set(returned_rule_ids).issubset(handoff_rule_ids)

    report = report_path.read_text()
    assert "413 after trim" not in report
    assert "[chunk 1/2] Chunk one summary" in report
    assert "[chunk 2/2] Chunk two summary" in report
    assert "| chunks_used | 2 |" in report


def test_ai_security_triage_writes_unavailable_report_on_rate_limit(tmp_path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    handoff_path = tmp_path / "handoff.json"
    findings_path.write_text(json.dumps(build_findings(12)))

    monkeypatch.setattr(
        "ai_security_triage.call_tracked",
        lambda system_prompt, user_prompt, step: (_ for _ in ()).throw(RateLimitError("rate limited")),
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

    report = report_path.read_text()
    assert "AI triage unavailable (rate limit)" in report
    assert "### Payload budget" in report
    assert "### Top findings" in report
    assert handoff_path.exists() is False


def test_ai_security_triage_single_shot_regression(tmp_path, monkeypatch, sample_security_findings):
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    handoff_path = tmp_path / "handoff.json"
    findings_path.write_text(json.dumps(sample_security_findings))

    monkeypatch.setattr(
        "ai_security_triage.call_tracked",
        lambda system_prompt, user_prompt, step: {
            "gate": "warn",
            "summary": "Single shot summary",
            "triaged_findings": [
                {
                    "scanner": "trivy-image",
                    "rule_id": "CVE-DOCKER-1",
                    "triage": "auto_fix",
                    "triage_reason": "Docker fix",
                    "explanation": "Update base image",
                    "recommended_fix": "Bump base image tag",
                },
                {
                    "scanner": "gosec",
                    "rule_id": "G401",
                    "triage": "needs_human",
                    "triage_reason": "Code review required",
                    "explanation": "Weak crypto",
                    "recommended_fix": "Replace crypto primitive",
                },
                {
                    "scanner": "gitleaks",
                    "rule_id": "git-secret",
                    "triage": "needs_human",
                    "triage_reason": "Rotate the secret",
                    "explanation": "Hardcoded secret",
                    "recommended_fix": "Rotate credential",
                },
            ],
            "aiheal_handoff": {
                "eligible": True,
                "targeted_findings": [{"scanner": "trivy-image", "rule_id": "CVE-DOCKER-1"}],
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
    assert handoff["gate"] == "warn"
    assert handoff["eligible"] is True
    assert [item["rule_id"] for item in handoff["targeted_findings"]] == ["CVE-DOCKER-1"]

    report = report_path.read_text()
    assert "Single shot summary" in report
    assert "| chunks_used | 1 |" in report
    assert "CVE-DOCKER-1" in report
