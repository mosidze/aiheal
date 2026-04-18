from findings_budget import SEVERITY_RANK, TRUNCATION_SUFFIX, chunk_findings, trim_findings


def make_finding(index: int, severity: str, path_scope: str, scanner: str) -> dict:
    return {
        "scanner": scanner,
        "rule_id": f"RULE-{index}",
        "severity": severity,
        "location": f"path/{index}",
        "message": f"message-{index}",
        "path_scope": path_scope,
    }


def test_trim_findings_keeps_top_40_sorted_and_prefers_docker():
    findings = []
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for index in range(100):
        severity = severities[index % len(severities)]
        path_scope = "docker" if index % 5 == 0 else "go_code"
        findings.append(make_finding(index, severity, path_scope, f"scanner-{index % 3}"))

    trimmed, stats = trim_findings(findings, max_findings=40)

    assert len(trimmed) == 40
    assert stats["input_count"] == 100
    assert stats["output_count"] == 40
    assert sum(stats["dropped_by_severity"].values()) == 60

    for current, nxt in zip(trimmed, trimmed[1:]):
        current_rank = (
            -SEVERITY_RANK[current["severity"]],
            -int(current["path_scope"] == "docker"),
            current["scanner"],
        )
        next_rank = (
            -SEVERITY_RANK[nxt["severity"]],
            -int(nxt["path_scope"] == "docker"),
            nxt["scanner"],
        )
        assert current_rank <= next_rank

    critical_docker = [
        finding for finding in findings if finding["severity"] == "CRITICAL" and finding["path_scope"] == "docker"
    ]
    retained_critical_docker = [
        finding for finding in trimmed if finding["severity"] == "CRITICAL" and finding["path_scope"] == "docker"
    ]
    assert len(retained_critical_docker) == len(critical_docker)


def test_trim_findings_caps_at_max_even_when_docker_exceeds_cap():
    findings = [make_finding(index, "HIGH", "docker", "trivy-image") for index in range(200)]

    trimmed, stats = trim_findings(findings, max_findings=40)

    assert len(trimmed) == 40
    assert stats["input_count"] == 200
    assert stats["output_count"] == 40
    assert stats["docker_retained"] == 40
    assert stats["docker_dropped"] == 160


def test_trim_findings_truncates_long_messages():
    findings = [
        {
            "scanner": "trivy-fs",
            "rule_id": "CVE-1",
            "severity": "HIGH",
            "location": "Dockerfile",
            "message": "x" * 500,
            "path_scope": "docker",
        }
    ]

    trimmed, stats = trim_findings(findings, max_message_len=300)

    assert trimmed[0]["message"] == ("x" * 300) + TRUNCATION_SUFFIX
    assert stats["truncated_messages"] == 1


def test_chunk_findings_splits_into_expected_sizes():
    findings = [make_finding(index, "LOW", "docker", "trivy-image") for index in range(50)]

    chunks = chunk_findings(findings, chunk_size=20)

    assert [len(chunk) for chunk in chunks] == [20, 20, 10]


def test_chunk_findings_empty_input():
    assert chunk_findings([], 20) == []
