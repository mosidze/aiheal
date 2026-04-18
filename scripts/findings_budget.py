"""Helpers for trimming and chunking AI triage findings payloads."""

from copy import deepcopy


SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "NOTE": 1,
    "UNKNOWN": 0,
}
TRUNCATION_SUFFIX = "...[truncated]"


def _severity_value(finding: dict) -> int:
    return SEVERITY_RANK.get(str(finding.get("severity", "UNKNOWN")).upper(), 0)


def _sort_key(item: tuple[int, dict]) -> tuple[int, int, str, int]:
    index, finding = item
    return (
        -_severity_value(finding),
        -int(finding.get("path_scope") == "docker"),
        str(finding.get("scanner", "")),
        index,
    )


def _truncate_message(finding: dict, max_message_len: int) -> tuple[dict, bool]:
    trimmed = deepcopy(finding)
    message = str(trimmed.get("message", ""))
    if max_message_len < 0:
        max_message_len = 0
    if len(message) <= max_message_len:
        return trimmed, False

    trimmed["message"] = f"{message[:max_message_len]}{TRUNCATION_SUFFIX}"
    return trimmed, True


def trim_findings(
    findings: list[dict],
    max_findings: int = 40,
    max_message_len: int = 300,
) -> tuple[list[dict], dict]:
    """
    Return a trimmed, deterministic view of findings for AI triage plus trim stats.
    """

    max_findings = max(0, max_findings)
    sorted_indexed = sorted(enumerate(findings), key=_sort_key)

    selected_indexed = sorted_indexed[:max_findings]
    selected_indexes = {index for index, _ in selected_indexed}
    selected = [finding for _, finding in selected_indexed]
    dropped = [finding for index, finding in sorted_indexed if index not in selected_indexes]

    dropped_by_severity = {severity: 0 for severity in SEVERITY_RANK}
    dropped_by_scanner: dict[str, int] = {}
    for finding in dropped:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        dropped_by_severity.setdefault(severity, 0)
        dropped_by_severity[severity] += 1
        scanner = str(finding.get("scanner", ""))
        dropped_by_scanner[scanner] = dropped_by_scanner.get(scanner, 0) + 1

    trimmed_list = []
    truncated_messages = 0
    for finding in selected:
        trimmed_finding, was_truncated = _truncate_message(finding, max_message_len)
        trimmed_list.append(trimmed_finding)
        truncated_messages += int(was_truncated)

    trim_stats = {
        "input_count": len(findings),
        "output_count": len(trimmed_list),
        "dropped_by_severity": dropped_by_severity,
        "dropped_by_scanner": dict(sorted(dropped_by_scanner.items())),
        "docker_retained": sum(1 for finding in trimmed_list if finding.get("path_scope") == "docker"),
        "docker_dropped": sum(1 for finding in dropped if finding.get("path_scope") == "docker"),
        "truncated_messages": truncated_messages,
    }
    return trimmed_list, trim_stats


def chunk_findings(findings: list[dict], chunk_size: int = 20) -> list[list[dict]]:
    """Split findings into ordered chunks of up to chunk_size items."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if not findings:
        return []
    return [findings[index : index + chunk_size] for index in range(0, len(findings), chunk_size)]
