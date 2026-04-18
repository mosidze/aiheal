import json
import sys

from govulncheck_to_sarif import main


def test_govulncheck_to_sarif_parses_multiline_stream(tmp_path):
    input_path = tmp_path / "govulncheck.json"
    output_path = tmp_path / "govulncheck.sarif"
    input_path.write_text(
        """{
  "osv": {
    "id": "GO-2024-1234",
    "summary": "Example vulnerability",
    "details": "Longer details"
  }
}
{
  "finding": {
    "osv": "GO-2024-1234",
    "trace": [
      {"package": "example.com/pkg/v2"}
    ]
  }
}
{
  "osv": {
    "id": "GO-2024-9999",
    "summary": "Second vuln"
  }
}
{
  "finding": {
    "osv": "GO-2024-9999",
    "message": "Reachable from main",
    "trace": [{"module": "example.com/other"}]
  }
}
"""
    )

    old_argv = sys.argv
    sys.argv = [
        "govulncheck_to_sarif.py",
        "--input",
        str(input_path),
        "--output",
        str(output_path),
    ]
    try:
        main()
    finally:
        sys.argv = old_argv

    payload = json.loads(output_path.read_text())
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "govulncheck"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"GO-2024-1234", "GO-2024-9999"}
    result_ids = [result["ruleId"] for result in run["results"]]
    assert result_ids == ["GO-2024-1234", "GO-2024-9999"]


def test_govulncheck_to_sarif_handles_empty_input(tmp_path):
    input_path = tmp_path / "empty.json"
    output_path = tmp_path / "empty.sarif"
    input_path.write_text("")

    old_argv = sys.argv
    sys.argv = [
        "govulncheck_to_sarif.py",
        "--input",
        str(input_path),
        "--output",
        str(output_path),
    ]
    try:
        main()
    finally:
        sys.argv = old_argv

    payload = json.loads(output_path.read_text())
    assert payload["runs"][0]["tool"]["driver"]["name"] == "govulncheck"
    assert payload["runs"][0]["results"] == []
