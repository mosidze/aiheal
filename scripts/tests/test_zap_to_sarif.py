import json

from zap_to_sarif import main


def test_zap_to_sarif_converts_minimal_report(tmp_path):
    input_path = tmp_path / "report.json"
    output_path = tmp_path / "zap.sarif"
    input_path.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "alerts": [
                            {
                                "alertRef": "10001",
                                "name": "Example alert",
                                "riskdesc": "High (High)",
                                "desc": "Example description",
                                "instances": [{"uri": "http://127.0.0.1:8080/"}],
                            }
                        ]
                    }
                ]
            }
        )
    )

    import sys

    old_argv = sys.argv
    sys.argv = [
        "zap_to_sarif.py",
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
    assert payload["runs"][0]["tool"]["driver"]["name"] == "OWASP-ZAP"
    assert payload["runs"][0]["results"][0]["ruleId"] == "10001"
    assert payload["runs"][0]["results"][0]["level"] == "error"
