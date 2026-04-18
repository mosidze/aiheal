import json
from pathlib import Path

from usage_tracker import call_tracked


def test_call_tracked_appends_usage_record(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_RUN_ID", "test")
    monkeypatch.setattr(
        "usage_tracker.call_ai_json_with_metadata",
        lambda system_prompt, user_prompt: {
            "result": {"ok": True},
            "response_payload": {
                "usage": {
                    "prompt_tokens": 3,
                    "completion_tokens": 5,
                    "total_tokens": 8,
                }
            },
            "model": "gpt-test",
            "latency_ms": 12,
        },
    )

    result = call_tracked("system", "user", step="generate_plan")

    assert result == {"ok": True}
    usage_log = Path("artifacts/ai_usage.jsonl")
    assert usage_log.exists()
    record = json.loads(usage_log.read_text().strip())
    assert record["run_id"] == "test"
    assert record["step"] == "generate_plan"
    assert record["total_tokens"] == 8
