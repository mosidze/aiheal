import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from ai_client import call_ai_json_with_metadata
except ImportError:  # pragma: no cover - package import path
    from .ai_client import call_ai_json_with_metadata


USAGE_LOG_PATH = Path("artifacts/ai_usage.jsonl")


def append_usage_record(record: dict, path: Path = USAGE_LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(record) + "\n")


def call_tracked(system_prompt: str, user_prompt: str, step: str) -> dict:
    response = call_ai_json_with_metadata(system_prompt, user_prompt)
    usage = response.get("response_payload", {}).get("usage", {}) or {}

    record = {
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "step": step,
        "model": response.get("model", os.getenv("AI_MODEL", "")),
        "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
        "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
        "total_tokens": int(usage.get("total_tokens", 0) or 0),
        "latency_ms": int(response.get("latency_ms", 0) or 0),
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    append_usage_record(record)
    return response["result"]
