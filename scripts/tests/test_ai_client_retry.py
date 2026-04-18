import json

import pytest
import requests

from ai_client import PayloadTooLargeError, call_ai_json_with_metadata


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status={self.status_code}", response=self)

    def json(self) -> dict:
        return self._payload


def make_success_response() -> FakeResponse:
    return FakeResponse(
        200,
        {
            "choices": [{"message": {"content": json.dumps({"ok": True})}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "model": "llama-3.3-70b-versatile",
        },
    )


def test_call_ai_json_with_metadata_raises_payload_too_large_after_three_413s(monkeypatch):
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(json)
        return FakeResponse(413)

    monkeypatch.setattr(
        "ai_client.get_ai_config",
        lambda: {
            "api_key": "test-key",
            "base_url": "https://example.test/v1",
            "model": "llama-3.3-70b-versatile",
            "provider": "openai-compatible",
        },
    )
    monkeypatch.setattr("ai_client.requests.post", fake_post)
    monkeypatch.setattr("ai_client.time.sleep", lambda _: None)

    with pytest.raises(PayloadTooLargeError):
        call_ai_json_with_metadata("system", "user")

    assert len(calls) == 3


def test_call_ai_json_with_metadata_retries_429_then_succeeds(monkeypatch):
    responses = [FakeResponse(429), FakeResponse(429), make_success_response()]
    calls = []
    sleeps = []

    def fake_post(url, headers, json, timeout):
        calls.append(json)
        return responses.pop(0)

    monkeypatch.setattr(
        "ai_client.get_ai_config",
        lambda: {
            "api_key": "test-key",
            "base_url": "https://example.test/v1",
            "model": "llama-3.3-70b-versatile",
            "provider": "openai-compatible",
        },
    )
    monkeypatch.setattr("ai_client.requests.post", fake_post)
    monkeypatch.setattr("ai_client.time.sleep", lambda seconds: sleeps.append(seconds))

    response = call_ai_json_with_metadata("system", "user")

    assert response["result"] == {"ok": True}
    assert len(calls) == 3
    assert sleeps == [2, 4]
    assert calls[0]["max_tokens"] == 2048
    assert calls[0]["response_format"] == {"type": "json_object"}


def test_call_ai_json_with_metadata_raises_non_retryable_immediately(monkeypatch):
    calls = []
    sleeps = []

    def fake_post(url, headers, json, timeout):
        calls.append(json)
        return FakeResponse(500)

    monkeypatch.setattr(
        "ai_client.get_ai_config",
        lambda: {
            "api_key": "test-key",
            "base_url": "https://example.test/v1",
            "model": "llama-3.3-70b-versatile",
            "provider": "openai-compatible",
        },
    )
    monkeypatch.setattr("ai_client.requests.post", fake_post)
    monkeypatch.setattr("ai_client.time.sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(requests.HTTPError):
        call_ai_json_with_metadata("system", "user")

    assert len(calls) == 1
    assert sleeps == []
