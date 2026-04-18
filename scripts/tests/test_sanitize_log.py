from collect_findings import sanitize_log


def test_ansi_codes_stripped():
    sanitized = sanitize_log("\x1b[31merror\x1b[0m")
    assert "\x1b" not in sanitized
    assert "error" in sanitized


def test_over_long_line_truncated():
    sanitized = sanitize_log("x" * 20, max_line_len=10)
    assert " ...[truncated]" in sanitized


def test_over_many_lines_truncated():
    sanitized = sanitize_log("a\nb\nc", max_lines=2)
    assert "... [1 more lines truncated]" in sanitized


def test_output_wrapped_in_untrusted_markers():
    sanitized = sanitize_log("hello")
    assert sanitized.startswith("<untrusted_runtime_log>\n")
    assert sanitized.endswith("\n</untrusted_runtime_log>")
