import json

from show_heal_history import main


def test_show_heal_history_empty_dir(tmp_path, capsys):
    directory = tmp_path / "heal_history"
    main_args = ["--dir", str(directory)]

    import sys

    old_argv = sys.argv
    sys.argv = ["show_heal_history.py", *main_args]
    try:
        main()
    finally:
        sys.argv = old_argv

    assert capsys.readouterr().out.strip() == "No heal records yet."


def test_show_heal_history_lists_latest_first(tmp_path, capsys):
    directory = tmp_path / "heal_history"
    directory.mkdir()
    (directory / "older.json").write_text(
        json.dumps(
            {
                "run_id": "1",
                "timestamp": "2026-01-01T00:00:00Z",
                "iteration": 0,
                "preheal_passed": False,
                "postheal_passed": True,
                "tokens_total": 10,
                "files_touched": ["Dockerfile"],
            }
        )
    )
    (directory / "newer.json").write_text(
        json.dumps(
            {
                "run_id": "2",
                "timestamp": "2026-01-02T00:00:00Z",
                "iteration": 1,
                "preheal_passed": True,
                "postheal_passed": True,
                "tokens_total": 20,
                "files_touched": ["docker-compose.yml"],
            }
        )
    )

    import sys

    old_argv = sys.argv
    sys.argv = ["show_heal_history.py", "--dir", str(directory)]
    try:
        main()
    finally:
        sys.argv = old_argv

    output = capsys.readouterr().out.strip().splitlines()
    assert output[1].startswith("2 | 2026-01-02T00:00:00Z")
