from pathlib import Path

from collect_findings import inspect_dockerfile, inspect_workflow


def test_broken_dockerfile_reports_expected_advisories(
    tmp_path, monkeypatch, sample_dockerfile_broken
):
    monkeypatch.chdir(tmp_path)
    Path("Dockerfile").write_text(sample_dockerfile_broken)

    issues = []
    advisory_issues = []
    inspect_dockerfile(issues, advisory_issues)

    advisory_ids = {issue["id"] for issue in advisory_issues}
    assert {"legacy_base_image", "root_runtime"}.issubset(advisory_ids)


def test_dockerfile_comment_does_not_produce_root_runtime(
    tmp_path, monkeypatch, sample_dockerfile_clean
):
    monkeypatch.chdir(tmp_path)
    Path("Dockerfile").write_text(sample_dockerfile_clean)

    issues = []
    advisory_issues = []
    inspect_dockerfile(issues, advisory_issues)

    advisory_ids = {issue["id"] for issue in advisory_issues}
    assert "root_runtime" not in advisory_ids


def test_workflow_dispatch_with_extra_space_is_still_recognized(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_dir.joinpath("aiheal-showcase.yml").write_text(
        """on:
  push: {}
  workflow_dispatch : {}
jobs:
  demo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: test
          path: artifacts/
"""
    )

    issues = []
    advisory_issues = []
    inspect_workflow(issues, advisory_issues)

    advisory_ids = {issue["id"] for issue in advisory_issues}
    assert "manual_trigger_missing" not in advisory_ids
    assert "artifact_publishing_missing" not in advisory_ids
