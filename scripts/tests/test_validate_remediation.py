from pathlib import Path

import pytest

from validate_remediation import validate_plan


def test_plan_with_path_outside_allow_list_raises():
    plan = {"changes": [{"path": "README.md", "content": "nope"}]}
    with pytest.raises(RuntimeError, match="Unsupported remediation path"):
        validate_plan(plan)


def test_plan_with_empty_content_raises():
    plan = {"changes": [{"path": "Dockerfile", "content": "   "}]}
    with pytest.raises(RuntimeError, match="Empty content"):
        validate_plan(plan)


def test_workflow_widened_permissions_raise(tmp_path, monkeypatch, sample_workflow_yaml):
    workflow_path = tmp_path / ".github" / "workflows" / "aiheal-showcase.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(sample_workflow_yaml)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("validate_remediation.validate_actionlint", lambda content: None)

    plan = {
        "changes": [
            {
                "path": ".github/workflows/aiheal-showcase.yml",
                "content": sample_workflow_yaml.replace("contents: read", "contents: write"),
            }
        ]
    }

    with pytest.raises(RuntimeError, match="permissions.*contents"):
        validate_plan(plan, root=tmp_path)
