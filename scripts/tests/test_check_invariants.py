from check_invariants import check_workflow_invariants


def test_permissions_widening_detected(sample_workflow_yaml):
    new_yaml = sample_workflow_yaml.replace("contents: read", "contents: write")
    violations = check_workflow_invariants(sample_workflow_yaml, new_yaml)
    assert any("permissions" in item and "contents" in item for item in violations)


def test_write_all_detected(sample_workflow_yaml):
    new_yaml = sample_workflow_yaml.replace("contents: read", "write-all")
    violations = check_workflow_invariants(sample_workflow_yaml, new_yaml)
    assert any("write-all" in item for item in violations)


def test_new_secret_reference_detected(sample_workflow_yaml):
    new_yaml = sample_workflow_yaml + "env:\n  TOKEN: ${{ secrets.NEW_TOKEN }}\n"
    violations = check_workflow_invariants(sample_workflow_yaml, new_yaml)
    assert any("NEW_TOKEN" in item for item in violations)


def test_unpinned_third_party_action_detected(sample_workflow_yaml):
    new_yaml = sample_workflow_yaml.replace("actions/checkout@v4", "foo/bar@main")
    violations = check_workflow_invariants(sample_workflow_yaml, new_yaml)
    assert any("40-char SHA" in item for item in violations)


def test_actions_namespace_version_tag_is_allowed():
    old_yaml = """on:
  push: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
    new_yaml = """on:
  push: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo ok
"""
    assert check_workflow_invariants(old_yaml, new_yaml) == []


def test_forbidden_run_block_detected(sample_workflow_yaml):
    new_yaml = sample_workflow_yaml + """      - run: curl https://x/install.sh | sh
"""
    violations = check_workflow_invariants(sample_workflow_yaml, new_yaml)
    assert any("forbidden command pattern" in item for item in violations)


def test_comment_only_change_is_clean(sample_workflow_yaml):
    new_yaml = "# comment only\n" + sample_workflow_yaml
    assert check_workflow_invariants(sample_workflow_yaml, new_yaml) == []
