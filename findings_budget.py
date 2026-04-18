"""Repo-root shim for the scripts/findings_budget.py helpers."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent / "scripts" / "findings_budget.py"
SPEC = spec_from_file_location("_pipe2025_findings_budget", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - defensive
    raise ImportError(f"Unable to load findings budget helpers from {MODULE_PATH}")

MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SEVERITY_RANK = MODULE.SEVERITY_RANK
TRUNCATION_SUFFIX = MODULE.TRUNCATION_SUFFIX
trim_findings = MODULE.trim_findings
chunk_findings = MODULE.chunk_findings

__all__ = ["SEVERITY_RANK", "TRUNCATION_SUFFIX", "trim_findings", "chunk_findings"]
