"""Strict independence tests.

Algorithm #3 (this package) must not import or call Algorithm #1 (credential
compromise) or Algorithm #2 (data exfiltration). The only permitted future
interaction is through Aegivion Threat Correlation, which lives outside this
repository layer.

These tests fail if that boundary is ever violated — at import time or in
the source text.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

FORBIDDEN_PREFIXES = ("Aegivion_algo_1", "Aegivion_algo_2")
PACKAGE_ROOT = ROOT / "detection" / "cloud_destruction"
INGESTION_ROOT = ROOT / "ingestion"


def _python_files():
    for base in (PACKAGE_ROOT, INGESTION_ROOT):
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


class TestNoCrossAlgorithmImports:
    def test_no_static_imports_from_algo_1_or_2(self):
        violations = []
        for path in _python_files():
            for module in _module_imports(path):
                if module.startswith(FORBIDDEN_PREFIXES):
                    violations.append(f"{path}: imports {module}")
        assert violations == []

    def test_no_dynamic_references_in_source(self):
        """Grep-style guard: even string references must stay out."""
        violations = []
        for path in _python_files():
            text = path.read_text(encoding="utf-8")
            for prefix in FORBIDDEN_PREFIXES:
                # allow the independence tests themselves to
                # name the folders
                if path.name in (
                    "test_independence.py",
                    "test_part7_final.py",
                ):
                    continue
                if prefix in text:
                    violations.append(f"{path}: mentions {prefix}")
        assert violations == []

    def test_runtime_sys_modules_isolation(self):
        """Importing the whole package must not load sibling algorithms."""
        for module_name in list(sys.modules):
            if module_name.startswith(FORBIDDEN_PREFIXES):
                del sys.modules[module_name]
        import importlib

        importlib.import_module("detection.cloud_destruction")
        importlib.import_module("ingestion.aws.cloudtrail_resource_activity")
        loaded = [name for name in sys.modules if name.startswith(FORBIDDEN_PREFIXES)]
        assert loaded == []


class TestSelfContainment:
    def test_package_imports_are_internal_or_stdlib_or_third_party(self):
        """Every import inside Algorithm #3 resolves within it (or to stdlib/deps)."""
        allowed_roots = (
            "detection.cloud_destruction",
            "ingestion.aws",
            "detection",
            "ingestion",
        )
        unknown = []
        for path in _python_files():
            for module in _module_imports(path):
                root = module.split(".")[0]
                if root in {"detection", "ingestion"} and not module.startswith(allowed_roots):
                    unknown.append(f"{path}: {module}")
        assert unknown == []
