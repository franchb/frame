"""Opt-in test-code and directory exclusion for directory scans
(`scan --skip-tests`, `scan --exclude-dir PATTERN`)."""

import json
from pathlib import Path

from frame.sil import FrameScanner
from frame.sil.cli import main as sil_main
from frame.sil.scanner import is_excluded_dir, is_test_path

GO_VULN = '''package main
import ("net/http"; "os/exec")
func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")).Run() }
'''

PY_VULN = '''import os
from flask import request

def h():
    os.system(request.args.get("c"))
'''

GO_TREE = [
    "main.go",
    "pkg/app/app.go",
    "test/e2e/suite.go",
    "tests/helper.go",
    "e2e/run.go",
    "pkg/app/testing/fake.go",
    "internal/testdata/fixture.go",
    "pkg/integration/prod.go",          # not a test directory by convention
    "pkg/apptesting/util.go",           # only exact directory names match
]
GO_TESTS = {"test/e2e/suite.go", "tests/helper.go", "e2e/run.go",
            "pkg/app/testing/fake.go"}

PY_TREE = [
    "app.py",
    "pkg/views.py",
    "tests/test_views.py",
    "tests/helpers.py",
    "pkg/test_models.py",
    "pkg/models_test.py",
    "conftest.py",
    "test/data.py",
    "pkg/testing_utils.py",             # not a test file by convention
]
PY_TESTS = {"tests/test_views.py", "tests/helpers.py", "pkg/test_models.py",
            "pkg/models_test.py", "conftest.py", "test/data.py"}


def _tree(root: Path, rels, body: str) -> None:
    for rel in rels:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)


def _scanned(root: Path, pattern: str, language: str, **kw):
    results = FrameScanner(language=language, verify=False).scan_directory(
        str(root), pattern, **kw)
    return {Path(r.filename).relative_to(root).as_posix() for r in results}


def test_go_tree_default_is_unchanged(tmp_path: Path):
    _tree(tmp_path, GO_TREE, GO_VULN)
    # testdata/ is always skipped for Go, with or without --skip-tests.
    assert _scanned(tmp_path, "**/*.go", "go") == set(GO_TREE) - {"internal/testdata/fixture.go"}


def test_go_tree_skip_tests(tmp_path: Path):
    _tree(tmp_path, GO_TREE, GO_VULN)
    assert _scanned(tmp_path, "**/*.go", "go", skip_tests=True) == (
        set(GO_TREE) - GO_TESTS - {"internal/testdata/fixture.go"})


def test_python_tree_default_is_unchanged(tmp_path: Path):
    _tree(tmp_path, PY_TREE, PY_VULN)
    assert _scanned(tmp_path, "**/*.py", "python") == set(PY_TREE)


def test_python_tree_skip_tests(tmp_path: Path):
    _tree(tmp_path, PY_TREE, PY_VULN)
    assert _scanned(tmp_path, "**/*.py", "python", skip_tests=True) == set(PY_TREE) - PY_TESTS


def test_scan_root_inside_a_test_directory_still_scans(tmp_path: Path):
    root = tmp_path / "test" / "e2e"
    _tree(root, ["suite.go"], GO_VULN)
    results = FrameScanner(language="go", verify=False).scan_directory(
        str(root), "**/*.go", skip_tests=True)
    assert [Path(r.filename).name for r in results] == ["suite.go"]
    assert "CWE-78" in {v.cwe_id for v in results[0].vulnerabilities}


def test_exclude_dir_name_and_path_patterns(tmp_path: Path):
    _tree(tmp_path, GO_TREE, GO_VULN)
    scanned = _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["e2e", "pkg/*/testing"])
    assert "test/e2e/suite.go" not in scanned and "e2e/run.go" not in scanned
    assert "pkg/app/testing/fake.go" not in scanned
    assert {"main.go", "pkg/app/app.go", "tests/helper.go"} <= scanned
    # A path pattern is anchored at the scan root.
    scanned = _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["app/testing"])
    assert "pkg/app/testing/fake.go" in scanned
    scanned = _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["pkg"])
    assert not any(s.startswith("pkg/") for s in scanned)


def test_exclude_dir_matches_below_the_root_only(tmp_path: Path):
    root = tmp_path / "vendorish" / "src"
    _tree(root, ["main.go"], GO_VULN)
    assert _scanned(root, "**/*.go", "go", exclude_dirs=["vendorish", "src"]) == {"main.go"}


def test_cli_skip_tests_and_repeated_exclude_dir(tmp_path: Path):
    _tree(tmp_path, GO_TREE, GO_VULN)
    out = tmp_path / "out.json"
    rc = sil_main(["scan", str(tmp_path), "-l", "go", "-p", "**/*.go", "--no-verify",
                   "-f", "json", "-o", str(out), "--fail-on", "none", "--skip-tests",
                   "--exclude-dir", "pkg/integration", "--exclude-dir", "*testing"])
    assert rc == 0
    files = {Path(f["filename"]).relative_to(tmp_path).as_posix()
             for f in json.loads(out.read_text())["files"]}
    assert files == {"main.go", "pkg/app/app.go"}


def test_cli_explicit_file_in_test_directory_is_still_scanned(tmp_path: Path):
    _tree(tmp_path, ["tests/test_views.py"], PY_VULN)
    out = tmp_path / "out.json"
    rc = sil_main(["scan", str(tmp_path / "tests" / "test_views.py"), "--no-verify",
                   "-f", "json", "-o", str(out), "--fail-on", "none", "--skip-tests",
                   "--exclude-dir", "tests"])
    assert rc == 0
    data = json.loads(out.read_text())
    vulns = data["files"][0]["vulnerabilities"] if "files" in data else data["vulnerabilities"]
    assert vulns, "an explicitly named file is analysed even under --skip-tests"


def test_frame_cli_accepts_the_options():
    from frame.cli import create_parser
    args = create_parser().parse_args(["scan", ".", "--skip-tests",
                                       "--exclude-dir", "a", "--exclude-dir", "b/*"])
    assert args.skip_tests and args.exclude_dir == ["a", "b/*"]


def test_other_language_conventions():
    assert is_test_path(Path("web/src/app.test.ts"))
    assert is_test_path(Path("web/src/app.spec.jsx"))
    assert is_test_path(Path("web/__tests__/app.js"))
    assert not is_test_path(Path("web/src/latest.js"))
    assert is_test_path(Path("svc/src/test/java/a/AppTest.java"))
    assert not is_test_path(Path("svc/src/main/java/a/App.java"))
    assert is_test_path(Path("App.Tests/AppTests.cs"))
    assert is_test_path(Path("src/App.UnitTests/Foo.cs"))
    assert not is_test_path(Path("src/App/Foo.cs"))
    assert is_test_path(Path("lib/tests/check.c"))
    assert not is_excluded_dir(Path("main.go"), ["*"])


# --- --exclude-dir normalization -------------------------------------------

STAGING = ["staging/direct.go", "staging/src/k8s.io/api/a.go", "pkg/staging/b.go", "main.go"]


def test_exclude_dir_leading_dot_slash_is_anchored(tmp_path: Path):
    _tree(tmp_path, STAGING, GO_VULN)
    assert _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["./staging"]) == {
        "pkg/staging/b.go", "main.go"}


def test_exclude_dir_trailing_slash_is_anchored_and_covers_the_subtree(tmp_path: Path):
    _tree(tmp_path, STAGING, GO_VULN)
    assert _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["staging/"]) == {
        "pkg/staging/b.go", "main.go"}


def test_exclude_dir_bare_name_matches_any_depth(tmp_path: Path):
    _tree(tmp_path, STAGING, GO_VULN)
    assert _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["staging"]) == {"main.go"}


def test_exclude_dir_star_matches_below_the_directory_only(tmp_path: Path):
    _tree(tmp_path, STAGING, GO_VULN)
    # `staging/*` names the directories inside staging/, not staging/ itself.
    assert _scanned(tmp_path, "**/*.go", "go", exclude_dirs=["staging/*"]) == {
        "staging/direct.go", "pkg/staging/b.go", "main.go"}


# --- --ai --repo-scale honours the exclusions --------------------------------

def _repo_scale_scanner(monkeypatch):
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    return FrameScanner(language="go", verify=False, llm_detect=True, llm_repo_scale=True)


def _llm_finding(root: Path, rel: str):
    from frame.sil.llm_detect import _repo_findings_to_vulns
    return _repo_findings_to_vulns([{"file": rel, "cwe": "CWE-22", "line": 1, "type": "path",
                                     "confidence": 0.9, "reasoning": "r"}], str(root))


def test_repo_scale_inventory_and_findings_respect_exclusions(tmp_path: Path, monkeypatch):
    from frame.sil import llm_detect
    _tree(tmp_path, ["main.go", "test/e2e/suite.go", "staging/x/s.go"], "package main\n")
    seen = {}

    def fake_repo(root, language, config, client=None, max_steps=None, path_filter=None):
        seen["inventory"] = set(llm_detect._repo_inventory(
            root, language, path_filter=path_filter).splitlines())
        return [v for rel in ("main.go", "test/e2e/suite.go", "staging/x/s.go")
                for v in _llm_finding(tmp_path, rel)]

    monkeypatch.setattr("frame.sil.llm_detect.detect_repo", fake_repo)
    results = _repo_scale_scanner(monkeypatch).scan_directory(
        str(tmp_path), "**/*.go", skip_tests=True, exclude_dirs=["staging/"])
    assert seen["inventory"] == {"main.go"}
    flagged = {Path(r.filename).resolve().relative_to(tmp_path.resolve()).as_posix()
               for r in results if r.vulnerabilities}
    assert flagged == {"main.go"}


def test_repo_scale_default_is_unchanged(tmp_path: Path, monkeypatch):
    _tree(tmp_path, ["main.go", "test/e2e/suite.go"], "package main\n")
    calls = []

    def fake_repo(root, language, config, client=None, max_steps=None):   # old signature
        calls.append(root)
        return [v for rel in ("main.go", "test/e2e/suite.go") for v in _llm_finding(tmp_path, rel)]

    monkeypatch.setattr("frame.sil.llm_detect.detect_repo", fake_repo)
    results = _repo_scale_scanner(monkeypatch).scan_directory(str(tmp_path), "**/*.go")
    assert len(calls) == 1
    assert sum(1 for r in results if r.vulnerabilities) == 2


def test_inventory_filter_is_applied_before_the_cap(tmp_path: Path):
    from frame.sil.llm_detect import _repo_inventory
    _tree(tmp_path, [f"test/t{i}.go" for i in range(5)] + ["main.go"], "package main\n")
    inv = _repo_inventory(str(tmp_path), "go", limit=2,
                          path_filter=lambda rel: not rel.startswith("test/"))
    assert inv.splitlines() == ["main.go"]
