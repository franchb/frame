"""`--ai` coverage on Go must not shrink when the symbolic frontend lands.

Before the Go frontend, Go ran the LLM layer on every file under --ai. With a
frontend, _apply_llm_detect would gate on is_detection_candidate, whose patterns
do not know Go. Go therefore bypasses that gate. Stubbed LLM: no network.
"""

from types import SimpleNamespace

import frame.sil.llm_detect as llm_detect
import frame.sil.llm_triage as llm_triage
from frame.sil import FrameScanner
from frame.sil.llm_detect import is_detection_candidate


def _run(monkeypatch, language, src, filename):
    calls = []
    monkeypatch.setattr(llm_detect, "detect_agentic",
                        lambda *a, **k: calls.append(a) or [])
    monkeypatch.setattr(llm_triage, "LLMTriageClient", lambda config: SimpleNamespace())
    cfg = SimpleNamespace(base_url="http://127.0.0.1:9", model="stub", repo_root="")
    result = FrameScanner(language=language, verify=False, llm_detect=True,
                           llm_config=cfg).scan(src, filename)
    return calls, result


def test_go_file_without_symbolic_finding_still_reaches_llm(monkeypatch):
    src = 'package main\nimport "os/exec"\nfunc run(command string) { exec.Command(command).Run() }\n'
    # Precondition: `command` is a plain string parameter, not a request-derived
    # source, so there is no symbolic finding here -- and the source doesn't
    # match the language-agnostic candidate heuristic either (it has no Go
    # patterns). Without the bypass, _apply_llm_detect would skip this file.
    assert not is_detection_candidate(src, False)
    calls, result = _run(monkeypatch, "go", src, "run.go")
    assert result.vulnerabilities == []
    assert len(calls) == 1


def test_go_file_with_symbolic_finding_reaches_llm(monkeypatch):
    src = ('package main\nimport ("net/http"; "os/exec")\n'
           'func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")) }\n')
    calls, result = _run(monkeypatch, "go", src, "h.go")
    assert "CWE-78" in {v.cwe_id for v in result.vulnerabilities}
    assert len(calls) == 1


def test_other_languages_keep_the_candidate_gate(monkeypatch):
    calls, _ = _run(monkeypatch, "python", "def f(x):\n    return x\n", "f.py")
    assert calls == []


def _boom(*a, **k):
    raise RuntimeError("translator blew up")


def test_go_symbolic_crash_still_reaches_llm(monkeypatch):
    # A file that crashes the symbolic layer (e.g. a `+` chain deep enough to
    # hit __str__ recursion) must not also lose the LLM pass under --ai.
    import frame.sil.scanner as scanner_mod
    monkeypatch.setattr(scanner_mod.SILTranslator, "translate_program", _boom)
    src = 'package main\nimport "os/exec"\nfunc run(command string) { exec.Command(command).Run() }\n'
    calls, result = _run(monkeypatch, "go", src, "run.go")
    assert any("Scan error" in e for e in result.errors)
    assert len(calls) == 1


def test_go_frontend_crash_still_reaches_llm(monkeypatch):
    from frame.sil.frontends.go_frontend import GoFrontend
    monkeypatch.setattr(GoFrontend, "translate", _boom)
    calls, result = _run(monkeypatch, "go", "package main\n", "p.go")
    assert any("Scan error" in e for e in result.errors)
    assert len(calls) == 1


def test_other_languages_symbolic_crash_is_unchanged(monkeypatch):
    import frame.sil.scanner as scanner_mod
    monkeypatch.setattr(scanner_mod.SILTranslator, "translate_program", _boom)
    calls, result = _run(monkeypatch, "python", "import os\nos.system(input())\n", "f.py")
    assert any("Scan error" in e for e in result.errors)
    assert calls == []
