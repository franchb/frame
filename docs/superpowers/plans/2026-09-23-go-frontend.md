# Go Symbolic Frontend (taint + CWE-770) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `.go` files sound symbolic taint findings (CWE-89/78/22/601/918/79/770) through Frame's shared tree-sitter → SIL → `SILTranslator` pipeline, replacing today's LLM-only fallback.

**Architecture:** A per-file `GoFrontend` parses with tree-sitter-go, builds a syntactic import/type environment (`_go_env.py`), and lowers Go to SIL. Every resolved call is registered in the program's own `library_specs` under a name that is unique per call site (`$r_N.Method`) or canonical in a reserved namespace (`go:pkg/path.Func`), and `Program.exact_spec_lookup` turns off the translator's fuzzy spec fallbacks. Same-file procedure summaries (`_go_summaries.py`) and guard-fact sanitization (`_go_guards.py`) are computed by the frontend; the translator only gains two Go-gated edits.

**Tech Stack:** Python ≥3.10, tree-sitter 0.26 binding, tree-sitter-go 0.25.0 (verified to load under tree-sitter 0.26.0 during planning), z3, pytest.

**Spec:** `docs/superpowers/specs/2026-09-23-go-frontend-design.md` (rev 4). Read it before starting; this plan implements it and cites its sections.

## Global Constraints

- Program language string is exactly `"go"`; Go stays out of `_is_c_lang` and `_IMPLICIT_RECEIVER_LANGUAGES`.
- No behaviour change for any other language: every translator/procedure edit is gated on `language == "go"` or on `exact_spec_lookup` (default `False`).
- Registered spec names are only `$r_N.<Method>` (site-unique receiver temp), `go:<canonical key>`, `go:<canonical key>~N` (site variant), `go:<builtin>`, or a same-file procedure name `go:F` / `go:Type.M`. Unresolved calls are emitted under source text and are never registered.
- Canonical package paths drop a trailing `/vN` (`github.com/labstack/echo/v4` → `github.com/labstack/echo`).
- The frontend never raises on user code; unsupported constructs lower to an opaque value or a default-propagation call.
- Sources in this milestone: handler-shaped `*http.Request`/`http.Request` params, `gin.Context`/`echo.Context`/`fiber.Ctx` params, and (only with `library_mode`) exported-function params typed `string`/`[]byte`/`io.Reader`. `os.Args`, `os.Getenv`, stdin are NOT sources.
- Precision over recall: when a rule cannot decide (unknown type, untrusted root, unrecognised guard), the frontend abstains from sanitizing and from registering, never guesses.
- Tests run with `.venv/bin/python -m pytest` from the repository root.
- Commit after every task; commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **Deeply nested or very large Go files** — a reasonable person expects a result (possibly with `result.errors`), never a Python `RecursionError` escaping `scan()`. Test added in Task 4 (`test_deep_nesting_does_not_crash`).
2. **Generic types and generic receivers** (`func (s *Set[T]) Add(x T)`, `F[int](x)`) — expected to lower and resolve like non-generic code. Test added in Task 4 (`test_generic_receiver_method_resolves`).
3. **An import alias shadowed by a local** (`exec := runner; exec.Command(x)`) — expected NOT to resolve to `os/exec.Command`. Test added in Task 3 (`test_local_shadows_import_alias`) and Task 4 (`test_shadowed_alias_is_not_a_sink`).
4. **Files with syntax errors** — intact functions still produce findings; broken ones are skipped. Test added in Task 4 (`test_syntax_error_keeps_intact_functions`).
5. **CRLF line endings, a UTF-8 BOM, and invalid UTF-8 bytes read through `scan_file`** — expected to scan normally. Test added in Task 8 (`test_scan_file_tolerates_crlf_bom_and_bad_bytes`).

---

## File Structure

| File | Responsibility |
|------|----------------|
| `frame/sil/procedure.py` (modify) | `Program.exact_spec_lookup`; exact-only branch in `get_spec` |
| `frame/sil/translator.py` (modify) | `_is_go_lang`; Go gate in `_is_noreturn_call`; Go assignment-replaces-value settlement |
| `frame/sil/frontends/_go_env.py` (create) | Import table, syntactic types, struct fields, signatures, `Scope` |
| `frame/sil/specs/go_specs.py` (create) | `GO_SPECS` and Go lowering-hint tables (all data) |
| `frame/sil/frontends/go_frontend.py` (create) | `GoFrontend`: procedures, statements, expressions, call resolution/registration, sources |
| `frame/sil/frontends/_go_summaries.py` (create) | Same-file summaries (out of callees) and the into-callee fixpoint |
| `frame/sil/frontends/_go_guards.py` (create) | Guard-fact CNF, sanitizer rules, `TrustOracle` |
| `frame/sil/frontends/__init__.py`, `frame/sil/specs/__init__.py` (modify) | `GoFrontend` / `GO_SPECS` exports with availability flag |
| `frame/sil/scanner.py` (modify) | `"go"` frontend, `.go` extension maps, Go directory exclusions, LLM candidate-gate bypass |
| `frame/sil/cli.py` (modify) | help text |
| `requirements.txt`, `pyproject.toml` (modify) | `tree-sitter-go>=0.25.0` |
| `benchmarks/vloc/README.md` (modify) | coverage row + measurement runbook |
| `tests/test_go_translator_contract.py` | Task 1 |
| `tests/test_go_env.py` | Task 2 |
| `tests/test_go_specs.py` | Task 3 |
| `tests/test_go_frontend.py` | Tasks 4–6 lowering unit tests |
| `tests/test_go_taint.py` | Tasks 4–7 end-to-end fixtures |
| `tests/test_go_scanner.py` | Task 8 |
| `tests/test_go_llm_coverage.py` | Task 8 |

---

### Task 1: Translator contract for Go

Makes the shared translator safe for a Go program before any Go is parsed: exact spec lookup, no name-based no-return, and assignment that replaces (not accumulates) taint and sanitization. Also pins, as tests, the translator behaviours the spec relies on (spec § "Return-value sanitizers" → "Translator behaviour this relies on").

**Files:**
- Modify: `frame/sil/procedure.py` (class `Program`, method `get_spec`)
- Modify: `frame/sil/translator.py` (add `_is_go_lang` next to `_is_c_lang` ~line 858; `_is_noreturn_call` ~line 4393; Assign dispatch ~line 1503)
- Modify: `.gitignore`
- Test: `tests/test_go_translator_contract.py`

**Interfaces:**
- Produces: `Program(exact_spec_lookup: bool = False)`; `SILTranslator._is_go_lang -> bool`. Later tasks construct `Program(language="go", exact_spec_lookup=True)`.

- [ ] **Step 0: Create the project venv and record the baseline**

```bash
cd /home/iru/p/github.com/franchb/frame
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt -r requirements-dev.txt pytest
grep -qxF '.venv/' .gitignore || echo '.venv/' >> .gitignore
.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3
```

Write the final summary line (e.g. `1901 passed, 12 skipped`) into your task notes. It is the regression baseline every later task compares against. If `requirements-dev.txt` does not exist, drop that `-r` argument.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_go_translator_contract.py`:

```python
"""The translator contract the Go frontend builds on.

Hand-built SIL programs (no parser) pin down how SILTranslator treats a
program whose language is "go": exact spec lookup, per-kind sanitization that
survives propagation, and assignment that REPLACES a variable's taint and
sanitization. The Go frontend's design (docs/superpowers/specs/
2026-09-23-go-frontend-design.md) depends on every one of these.
"""

from frame.sil.types import Ident, PVar, Typ, Location, ExpVar, ExpConst, ExpBinOp
from frame.sil.instructions import (
    Call, Assign, Prune, Return, TaintSource, Sanitize, TaintKind, SinkKind,
)
from frame.sil.procedure import Procedure, Program, ProcSpec, NodeKind
from frame.sil.translator import SILTranslator

LOC = Location("t.go", 1)


def _proc(instrs, name="go:f"):
    proc = Procedure(name=name, loc=LOC)
    entry = proc.new_node(NodeKind.ENTRY)
    proc.add_node(entry)
    proc.entry_node = entry.id
    entry.instrs.extend(instrs)
    exit_node = proc.new_node(NodeKind.EXIT)
    proc.add_node(exit_node)
    proc.exit_node = exit_node.id
    proc.connect(entry.id, exit_node.id)
    return proc


def _call(ret, name, *args):
    return Call(loc=LOC,
                ret=(Ident(ret, 1), Typ.unknown_type()) if ret else None,
                func=ExpConst.string(name),
                args=[(a, Typ.unknown_type()) for a in args])


def _v(name):
    return ExpVar(PVar(name))


def _ret(name):
    return ExpVar(Ident(name, 1))


def _src(name):
    return TaintSource(loc=LOC, var=PVar(name), kind=TaintKind.USER_INPUT)


def _sink_types(instrs, specs, exact=True, language="go"):
    program = Program(language=language, exact_spec_lookup=exact,
                      library_specs=dict(specs))
    program.add_procedure(_proc(instrs))
    return {c.sink_type for c in SILTranslator(program).translate_program()}


ALLOC = {"bytes.Repeat": ProcSpec(is_sink="alloc_size", sink_args=[1])}


def test_exact_lookup_blocks_type_prefix_fallback():
    # "custom.Repeat" reaches "bytes.Repeat" through get_spec's hard-coded
    # `bytes` prefix unless lookup is exact.
    instrs = [_src("n"), _call("c", "custom.Repeat", _v("s"), _v("n"))]
    assert "alloc_size" not in _sink_types(instrs, ALLOC, exact=True)


def test_fallback_still_exists_when_not_exact():
    instrs = [_src("n"), _call("c", "custom.Repeat", _v("s"), _v("n"))]
    assert "alloc_size" in _sink_types(instrs, ALLOC, exact=False)


def test_exact_lookup_still_finds_procedure_spec():
    program = Program(language="go", exact_spec_lookup=True)
    callee = _proc([], name="go:helper")
    callee.spec = ProcSpec(taint_propagates=[0])
    program.add_procedure(callee)
    assert program.get_spec("go:helper") is callee.spec
    assert program.get_spec("helper") is None


SQL_AND_ALLOC = {
    "go:strconv.Atoi": ProcSpec(
        is_sanitizer=["sql", "shell", "filesystem", "redirect", "ssrf", "html"],
        taint_propagates=[0]),
    "go:make": ProcSpec(is_sink="alloc_size", sink_args=[1, 2]),
    "$r_9.Query": ProcSpec(is_sink="sql", sink_args=[0]),
}


def test_atoi_sanitizes_injection_but_keeps_alloc_size():
    instrs = [
        _src("x"),
        _call("n", "go:strconv.Atoi", _v("x")),
        Assign(loc=LOC, id=PVar("k"), exp=_ret("n")),
        _call("m", "go:make", ExpConst.string("[]byte"), _v("k")),
        _call("q", "$r_9.Query", _v("k")),
    ]
    kinds = _sink_types(instrs, SQL_AND_ALLOC)
    assert "alloc_size" in kinds
    assert "sql" not in kinds


OPEN = {"go:os.Open": ProcSpec(is_sink="filesystem", sink_args=[0])}


def test_sanitize_carries_through_plain_assignment():
    instrs = [
        _src("p"),
        Sanitize(loc=LOC, var=PVar("p"), sanitizes=[SinkKind.FILE_PATH]),
        Assign(loc=LOC, id=PVar("q"), exp=_v("p")),
        _call("f", "go:os.Open", _v("q")),
    ]
    assert "filesystem" not in _sink_types(instrs, OPEN)


def test_reassignment_replaces_sanitization():
    # p was sanitized, then REPLACED by fresh tainted data: the sink must fire.
    instrs = [
        _src("p"),
        Sanitize(loc=LOC, var=PVar("p"), sanitizes=[SinkKind.FILE_PATH]),
        _src("y"),
        Assign(loc=LOC, id=PVar("p"), exp=_v("y")),
        _call("f", "go:os.Open", _v("p")),
    ]
    assert "filesystem" in _sink_types(instrs, OPEN)


def test_reassignment_to_constant_clears_taint():
    instrs = [
        _src("p"),
        Assign(loc=LOC, id=PVar("p"), exp=ExpConst.string("/etc/app.conf")),
        _call("f", "go:os.Open", _v("p")),
    ]
    assert "filesystem" not in _sink_types(instrs, OPEN)


def test_self_update_keeps_taint_and_drops_sanitization_it_no_longer_has():
    # p = p + y: still tainted, and sanitized only for what BOTH sides were.
    instrs = [
        _src("p"),
        Sanitize(loc=LOC, var=PVar("p"), sanitizes=[SinkKind.FILE_PATH]),
        _src("y"),
        Assign(loc=LOC, id=PVar("p"), exp=ExpBinOp("+", _v("p"), _v("y"))),
        _call("f", "go:os.Open", _v("p")),
    ]
    assert "filesystem" in _sink_types(instrs, OPEN)


def test_plain_flow_fires():
    # Positive counterpart of the sanitize test above: without the Sanitize the
    # same flow must fire, or that test proves nothing.
    instrs = [_src("p"), Assign(loc=LOC, id=PVar("q"), exp=_v("p")),
              _call("f", "go:os.Open", _v("q"))]
    assert "filesystem" in _sink_types(instrs, OPEN)


def _branch_program(entry_instrs, cond, then_instrs, else_instrs, specs):
    """entry --(Prune cond T | Prune cond F)--> then / else: the two-way layout
    the Go frontend emits (both prunes in the branching node, successor 0 is the
    true side), matching SILTranslator._branch_edge_formula."""
    proc = Procedure(name="go:f", loc=LOC)
    entry = proc.new_node(NodeKind.ENTRY)
    proc.add_node(entry)
    proc.entry_node = entry.id
    entry.instrs.extend(entry_instrs)
    entry.instrs.append(Prune(loc=LOC, condition=cond, is_true_branch=True))
    entry.instrs.append(Prune(loc=LOC, condition=cond, is_true_branch=False))
    then_node, else_node = proc.new_node(), proc.new_node()
    exit_node = proc.new_node(NodeKind.EXIT)
    for n in (then_node, else_node, exit_node):
        proc.add_node(n)
    proc.exit_node = exit_node.id
    then_node.instrs.extend(then_instrs)
    else_node.instrs.extend(else_instrs)
    proc.connect(entry.id, then_node.id)
    proc.connect(entry.id, else_node.id)
    proc.connect(then_node.id, exit_node.id)
    proc.connect(else_node.id, exit_node.id)
    program = Program(language="go", exact_spec_lookup=True, library_specs=dict(specs))
    program.add_procedure(proc)
    return {c.sink_type for c in SILTranslator(program).translate_program()}


MAKE = {"go:make": ProcSpec(is_sink="alloc_size", sink_args=[1, 2])}


def test_bound_on_the_branch_edge_discharges_alloc_size():
    make = _call("m", "go:make", ExpConst.string("[]byte"), _v("n"))
    bounded = _branch_program([_src("n")], ExpBinOp(">", _v("n"), ExpConst.integer(1048576)),
                              [Return(loc=LOC, value=None)], [make], MAKE)
    assert "alloc_size" not in bounded
    unbounded = _branch_program([_src("n")], ExpBinOp(">", _v("k"), ExpConst.integer(1)),
                                [Return(loc=LOC, value=None)], [make], MAKE)
    assert "alloc_size" in unbounded


def test_constant_false_branch_is_dead():
    sink = _call("f", "go:os.Open", _v("p"))
    assert "filesystem" not in _branch_program([_src("p")], ExpConst.boolean(False), [sink], [], OPEN)
    assert "filesystem" in _branch_program([_src("p")], ExpConst.boolean(True), [sink], [], OPEN)


def test_noreturn_names_do_not_cut_go_paths():
    # "exit" and "err" are C no-return names; in Go they are ordinary
    # identifiers and must not end the path before the sink.
    instrs = [_src("p"), _call(None, "exit"), _call("f", "go:os.Open", _v("p"))]
    assert "filesystem" in _sink_types(instrs, OPEN)
```

- [ ] **Step 2: Run the tests to see which fail**

Run: `.venv/bin/python -m pytest tests/test_go_translator_contract.py -v`

Expected before the change:
- FAIL (TypeError, unexpected keyword `exact_spec_lookup`): every test.

After Step 3 adds only the field and the exact branch, re-run and expect `test_reassignment_replaces_sanitization`, `test_self_update_keeps_taint_and_drops_sanitization_it_no_longer_has` and `test_noreturn_names_do_not_cut_go_paths` to FAIL; `test_reassignment_to_constant_clears_taint` may pass or fail at this point (Step 4 makes it pass either way). The exact-lookup tests, `test_atoi_sanitizes_injection_but_keeps_alloc_size`, `test_sanitize_carries_through_plain_assignment`, `test_plain_flow_fires`, `test_bound_on_the_branch_edge_discharges_alloc_size` and `test_constant_false_branch_is_dead` characterise existing behaviour and must PASS after Step 3. **If any of them fails, stop and report it with the output**: the spec's sanitizer encoding and the Go frontend's branch layout (Task 4 `_branch`) assume them, and the fix must be discussed rather than guessed.

- [ ] **Step 3: Add `exact_spec_lookup` to `Program`**

In `frame/sil/procedure.py`, in the `Program` dataclass directly after the `language: str = ""` field, add:

```python
    # Set by frontends that resolve call names before lookup (Go). A miss is
    # then a miss: no suffix, type-prefix or bare-method fallback, which would
    # let an unresolved `x.Query` borrow another type's spec.
    exact_spec_lookup: bool = False
```

In `Program.get_spec`, directly after the block

```python
        # Check library specs (exact match)
        spec = self.library_specs.get(func_name)
        if spec:
            return spec
```

insert:

```python
        if self.exact_spec_lookup:
            return None
```

- [ ] **Step 4: Gate no-return and add assignment settlement for Go**

In `frame/sil/translator.py`, directly after the `_is_c_lang` property, add:

```python
    @property
    def _is_go_lang(self) -> bool:
        """The Go frontend owns path termination and resolves every call name
        itself; a few shared behaviours are switched for it."""
        return (getattr(self.program, "language", "") or "").lower() == "go"
```

At the top of `_is_noreturn_call`, before `if not isinstance(instr, Call):`, add:

```python
        # Go termination is structural (the frontend ends the path after
        # panic/os.Exit/log.Fatal*). The C names below (`exit`, `err`) are
        # ordinary Go identifiers and must not cut a Go path.
        if self._is_go_lang:
            return False
```

Replace the Assign dispatch

```python
        if isinstance(instr, Assign):
            assign_checks, state = self._exec_assign(instr, state, proc_name)
            checks.extend(assign_checks)
```

with

```python
        if isinstance(instr, Assign):
            go_rhs = self._go_assign_rhs(instr, state) if self._is_go_lang else None
            assign_checks, state = self._exec_assign(instr, state, proc_name)
            checks.extend(assign_checks)
            if go_rhs is not None:
                self._go_settle_assign(instr, state, go_rhs)
```

and add these two methods directly after `_exec_assign`'s definition ends (before the next `def`):

```python
    def _go_assign_rhs(self, instr: Assign, state: SymbolicState):
        """Go: the taint and sanitization an assignment's right-hand side
        carries, read BEFORE the assignment runs, so `p = p + y` sees old p."""
        tainted = [v for v in self._get_exp_vars(instr.exp) if state.is_tainted(v)]
        if not tainted:
            return (None, set())
        kinds = set(state.sanitized.get(tainted[0], []))
        for v in tainted[1:]:
            kinds &= set(state.sanitized.get(v, []))
        return (state.get_taint_info(tainted[0]), kinds)

    def _go_settle_assign(self, instr: Assign, state: SymbolicState, rhs) -> None:
        """Go: an assignment REPLACES the target's value. The shared
        _exec_assign only adds taint and unions sanitization, which would leave
        a sanitized-then-reassigned variable looking clean (a missed finding)
        and a reassigned-to-constant variable looking tainted."""
        target = self._get_var_name(instr.id)
        info, kinds = rhs
        if info is None:
            state.tainted.pop(target, None)
            state.sanitized.pop(target, None)
            return
        if target not in state.tainted:
            state.tainted[target] = info
        if kinds:
            state.sanitized[target] = sorted(kinds)
        else:
            state.sanitized.pop(target, None)
```

- [ ] **Step 5: Run the contract tests**

Run: `.venv/bin/python -m pytest tests/test_go_translator_contract.py -v`
Expected: all 12 PASS.

- [ ] **Step 6: Run the full suite against the baseline**

Run: `.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3`
Expected: baseline count + 12 passed, and no new failures.

- [ ] **Step 7: Commit**

```bash
git add .gitignore frame/sil/procedure.py frame/sil/translator.py tests/test_go_translator_contract.py
git commit -m "Translator contract for Go: exact spec lookup, structural termination, replacing assignment

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Go import and type environment

**Files:**
- Create: `frame/sil/frontends/_go_env.py`
- Modify: `requirements.txt`, `pyproject.toml`
- Test: `tests/test_go_env.py`

**Interfaces:**
- Produces (all in `frame.sil.frontends._go_env`):
  - `GoType(path: str = "", pointer: bool = False)` with `.known -> bool`; `UNKNOWN = GoType("")`
  - `FuncSig(name, params: List[Tuple[str, GoType]], results: List[GoType], receiver: Optional[Tuple[str, GoType]], exported: bool)`
  - `FileEnv` with `package`, `imports: Dict[str,str]`, `struct_fields: Dict[str, Dict[str, GoType]]`, `package_vars: Dict[str, GoType]`, `consts: Dict[str, object]`, `funcs: Dict[str, FuncSig]`, `methods: Dict[Tuple[str,str], FuncSig]`, `local_types: Set[str]`, and `pkg_of(alias) -> Optional[str]`
  - `canonical_pkg(path) -> str`, `default_package_name(path) -> str`
  - `text(node, src: bytes) -> str`, `literal_value(node, src) -> object | None`
  - `type_of(node, src, imports) -> GoType`, `params_of(plist, src, imports) -> List[Tuple[str, GoType]]`
  - `build_file_env(root, src: bytes) -> FileEnv`
  - `Scope(parent=None)` with `declare(name, typ=UNKNOWN)`, `lookup(name) -> Optional[GoType]`, `child() -> Scope`
  - `statements_of(block) -> List[node]` (flattens tree-sitter-go 0.25's `statement_list`)

- [ ] **Step 1: Add the dependency**

In `requirements.txt`, after the `tree-sitter-c-sharp` line add:

```
tree-sitter-go>=0.25.0
```

In `pyproject.toml`, add `"tree-sitter-go>=0.25.0",` to both the `scan` and `all` optional-dependency lists, next to `"tree-sitter-python>=0.21.0",`.

Run: `.venv/bin/pip install -q "tree-sitter-go>=0.25.0" && .venv/bin/python -c "import tree_sitter_go as g; from tree_sitter import Language, Parser; Parser(Language(g.language())); print('ok')"`
Expected: `ok`. (Verified during planning: tree-sitter-go 0.25.0 loads under tree-sitter 0.26.0.) If it fails, run `.venv/bin/pip install "tree-sitter-go>=0.23,<0.24"`, repeat, and pin that range in both files instead.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_go_env.py`:

```python
"""The Go frontend's per-file import and type environment."""

import tree_sitter_go as tsgo
from tree_sitter import Language, Parser

from frame.sil.frontends._go_env import (
    GoType, UNKNOWN, Scope, build_file_env, canonical_pkg, default_package_name,
)

_PARSER = Parser(Language(tsgo.language()))


def _env(src: str):
    data = src.encode()
    return build_file_env(_PARSER.parse(data).root_node, data)


SRC = '''package main

import (
	"database/sql"
	"net/http"
	osexec "os/exec"
	_ "embed"
	. "strings"
	"github.com/labstack/echo/v4"
	"github.com/cyphar/filepath-securejoin"
)

const apiKey = "k-123"
const limit = 10
var root = "/srv"
var db *sql.DB

type Server struct {
	root string
	db   *sql.DB
}

type Set[T any] struct{ items []T }

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) (string, error) { return "", nil }
func (s *Set[T]) Add(x T) {}
func helper(xs ...string) int { return 0 }
func Exported(p string) {}
'''


def test_imports_default_alias_and_versions():
    env = _env(SRC)
    assert env.imports["sql"] == "database/sql"
    assert env.imports["http"] == "net/http"
    assert env.imports["osexec"] == "os/exec"
    assert env.imports["echo"] == "github.com/labstack/echo/v4"
    assert env.imports["securejoin"] == "github.com/cyphar/filepath-securejoin"
    assert "_" not in env.imports and "." not in env.imports
    assert env.pkg_of("echo") == "github.com/labstack/echo"


def test_canonical_and_default_names():
    assert canonical_pkg("github.com/go-chi/chi/v5") == "github.com/go-chi/chi"
    assert default_package_name("gopkg.in/yaml.v3") == "yaml"
    assert default_package_name("os/exec") == "exec"


def test_package_level_declarations():
    env = _env(SRC)
    assert env.consts["apiKey"] == "k-123"
    assert env.consts["limit"] == 10
    assert env.package_vars["db"] == GoType("database/sql.DB", True)
    assert env.struct_fields["Server"]["db"] == GoType("database/sql.DB", True)
    assert env.struct_fields["Server"]["root"] == GoType("string")
    assert "Server" in env.local_types and "Set" in env.local_types


def test_signatures_and_methods():
    env = _env(SRC)
    sig = env.methods[("Server", "Handle")]
    assert sig.name == "Server.Handle"
    assert sig.receiver == ("s", GoType("Server", True))
    assert [t for _, t in sig.params] == [GoType("net/http.ResponseWriter"),
                                          GoType("net/http.Request", True)]
    assert sig.results == [GoType("string"), GoType("error")]
    assert ("Set", "Add") in env.methods          # generic receiver
    assert env.funcs["helper"].params == [("xs", GoType("[]string"))]
    assert env.funcs["Exported"].exported and not env.funcs["helper"].exported


def test_scope_shadowing():
    outer = Scope()
    outer.declare("x", GoType("string"))
    inner = outer.child()
    assert inner.lookup("x") == GoType("string")
    inner.declare("x", GoType("int"))
    assert inner.lookup("x") == GoType("int")
    assert outer.lookup("x") == GoType("string")
    assert inner.lookup("nope") is None
    inner.declare("_", GoType("int"))
    assert inner.lookup("_") is None


def test_unknown_type_is_unknown():
    assert not UNKNOWN.known
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_go_env.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'frame.sil.frontends._go_env'`.

- [ ] **Step 4: Implement `_go_env.py`**

Create `frame/sil/frontends/_go_env.py`:

```python
"""Per-file import and syntactic type environment for the Go frontend.

Go writes parameter, receiver, field and most variable types in source, so a
single parse yields package-qualified names without a Go toolchain:
`osexec.Command` resolves to `os/exec.Command` through the import table, and
`db.Query` resolves to `database/sql.DB.Query` because `db` was declared
`*sql.DB`. Everything here is syntactic. An unknown type is UNKNOWN, never a
guess, because a wrong guess becomes a wrong spec and a false finding.
"""

import codecs
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

BUILTIN_TYPES = frozenset({
    "bool", "byte", "complex64", "complex128", "error", "float32", "float64",
    "int", "int8", "int16", "int32", "int64", "rune", "string",
    "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any",
})

# Import paths whose package name is not their last path element.
_PACKAGE_NAMES = {
    "github.com/cyphar/filepath-securejoin": "securejoin",
    "gopkg.in/yaml.v2": "yaml",
    "gopkg.in/yaml.v3": "yaml",
}

_VERSION_SUFFIX = re.compile(r"/v\d+$")


def canonical_pkg(path: str) -> str:
    """Drop a major-version suffix: github.com/labstack/echo/v4 -> .../echo."""
    return _VERSION_SUFFIX.sub("", path)


def default_package_name(path: str) -> str:
    if path in _PACKAGE_NAMES:
        return _PACKAGE_NAMES[path]
    return canonical_pkg(path).rsplit("/", 1)[-1]


@dataclass(frozen=True)
class GoType:
    """A syntactic type. `path` is canonical: 'net/http.Request' for an imported
    named type, 'Server' for a type declared in this file, 'string' for a
    builtin, source text for composite types ('[]byte'), '' when unknown."""
    path: str = ""
    pointer: bool = False

    @property
    def known(self) -> bool:
        return bool(self.path)


UNKNOWN = GoType("")


@dataclass
class FuncSig:
    name: str                                   # "F", or "Server.H" for a method
    params: List[Tuple[str, GoType]]            # (name, type); "" if unnamed
    results: List[GoType]
    receiver: Optional[Tuple[str, GoType]] = None
    exported: bool = False


@dataclass
class FileEnv:
    package: str = ""
    imports: Dict[str, str] = field(default_factory=dict)        # local name -> path
    struct_fields: Dict[str, Dict[str, GoType]] = field(default_factory=dict)
    package_vars: Dict[str, GoType] = field(default_factory=dict)
    consts: Dict[str, object] = field(default_factory=dict)      # name -> literal or None
    funcs: Dict[str, FuncSig] = field(default_factory=dict)
    methods: Dict[Tuple[str, str], FuncSig] = field(default_factory=dict)
    local_types: Set[str] = field(default_factory=set)

    def pkg_of(self, alias: str) -> Optional[str]:
        path = self.imports.get(alias)
        return canonical_pkg(path) if path else None


def text(node, src: bytes) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def statements_of(block) -> list:
    """The statements of a block or case body. tree-sitter-go 0.25 wraps them
    in a `statement_list`; older grammars do not."""
    out = []
    if block is None:
        return out
    for child in block.named_children:
        if child.type == "statement_list":
            out.extend(child.named_children)
        else:
            out.append(child)
    return out


def literal_value(node, src: bytes):
    """The Python value of a literal node, or None if it is not a literal."""
    if node is None:
        return None
    t = node.type
    raw = text(node, src)
    if t == "interpreted_string_literal":
        body = raw[1:-1]
        try:
            return codecs.decode(body, "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return body
    if t == "raw_string_literal":
        return raw[1:-1]
    if t == "rune_literal":
        return raw[1:-1]
    if t == "int_literal":
        try:
            return int(raw.replace("_", ""), 0)
        except ValueError:
            return None
    if t == "true":
        return True
    if t == "false":
        return False
    return None


def type_of(node, src: bytes, imports: Dict[str, str]) -> GoType:
    if node is None:
        return UNKNOWN
    t = node.type
    if t == "pointer_type":
        inner = type_of(node.named_children[0], src, imports) if node.named_children else UNKNOWN
        return GoType(inner.path, True) if inner.known else UNKNOWN
    if t == "qualified_type":
        pkg = node.child_by_field_name("package")
        name = node.child_by_field_name("name")
        path = imports.get(text(pkg, src))
        if path is None or name is None:
            return UNKNOWN
        return GoType(f"{canonical_pkg(path)}.{text(name, src)}")
    if t == "type_identifier":
        return GoType(text(node, src))
    if t == "generic_type":
        base = node.child_by_field_name("type")
        if base is None and node.named_children:
            base = node.named_children[0]
        return type_of(base, src, imports)
    if t == "parenthesized_type":
        return type_of(node.named_children[0], src, imports) if node.named_children else UNKNOWN
    if t in ("slice_type", "array_type", "map_type", "channel_type",
             "function_type", "struct_type", "interface_type"):
        return GoType(text(node, src))
    return UNKNOWN


def params_of(plist, src: bytes, imports: Dict[str, str]) -> List[Tuple[str, GoType]]:
    out: List[Tuple[str, GoType]] = []
    if plist is None:
        return out
    for p in plist.named_children:
        if p.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        typ = type_of(p.child_by_field_name("type"), src, imports)
        if p.type == "variadic_parameter_declaration":
            typ = GoType(f"[]{typ.path}") if typ.known else UNKNOWN
        names = p.children_by_field_name("name")
        if names:
            out.extend((text(n, src), typ) for n in names)
        else:
            out.append(("", typ))
    return out


def _descendants(node, node_type: str):
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == node_type:
            yield n
            continue
        stack.extend(reversed(n.named_children))


def _struct_fields(struct_node, src, imports) -> Dict[str, GoType]:
    fields: Dict[str, GoType] = {}
    for decl in _descendants(struct_node, "field_declaration"):
        typ = type_of(decl.child_by_field_name("type"), src, imports)
        names = decl.children_by_field_name("name")
        if names:
            for n in names:
                fields[text(n, src)] = typ
        elif typ.known:                       # embedded field: named by its type
            fields[typ.path.rsplit(".", 1)[-1]] = typ
    return fields


def _sig(node, src, imports, receiver) -> FuncSig:
    base = text(node.child_by_field_name("name"), src)
    params = params_of(node.child_by_field_name("parameters"), src, imports)
    result = node.child_by_field_name("result")
    if result is None:
        results: List[GoType] = []
    elif result.type == "parameter_list":
        results = [t for _, t in params_of(result, src, imports)]
    else:
        results = [type_of(result, src, imports)]
    name = f"{receiver[1].path}.{base}" if receiver else base
    return FuncSig(name=name, params=params, results=results, receiver=receiver,
                   exported=base[:1].isupper())


def build_file_env(root, src: bytes) -> FileEnv:
    env = FileEnv()
    for node in root.named_children:
        if node.type == "package_clause" and node.named_children:
            env.package = text(node.named_children[0], src)
        elif node.type == "import_declaration":
            for spec in _descendants(node, "import_spec"):
                path_node = spec.child_by_field_name("path")
                if path_node is None:
                    continue
                path = text(path_node, src).strip('"`')
                name_node = spec.child_by_field_name("name")
                if name_node is None:
                    env.imports[default_package_name(path)] = path
                elif name_node.type == "package_identifier":
                    env.imports[text(name_node, src)] = path
                # "_" and "." imports bind no usable name.
    for node in root.named_children:
        t = node.type
        if t == "type_declaration":
            for spec in node.named_children:
                if spec.type not in ("type_spec", "type_alias"):
                    continue
                name = text(spec.child_by_field_name("name"), src)
                env.local_types.add(name)
                body = spec.child_by_field_name("type")
                if body is not None and body.type == "struct_type":
                    env.struct_fields[name] = _struct_fields(body, src, env.imports)
        elif t == "var_declaration":
            for spec in _descendants(node, "var_spec"):
                typ = type_of(spec.child_by_field_name("type"), src, env.imports)
                for n in spec.children_by_field_name("name"):
                    env.package_vars[text(n, src)] = typ
        elif t == "const_declaration":
            for spec in _descendants(node, "const_spec"):
                values = spec.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, n in enumerate(spec.children_by_field_name("name")):
                    env.consts[text(n, src)] = literal_value(vals[i], src) if i < len(vals) else None
        elif t == "function_declaration":
            sig = _sig(node, src, env.imports, receiver=None)
            env.funcs[sig.name] = sig
        elif t == "method_declaration":
            recv = params_of(node.child_by_field_name("receiver"), src, env.imports)
            if not recv or not recv[0][1].known:
                continue
            sig = _sig(node, src, env.imports, receiver=recv[0])
            env.methods[(recv[0][1].path, sig.name.split(".", 1)[1])] = sig
    return env


class Scope:
    """Lexical scope for locals. A name declared in any enclosing function
    scope shadows package-level names and import aliases."""

    def __init__(self, parent: Optional["Scope"] = None):
        self.parent = parent
        self.names: Dict[str, GoType] = {}

    def declare(self, name: str, typ: GoType = UNKNOWN) -> None:
        if name and name != "_":
            self.names[name] = typ

    def lookup(self, name: str) -> Optional[GoType]:
        scope = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None

    def child(self) -> "Scope":
        return Scope(self)
```

- [ ] **Step 5: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_env.py -v`
Expected: all 6 PASS. If `test_signatures_and_methods` fails on the generic receiver, dump the receiver node with `print(root.sexp())` (or walk `named_children`) and adjust `type_of`'s `generic_type` branch to the field name the grammar uses; the assertion is the contract.

- [ ] **Step 6: Commit**

```bash
git add requirements.txt pyproject.toml frame/sil/frontends/_go_env.py tests/test_go_env.py
git commit -m "Go frontend: per-file import and syntactic type environment

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---
### Task 3: Go spec and lowering-hint tables

All data, no lowering. Keys are canonical: `<pkg path>.<Func>` for package functions and `<pkg path>.<Type>.<Method>` for methods (pointer-ness dropped). The frontend (Task 4) turns a resolved key into a registered site name.

**Files:**
- Create: `frame/sil/specs/go_specs.py`
- Modify: `frame/sil/specs/__init__.py`
- Test: `tests/test_go_specs.py`

**Interfaces:**
- Produces (module `frame.sil.specs.go_specs`):
  - `GO_SPECS: Dict[str, ProcSpec]`
  - `CONST_ARG0_EXEMPT: FrozenSet[str]` — sink only when arg 0 is not a constant string (gorm `Where`/`Order`/`Group`)
  - `SHELL_COMMAND_KEYS: Dict[str, int]` — key → index of the program-name argument; `SHELL_NAMES`, `SHELL_FLAGS: FrozenSet[str]`
  - `OUT_PARAMS: Dict[str, Tuple[int, ...]]`, `RECEIVER_MUTATION: FrozenSet[str]`
  - `NON_PROPAGATING_CALLS: FrozenSet[str]`, `NON_PROPAGATING_FIELDS: FrozenSet[str]`
  - `RESULT_TYPES: Dict[str, str]`, `FIELD_TYPES: Dict[str, str]`
  - `REQUEST_TYPE`, `RESPONSE_WRITER: str`; `SERVER_CONTEXT_TYPES`, `LIBRARY_PARAM_TYPES: FrozenSet[str]`
  - `HANDLER_REGISTRAR_FUNCS`, `HANDLER_REGISTRAR_METHODS: FrozenSet[str]`
  - `NORETURN: Dict[str, bool]` — key → whether deferred calls run first
  - `NORMALIZING_KEYS: FrozenSet[str]`, `TRUSTED_PURE_CALLS: FrozenSet[str]`, `EMPTY_BUILTINS: FrozenSet[str]`
  - `INJECTION_KINDS: List[str]`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_go_specs.py`:

```python
"""Go spec tables: the sink/sanitizer contract from the design spec."""

from frame.sil.specs.go_specs import (
    GO_SPECS, CONST_ARG0_EXEMPT, OUT_PARAMS, RECEIVER_MUTATION, NORETURN,
    NON_PROPAGATING_CALLS, NON_PROPAGATING_FIELDS, RESULT_TYPES, FIELD_TYPES,
)


def _sink(key):
    spec = GO_SPECS[key]
    return spec.is_sink, spec.sink_args


def test_sql_sinks_only_the_query_argument():
    assert _sink("database/sql.DB.Query") == ("sql", [0])
    assert _sink("database/sql.Tx.ExecContext") == ("sql", [1])
    assert _sink("github.com/jmoiron/sqlx.DB.Select") == ("sql", [1])
    assert _sink("gorm.io/gorm.DB.Raw") == ("sql", [0])
    assert "gorm.io/gorm.DB.Where" in CONST_ARG0_EXEMPT


def test_other_sink_rows():
    assert _sink("os/exec.Command") == ("shell", [0])
    assert _sink("os/exec.CommandContext") == ("shell", [1])
    assert _sink("os.Open") == ("filesystem", [0])
    assert _sink("net/http.ServeFile") == ("filesystem", [2])
    assert _sink("net/http.Redirect") == ("redirect", [2])
    assert _sink("github.com/gin-gonic/gin.Context.Redirect") == ("redirect", [1])
    assert _sink("net/http.NewRequestWithContext") == ("ssrf", [2])
    assert _sink("net/http.Client.Get") == ("ssrf", [0])
    assert _sink("html/template.HTML") == ("html", [0])
    assert _sink("strings.Repeat") == ("alloc_size", [1])


def test_excluded_apis_are_not_sinks():
    for key in ("html/template.JS", "html/template.URL", "html/template.CSS",
                "html/template.HTMLAttr", "os.Root.Open", "net/url.QueryEscape",
                "os.Getenv"):
        spec = GO_SPECS.get(key)
        assert spec is None or not spec.is_sink, key


def test_sanitizers():
    atoi = GO_SPECS["strconv.Atoi"]
    assert "alloc_size" not in atoi.is_sanitizer
    assert {"sql", "shell", "filesystem", "redirect", "ssrf", "html"} <= set(atoi.is_sanitizer)
    assert GO_SPECS["path/filepath.Base"].is_sanitizer == ["filesystem"]
    assert GO_SPECS["html.EscapeString"].is_sanitizer == ["html"]
    assert "path/filepath.Clean" not in GO_SPECS          # not a sanitizer alone
    assert "net/url.QueryEscape" not in GO_SPECS          # not a destination check


def test_hint_tables():
    assert OUT_PARAMS["encoding/json.Unmarshal"] == (1,)
    assert OUT_PARAMS["encoding/json.Decoder.Decode"] == (0,)
    assert "strings.Builder.WriteString" in RECEIVER_MUTATION
    assert "net/http.Request.Context" in NON_PROPAGATING_CALLS
    assert "github.com/gin-gonic/gin.Context.GetString" in NON_PROPAGATING_CALLS
    assert "net/http.Request.Method" in NON_PROPAGATING_FIELDS
    assert NORETURN["os.Exit"] is False and NORETURN["panic"] is True
    assert RESULT_TYPES["database/sql.Open"] == "database/sql.DB"
    assert FIELD_TYPES["net/http.Request.URL"] == "net/url.URL"
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_go_specs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'frame.sil.specs.go_specs'`.

- [ ] **Step 3: Implement `go_specs.py`**

Create `frame/sil/specs/go_specs.py`:

```python
"""Library specifications and lowering hints for the Go frontend.

Keys are canonical: `<package path>.<Func>` or `<package path>.<Type>.<Method>`,
with a major-version suffix dropped and pointer-ness ignored. The frontend
resolves every call to such a key through its import/type environment and
registers the spec under a site-unique name, so nothing here is ever matched by
suffix or method name (see docs/superpowers/specs/2026-09-23-go-frontend-design.md).

Only behaviour that differs from the translator's default is listed. An
unregistered call already propagates taint from its arguments and receiver to
its result, so plain propagators (fmt.Sprintf, strings.Join, ...) need no entry.
"""

from typing import Dict, FrozenSet, List, Tuple

from frame.sil.procedure import ProcSpec

SQL = "sql"
SHELL = "shell"
FS = "filesystem"
REDIRECT = "redirect"
SSRF = "ssrf"
HTML = "html"
ALLOC = "alloc_size"
INJECTION_KINDS: List[str] = [SQL, SHELL, FS, REDIRECT, SSRF, HTML]


def _sink(kind: str, args, desc: str, propagates=()) -> ProcSpec:
    return ProcSpec(is_sink=kind, sink_args=list(args),
                    taint_propagates=list(propagates), description=desc)


def _sanitizer(kinds, desc: str, propagates=(0,)) -> ProcSpec:
    return ProcSpec(is_sanitizer=list(kinds), taint_propagates=list(propagates),
                    description=desc)


GO_SPECS: Dict[str, ProcSpec] = {}

# --- CWE-89 SQL ---------------------------------------------------------------
_SQL_RECEIVERS = (
    "database/sql.DB", "database/sql.Tx", "database/sql.Conn",
    "github.com/jmoiron/sqlx.DB", "github.com/jmoiron/sqlx.Tx",
)
for _recv in _SQL_RECEIVERS:
    for _m in ("Query", "QueryRow", "Exec", "Prepare"):
        GO_SPECS[f"{_recv}.{_m}"] = _sink(SQL, [0], f"{_recv}.{_m}(query)")
        GO_SPECS[f"{_recv}.{_m}Context"] = _sink(SQL, [1], f"{_recv}.{_m}Context(ctx, query)")
for _recv in ("github.com/jmoiron/sqlx.DB", "github.com/jmoiron/sqlx.Tx"):
    for _m in ("Select", "Get"):
        GO_SPECS[f"{_recv}.{_m}"] = _sink(SQL, [1], f"sqlx {_m}(dest, query)")
    for _m in ("Queryx", "QueryRowx", "MustExec"):
        GO_SPECS[f"{_recv}.{_m}"] = _sink(SQL, [0], f"sqlx {_m}(query)")
for _m in ("Raw", "Exec"):
    GO_SPECS[f"gorm.io/gorm.DB.{_m}"] = _sink(SQL, [0], f"gorm {_m}(sql)")
for _m in ("Where", "Order", "Group"):
    # Chained: the result is the *gorm.DB, so taint of the receiver flows on.
    GO_SPECS[f"gorm.io/gorm.DB.{_m}"] = ProcSpec(
        is_sink=SQL, sink_args=[0], taint_from_receiver=True,
        description=f"gorm {_m}(non-constant string)")
CONST_ARG0_EXEMPT: FrozenSet[str] = frozenset(
    f"gorm.io/gorm.DB.{m}" for m in ("Where", "Order", "Group"))

# --- CWE-78 command -------------------------------------------------------------
GO_SPECS["os/exec.Command"] = _sink(SHELL, [0], "exec.Command(name, ...)")
GO_SPECS["os/exec.CommandContext"] = _sink(SHELL, [1], "exec.CommandContext(ctx, name, ...)")
GO_SPECS["syscall.Exec"] = _sink(SHELL, [0], "syscall.Exec(argv0, ...)")
SHELL_COMMAND_KEYS: Dict[str, int] = {"os/exec.Command": 0, "os/exec.CommandContext": 1}
SHELL_NAMES: FrozenSet[str] = frozenset({
    "sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh"})
SHELL_FLAGS: FrozenSet[str] = frozenset({"-c", "/c", "/C", "-Command"})

# --- CWE-22 path ------------------------------------------------------------------
for _f in ("Open", "OpenFile", "Create", "ReadFile", "WriteFile", "Remove",
           "RemoveAll", "Mkdir", "MkdirAll", "Rename", "DirFS"):
    GO_SPECS[f"os.{_f}"] = _sink(FS, [0], f"os.{_f}(path)")
for _f in ("ReadFile", "WriteFile"):
    GO_SPECS[f"io/ioutil.{_f}"] = _sink(FS, [0], f"ioutil.{_f}(path)")
GO_SPECS["net/http.ServeFile"] = _sink(FS, [2], "http.ServeFile(w, r, name)")
GO_SPECS["net/http.Dir"] = _sink(FS, [0], "http.Dir(root)", propagates=[0])

# --- CWE-601 redirect ---------------------------------------------------------------
GO_SPECS["net/http.Redirect"] = _sink(REDIRECT, [2], "http.Redirect(w, r, url, code)")
GO_SPECS["github.com/gin-gonic/gin.Context.Redirect"] = _sink(REDIRECT, [1], "gin c.Redirect(code, url)")
GO_SPECS["github.com/labstack/echo.Context.Redirect"] = _sink(REDIRECT, [1], "echo c.Redirect(code, url)")

# --- CWE-918 SSRF -----------------------------------------------------------------------
for _f in ("Get", "Head", "Post", "PostForm"):
    GO_SPECS[f"net/http.{_f}"] = _sink(SSRF, [0], f"http.{_f}(url)")
    if _f != "PostForm":
        GO_SPECS[f"net/http.Client.{_f}"] = _sink(SSRF, [0], f"client.{_f}(url)")
GO_SPECS["net/http.NewRequest"] = _sink(SSRF, [1], "http.NewRequest(method, url, body)", propagates=[1])
GO_SPECS["net/http.NewRequestWithContext"] = _sink(
    SSRF, [2], "http.NewRequestWithContext(ctx, method, url, body)", propagates=[2])

# --- CWE-79 (explicit escape bypass only) ---------------------------------------------------
GO_SPECS["html/template.HTML"] = _sink(HTML, [0], "template.HTML(x) marks x trusted", propagates=[0])

# --- CWE-770 ------------------------------------------------------------------------------------
GO_SPECS["strings.Repeat"] = _sink(ALLOC, [1], "strings.Repeat(s, count)", propagates=[0])
GO_SPECS["bytes.Repeat"] = _sink(ALLOC, [1], "bytes.Repeat(b, count)", propagates=[0])
MAKE_SLICE_SPEC = ProcSpec(is_sink=ALLOC, sink_args=[1, 2], description="make([]T, len, cap)")

# --- Sanitizers --------------------------------------------------------------------------------------
GO_SPECS["path/filepath.Base"] = _sanitizer([FS], "filepath.Base")
GO_SPECS["path.Base"] = _sanitizer([FS], "path.Base")
GO_SPECS["github.com/cyphar/filepath-securejoin.SecureJoin"] = _sanitizer(
    [FS], "securejoin.SecureJoin(root, unsafe)", propagates=(0, 1))
GO_SPECS["html.EscapeString"] = _sanitizer([HTML], "html.EscapeString")
GO_SPECS["html/template.HTMLEscapeString"] = _sanitizer([HTML], "template.HTMLEscapeString")
GO_SPECS["text/template.HTMLEscapeString"] = _sanitizer([HTML], "template.HTMLEscapeString")
for _f in ("Atoi", "ParseInt", "ParseUint", "ParseBool", "ParseFloat"):
    # Clean for string injection, still tainted for ALLOC_SIZE: the number is
    # exactly what an unbounded allocation is made of.
    GO_SPECS[f"strconv.{_f}"] = _sanitizer(INJECTION_KINDS, f"strconv.{_f}")

# --- Lowering hints --------------------------------------------------------------------------------------
OUT_PARAMS: Dict[str, Tuple[int, ...]] = {
    "encoding/json.Unmarshal": (1,),
    "encoding/xml.Unmarshal": (1,),
    "encoding/json.Decoder.Decode": (0,),
    "encoding/xml.Decoder.Decode": (0,),
    "fmt.Sscanf": tuple(range(2, 12)),
    "fmt.Sscan": tuple(range(1, 12)),
    "fmt.Sscanln": tuple(range(1, 12)),
}
for _m in ("Bind", "BindJSON", "BindQuery", "BindUri", "ShouldBind", "ShouldBindJSON",
           "ShouldBindQuery", "ShouldBindUri", "ShouldBindWith", "BindWith"):
    OUT_PARAMS[f"github.com/gin-gonic/gin.Context.{_m}"] = (0,)
OUT_PARAMS["github.com/labstack/echo.Context.Bind"] = (0,)
OUT_PARAMS["github.com/gofiber/fiber.Ctx.BodyParser"] = (0,)
OUT_PARAMS["github.com/gofiber/fiber.Ctx.QueryParser"] = (0,)

RECEIVER_MUTATION: FrozenSet[str] = frozenset(
    [f"strings.Builder.{m}" for m in ("WriteString", "Write", "WriteByte", "WriteRune")]
    + [f"bytes.Buffer.{m}" for m in ("WriteString", "Write", "WriteByte", "WriteRune")]
    + ["net/url.Values.Set", "net/url.Values.Add"])

NON_PROPAGATING_CALLS: FrozenSet[str] = frozenset({
    "net/http.Request.Context",
    "github.com/gin-gonic/gin.Context.Get",
    "github.com/gin-gonic/gin.Context.MustGet",
    "github.com/gin-gonic/gin.Context.GetString",
    "github.com/labstack/echo.Context.Get",
})
NON_PROPAGATING_FIELDS: FrozenSet[str] = frozenset({
    "net/http.Request.Method", "net/http.Request.TLS",
})

RESULT_TYPES: Dict[str, str] = {
    "database/sql.Open": "database/sql.DB",
    "database/sql.OpenDB": "database/sql.DB",
    "database/sql.DB.Begin": "database/sql.Tx",
    "database/sql.DB.BeginTx": "database/sql.Tx",
    "database/sql.DB.Conn": "database/sql.Conn",
    "github.com/jmoiron/sqlx.Open": "github.com/jmoiron/sqlx.DB",
    "github.com/jmoiron/sqlx.Connect": "github.com/jmoiron/sqlx.DB",
    "github.com/jmoiron/sqlx.MustConnect": "github.com/jmoiron/sqlx.DB",
    "github.com/jmoiron/sqlx.MustOpen": "github.com/jmoiron/sqlx.DB",
    "github.com/jmoiron/sqlx.NewDb": "github.com/jmoiron/sqlx.DB",
    "github.com/jmoiron/sqlx.DB.Beginx": "github.com/jmoiron/sqlx.Tx",
    "github.com/jmoiron/sqlx.DB.MustBegin": "github.com/jmoiron/sqlx.Tx",
    "gorm.io/gorm.Open": "gorm.io/gorm.DB",
    "net/http.NewRequest": "net/http.Request",
    "net/http.NewRequestWithContext": "net/http.Request",
    "net/url.Parse": "net/url.URL",
    "net/url.ParseRequestURI": "net/url.URL",
    "net/url.URL.Query": "net/url.Values",
    "encoding/json.NewDecoder": "encoding/json.Decoder",
    "encoding/xml.NewDecoder": "encoding/xml.Decoder",
    "github.com/gorilla/mux.NewRouter": "github.com/gorilla/mux.Router",
    "net/http.NewServeMux": "net/http.ServeMux",
    "github.com/go-chi/chi.NewRouter": "github.com/go-chi/chi.Mux",
    "github.com/gin-gonic/gin.Default": "github.com/gin-gonic/gin.Engine",
    "github.com/gin-gonic/gin.New": "github.com/gin-gonic/gin.Engine",
    "github.com/labstack/echo.New": "github.com/labstack/echo.Echo",
    "github.com/labstack/echo.Context.Request": "net/http.Request",
}
for _m in ("Where", "Order", "Group", "Model", "Table", "Raw", "Joins", "Select",
           "Session", "WithContext", "Debug", "Limit", "Offset", "Preload"):
    RESULT_TYPES[f"gorm.io/gorm.DB.{_m}"] = "gorm.io/gorm.DB"

FIELD_TYPES: Dict[str, str] = {
    "net/http.Request.URL": "net/url.URL",
    "net/http.Request.Header": "net/http.Header",
    "net/http.Request.Form": "net/url.Values",
    "net/http.Request.PostForm": "net/url.Values",
    "github.com/gin-gonic/gin.Context.Request": "net/http.Request",
}

# --- Sources and handler shape ------------------------------------------------------------------------------
REQUEST_TYPE = "net/http.Request"
RESPONSE_WRITER = "net/http.ResponseWriter"
SERVER_CONTEXT_TYPES: FrozenSet[str] = frozenset({
    "github.com/gin-gonic/gin.Context",
    "github.com/labstack/echo.Context",
    "github.com/gofiber/fiber.Ctx",
})
LIBRARY_PARAM_TYPES: FrozenSet[str] = frozenset({"string", "[]byte", "io.Reader"})
HANDLER_REGISTRAR_FUNCS: FrozenSet[str] = frozenset({
    "net/http.HandleFunc", "net/http.Handle", "net/http.HandlerFunc"})
HANDLER_REGISTRAR_METHODS: FrozenSet[str] = frozenset({
    "HandleFunc", "Handle", "Get", "Post", "Put", "Delete", "Patch", "Head", "Options",
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "Any", "Method",
    "MethodFunc", "Connect", "Trace"})

# --- Termination, normalisation, trust ------------------------------------------------------------------------
# Value: whether Go runs deferred calls before the path ends.
NORETURN: Dict[str, bool] = {
    "panic": True, "runtime.Goexit": True,
    "os.Exit": False,
    "log.Fatal": False, "log.Fatalf": False, "log.Fatalln": False,
    "log.Panic": True, "log.Panicf": True, "log.Panicln": True,
}
NORMALIZING_KEYS: FrozenSet[str] = frozenset({
    "path/filepath.Clean", "path/filepath.Abs", "path/filepath.Join",
    "path.Clean", "path.Join"})
TRUSTED_PURE_CALLS: FrozenSet[str] = frozenset({
    "path/filepath.Join", "path/filepath.Clean", "path/filepath.Abs",
    "path.Join", "path.Clean", "strings.TrimSuffix", "strings.TrimPrefix",
    "os.Getenv", "os.TempDir", "os.UserHomeDir", "os.Getwd"})
# Builtins whose result carries no taint (len/cap: see spec, CWE-770 FP).
EMPTY_BUILTINS: FrozenSet[str] = frozenset({
    "len", "cap", "new", "recover", "print", "println", "delete", "close",
    "clear", "complex", "real", "imag"})
```

In `frame/sil/specs/__init__.py`, after the C# block add:

```python
# Go specs
try:
    from frame.sil.specs.go_specs import GO_SPECS
except ImportError:
    GO_SPECS = {}
```

and add `"GO_SPECS",` to `__all__`.

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_specs.py -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add frame/sil/specs/go_specs.py frame/sil/specs/__init__.py tests/test_go_specs.py
git commit -m "Go frontend: spec and lowering-hint tables

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Core Go frontend (procedures, statements, calls, sources)

The frontend proper: lowers every function, method and function literal to a `Procedure`, resolves and registers calls under site-unique names, emits handler-shaped sources, and handles control flow, `defer`/`go`, and structural termination. Summaries (Task 5) and guard sanitization (Task 6) plug into hooks created here.

**Files:**
- Create: `frame/sil/frontends/go_frontend.py`
- Modify: `frame/sil/frontends/__init__.py`
- Modify: `frame/sil/scanner.py` (`_get_frontend`, ~line 712)
- Test: `tests/test_go_frontend.py`, `tests/test_go_taint.py`

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces:
  - `GoFrontend(specs: Optional[Dict[str, ProcSpec]] = None)` with attribute `taint_exported_params: bool` and `translate(source_code: str, filename: str = "<unknown>") -> Program`.
  - `GoFrontend._site_callees: Dict[str, str]` — emitted call name → same-file procedure name (consumed by Task 5).
  - Hook methods Tasks 5–6 replace (no-ops here): `_before_lowering(self, root)`, `_after_lowering(self)` (Task 5), `_on_branch(self, cond_node, truth: bool, node: Node)`, `_on_assign(self, name: str, value_node)`, `_on_multi_assign(self, names: List[str], value_node)`, `_on_function_start(self, node, receiver_name: str, param_names: Set[str])`, `_on_function_end(self)`, `_facts_snapshot(self)`, `_facts_restore(self, snap)`, `_facts_join(self, snaps: list)`, `_facts_clear(self)`, `_adjust_site_spec(self, key, spec, arg_nodes, arg_exps) -> Optional[ProcSpec]` (Task 6 extends; must return `spec` itself when unchanged, because identity decides whether a site variant name is used).
  - Helpers later tasks call: `_call_key(node) -> Optional[str]`, `_const_str(node) -> Optional[str]`, `_arg_nodes(call) -> list`, `_t(node) -> str`, `_loc(node) -> Location`, `_is_package_alias(node) -> bool`, `_type_of(node) -> GoType`.
  - `tests/test_go_taint.py` helper `_cwes(src, **kw) -> Set[str]` used by Tasks 5–8.

- [ ] **Step 1: Write the failing lowering tests**

Create `tests/test_go_frontend.py`:

```python
"""Lowering unit tests for the Go frontend (Go -> SIL)."""

from frame.sil.frontends.go_frontend import GoFrontend
from frame.sil.instructions import Call, TaintSource, Return
from frame.sil.procedure import NodeKind


def _prog(src: str, **kw):
    fe = GoFrontend()
    for k, v in kw.items():
        setattr(fe, k, v)
    return fe.translate(src, "t.go")


def _calls(proc):
    return [i for n in proc.nodes.values() for i in n.instrs if isinstance(i, Call)]


def _names(proc):
    return [c.get_full_name() for c in _calls(proc)]


HANDLER = '''package main

import (
	"database/sql"
	"net/http"
	osexec "os/exec"
)

var db *sql.DB

type Server struct{ db *sql.DB }

func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM t WHERE id = " + id)
	osexec.Command(id)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func client(req *http.Request) {}
'''


def test_procedure_names_use_go_namespace():
    p = _prog(HANDLER)
    assert {"go:h", "go:Server.ServeHTTP", "go:client"} <= set(p.procedures)
    assert p.language == "go" and p.exact_spec_lookup


def test_resolved_method_call_uses_site_unique_receiver():
    p = _prog(HANDLER)
    names = _names(p.procedures["go:h"])
    sql = [n for n in names if n.endswith(".Query") and n.startswith("$r_")]
    assert len(sql) == 1
    assert p.library_specs[sql[0]].is_sink == "sql"


def test_resolved_package_function_uses_canonical_name():
    p = _prog(HANDLER)
    assert "go:os/exec.Command" in _names(p.procedures["go:h"])
    assert p.library_specs["go:os/exec.Command"].is_sink == "shell"


def test_unresolved_calls_are_never_registered():
    p = _prog(HANDLER)
    for name in _names(p.procedures["go:h"]):
        if not (name.startswith("$r_") or name.startswith("go:")):
            assert name not in p.library_specs, name


def test_handler_shaped_request_is_a_source_client_request_is_not():
    p = _prog(HANDLER)

    def sources(pname):
        return [i for n in p.procedures[pname].nodes.values() for i in n.instrs
                if isinstance(i, TaintSource)]
    assert [s.var.name for s in sources("go:h")] == ["r"]
    assert [s.var.name for s in sources("go:Server.ServeHTTP")] == ["r"]
    assert sources("go:client") == []


def test_func_literal_is_its_own_procedure():
    src = '''package main
import "net/http"
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
}'''
    p = _prog(src)
    assert "go:main$func1" in p.procedures
    lit = p.procedures["go:main$func1"]
    assert any(isinstance(i, TaintSource) for n in lit.nodes.values() for i in n.instrs)


def test_multi_value_error_slot_is_untainted():
    src = '''package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	v, err := parse(r)
	_ = v
	_ = err
}
func parse(r *http.Request) (string, error) { return r.FormValue("a"), nil }'''
    p = _prog(src)
    assigns = {str(i.id): i for n in p.procedures["go:h"].nodes.values()
               for i in n.instrs if type(i).__name__ == "Assign"}
    assert "go:opaque" in str(assigns["err"].exp) or str(assigns["err"].exp).startswith("$o_")


def test_defer_runs_at_exit_after_return_operands():
    src = '''package main
import "os"
func f(p string) string {
	defer os.Remove(p)
	return p
}'''
    p = _prog(src)
    proc = p.procedures["go:f"]
    order = [type(i).__name__ + ":" + (i.get_full_name() if isinstance(i, Call) else "")
             for n in sorted(proc.nodes.values(), key=lambda n: n.id) for i in n.instrs]
    remove_at = max(i for i, s in enumerate(order) if s.endswith("go:os.Remove"))
    return_at = max(i for i, s in enumerate(order) if s.startswith("Return"))
    assert remove_at < return_at


def test_os_exit_ends_the_path():
    src = '''package main
import "os"
func f() {
	os.Exit(1)
	os.Remove("x")
}'''
    proc = _prog(src).procedures["go:f"]
    remove_nodes = [n for n in proc.nodes.values()
                    if any(isinstance(i, Call) and i.get_full_name() == "go:os.Remove"
                           for i in n.instrs)]
    assert all(not n.preds for n in remove_nodes)


def test_if_uses_the_translators_two_way_branch_layout():
    src = '''package main
func f(n int) {
	if n > 10 { g() } else { h() }
}'''
    proc = _prog(src).procedures["go:f"]
    branching = [n for n in proc.nodes.values()
                 if [type(i).__name__ for i in n.instrs].count("Prune") == 2]
    assert len(branching) == 1
    node = branching[0]
    prunes = [i for i in node.instrs if type(i).__name__ == "Prune"]
    assert prunes[0].is_true_branch and not prunes[1].is_true_branch
    assert len(node.succs) == 2


def test_infinite_loop_never_claims_body_cannot_exit():
    src = '''package main
func serve(l Listener) {
	for {
		c := l.Accept()
		go handle(c)
	}
}'''
    proc = _prog(src).procedures["go:serve"]
    heads = [n for n in proc.nodes.values() if n.kind == NodeKind.LOOP_HEAD]
    assert heads and all(n.loop_body_can_exit is None for n in heads)


def test_generic_receiver_method_resolves():
    src = '''package main
type Set[T any] struct{ items []T }
func (s *Set[T]) Add(x T) {}
func use(s *Set[int]) { s.Add(1) }'''
    p = _prog(src)
    assert "go:Set.Add" in p.procedures
    assert p.procedures["go:use"] is not None


def test_deep_nesting_does_not_crash():
    body = "if x {\n" * 400 + "}\n" * 400
    src = f"package main\nfunc f(x bool) {{\n{body}}}\n"
    _prog(src)          # must not raise


def test_syntax_error_keeps_intact_functions():
    src = '''package main
func ok() { g() }
func broken( {
'''
    p = _prog(src)
    assert "go:ok" in p.procedures
```

- [ ] **Step 2: Write the failing end-to-end tests**

Create `tests/test_go_taint.py`:

```python
"""End-to-end Go taint fixtures through FrameScanner(language="go").

Every sink row of the design spec has a vulnerable fixture that must fire and a
patched twin that must stay silent; Tasks 5-7 extend this file.
"""

from frame.sil import FrameScanner


def _cwes(src: str, **kw):
    scanner = FrameScanner(language="go", verify=False, **kw)
    result = scanner.scan(src, "t.go")
    assert not [e for e in result.errors if "Scan error" in e], result.errors
    return {v.cwe_id for v in result.vulnerabilities}


def _handler(body: str, imports: str = '"net/http"', extra: str = "") -> str:
    return (f"package main\n\nimport (\n{imports}\n)\n\n{extra}\n"
            f"func h(w http.ResponseWriter, r *http.Request) {{\n{body}\n}}\n")


def _pair(cwe: str, vulnerable: str, patched: str) -> None:
    """A patched twin proves something only if the same shape without the fix
    fires: otherwise a broken propagation step would make every twin pass."""
    assert cwe in _cwes(vulnerable), "vulnerable counterpart must fire"
    assert cwe not in _cwes(patched), "patched twin must be silent"


SQL_IMPORTS = '"database/sql"\n"net/http"'


def test_sqli_fires():
    src = _handler('id := r.URL.Query().Get("id")\n'
                   'db.Query("SELECT * FROM t WHERE id = " + id)',
                   SQL_IMPORTS, "var db *sql.DB")
    assert "CWE-89" in _cwes(src)


def test_parameterized_query_is_silent():
    _pair("CWE-89",
          _handler('id := r.URL.Query().Get("id")\ndb.Query("SELECT * FROM t WHERE id = " + id)',
                   SQL_IMPORTS, "var db *sql.DB"),
          _handler('id := r.URL.Query().Get("id")\ndb.Query("SELECT * FROM t WHERE id = $1", id)',
                   SQL_IMPORTS, "var db *sql.DB"))


def test_query_on_non_sql_type_is_silent():
    src = _handler('q := r.FormValue("q")\nc.Query(q)',
                   '"net/http"', "type Cache struct{}\nfunc (c *Cache) Query(s string) {}\nvar c *Cache")
    assert "CWE-89" not in _cwes(src)


def test_same_name_call_on_unknown_type_does_not_borrow_sql_spec():
    src = f'''package main
import (
{SQL_IMPORTS}
"example.com/ext"
)
func a(w http.ResponseWriter, r *http.Request, x *sql.DB) {{
	x.Query(r.FormValue("a"))
}}
func b(w http.ResponseWriter, r *http.Request, x *ext.Thing) {{
	x.Query(r.FormValue("b"))
}}
'''
    result = FrameScanner(language="go", verify=False).scan(src, "t.go")
    sqli = [v for v in result.vulnerabilities if v.cwe_id == "CWE-89"]
    assert len(sqli) == 1 and sqli[0].procedure == "go:a"


def test_aliased_exec_fires():
    src = _handler('osexec.Command(r.FormValue("cmd")).Run()',
                   '"net/http"\nosexec "os/exec"')
    assert "CWE-78" in _cwes(src)


def test_shadowed_alias_is_not_a_sink():
    src = _handler('exec := runner{}\nexec.Command(r.FormValue("cmd"))',
                   '"net/http"\n"os/exec"',
                   "type runner struct{}\nfunc (runner) Command(s string) {}\nvar _ = exec.Command")
    assert "CWE-78" not in _cwes(src)


def test_client_side_request_is_not_a_source():
    src = '''package main
import ("net/http"; "os/exec")
type rt struct{}
func (rt) RoundTrip(req *http.Request) (*http.Response, error) {
	exec.Command(req.URL.Path)
	return nil, nil
}'''
    assert "CWE-78" not in _cwes(src)


def test_handler_func_literal_fires():
    src = '''package main
import ("net/http"; "os")
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		os.ReadFile(r.URL.Query().Get("f"))
	})
}'''
    assert "CWE-22" in _cwes(src)


def test_gin_handler_fires():
    src = '''package main
import ("github.com/gin-gonic/gin"; "os/exec")
func h(c *gin.Context) { exec.Command(c.Query("x")) }'''
    assert "CWE-78" in _cwes(src)


def test_json_decode_into_struct_fires():
    src = _handler('var in struct{ Cmd string }\n'
                   'json.NewDecoder(r.Body).Decode(&in)\n'
                   'exec.Command(in.Cmd)',
                   '"encoding/json"\n"net/http"\n"os/exec"')
    assert "CWE-78" in _cwes(src)


def test_defer_os_exit_does_not_hide_later_sink():
    src = _handler('defer os.Exit(0)\nexec.Command(r.FormValue("c")).Run()',
                   '"net/http"\n"os"\n"os/exec"')
    assert "CWE-78" in _cwes(src)


def test_go_os_exit_does_not_end_caller():
    src = _handler('go os.Exit(0)\nexec.Command(r.FormValue("c")).Run()',
                   '"net/http"\n"os"\n"os/exec"')
    assert "CWE-78" in _cwes(src)


def test_guarded_exit_still_ends_that_path():
    src = _handler('c := r.FormValue("c")\nif c != "" { os.Exit(1) }\nexec.Command(c)',
                   '"net/http"\n"os"\n"os/exec"')
    # The sink is reachable on the c == "" path; this only pins that lowering
    # an exit inside a branch does not crash or cut the join.
    assert isinstance(_cwes(src), set)


def test_len_is_untainted_for_make():
    imports = '"io"\n"net/http"\n"strconv"'
    _pair("CWE-770",
          _handler('body, _ := io.ReadAll(r.Body)\nn, _ := strconv.Atoi(string(body))\n'
                   'buf := make([]byte, n)\n_ = buf', imports),
          _handler('body, _ := io.ReadAll(r.Body)\nbuf := make([]byte, len(body))\n_ = buf', imports))


def test_tainted_make_size_fires():
    src = _handler('n, _ := strconv.Atoi(r.FormValue("n"))\nbuf := make([]byte, n)\n_ = buf',
                   '"net/http"\n"strconv"')
    assert "CWE-770" in _cwes(src)


def test_atoi_before_sql_is_silent():
    imports = '"database/sql"\n"fmt"\n"net/http"\n"strconv"'
    _pair("CWE-89",
          _handler('n := r.FormValue("n")\ndb.Query(fmt.Sprintf("SELECT * FROM t LIMIT %s", n))',
                   imports, "var db *sql.DB"),
          _handler('n, _ := strconv.Atoi(r.FormValue("n"))\n'
                   'db.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n))', imports, "var db *sql.DB"))


def test_env_and_args_are_not_sources():
    src = '''package main
import "os"
func main() { os.Open(os.Args[1]); os.ReadFile(os.Getenv("F")) }'''
    assert "CWE-22" not in _cwes(src)
```

- [ ] **Step 3: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_go_frontend.py tests/test_go_taint.py -q`
Expected: collection error / FAIL with `ModuleNotFoundError: No module named 'frame.sil.frontends.go_frontend'`.

- [ ] **Step 4: Implement `go_frontend.py`**

Create `frame/sil/frontends/go_frontend.py`:

```python
"""
Go to Frame SIL frontend.

Lowers Go (parsed by tree-sitter-go) to SIL for the shared SILTranslator. The
Go-specific parts, all syntactic (docs/superpowers/specs/2026-09-23-go-frontend-design.md):

* call resolution through a per-file import/type environment, with every
  resolved call registered under a site-unique (`$r_N.M`) or canonical
  (`go:pkg.F`) name and the program in exact-lookup mode, so no call can borrow
  another's spec;
* function literals as their own procedures (`Outer$funcN`);
* multi-value results with an untainted error slot;
* immediate / deferred / asynchronous calls kept apart, and path termination
  owned here rather than by the translator's C no-return list;
* sources rooted only in handler-shaped functions.
"""

import sys
from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

try:
    import tree_sitter_go as tsgo
    from tree_sitter import Language, Parser
    TREE_SITTER_GO_AVAILABLE = True
except ImportError:
    TREE_SITTER_GO_AVAILABLE = False

from frame.sil.types import (
    Ident, PVar, Typ, Location, Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess,
)
from frame.sil.instructions import (
    Call, Assign, Prune, Return, TaintSource, TaintKind, PruneKind,
)
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
from frame.sil.frontends._go_env import (
    GoType, UNKNOWN, BUILTIN_TYPES, FileEnv, Scope, build_file_env,
    literal_value, params_of, statements_of, text as node_text, type_of,
)
from frame.sil.specs.go_specs import (
    GO_SPECS, CONST_ARG0_EXEMPT, EMPTY_BUILTINS, FIELD_TYPES,
    HANDLER_REGISTRAR_FUNCS, HANDLER_REGISTRAR_METHODS, LIBRARY_PARAM_TYPES,
    MAKE_SLICE_SPEC, NON_PROPAGATING_CALLS, NON_PROPAGATING_FIELDS, NORETURN,
    OUT_PARAMS, RECEIVER_MUTATION, REQUEST_TYPE, RESPONSE_WRITER, RESULT_TYPES,
    SERVER_CONTEXT_TYPES, SHELL_COMMAND_KEYS, SHELL_FLAGS, SHELL_NAMES,
)

_EMPTY = ProcSpec(description="Go: result carries no taint")
_STRING_LITERALS = ("interpreted_string_literal", "raw_string_literal")


def _same(a, b) -> bool:
    """tree-sitter returns a fresh wrapper per access, so `is` is always False;
    nodes compare equal with ==."""
    return a is not None and b is not None and a == b


class _Breakable:
    def __init__(self, break_to: Node, continue_to: Optional[Node], label: Optional[str]):
        self.break_to = break_to
        self.continue_to = continue_to      # None for switch/select
        self.label = label


class GoFrontend:
    """Translates Go source code to Frame SIL."""

    def __init__(self, specs: Optional[Dict[str, ProcSpec]] = None):
        if not TREE_SITTER_GO_AVAILABLE:
            raise ImportError("tree-sitter-go is required. "
                              "Install with: pip install tree-sitter-go")
        self.parser = Parser(Language(tsgo.language()))
        self.specs = specs or GO_SPECS
        # Set by FrameScanner in library_mode: exported functions' string /
        # []byte / io.Reader parameters are attacker-controlled.
        self.taint_exported_params = False

    # ------------------------------------------------------------------ driver
    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        self._src = source_code.encode("utf-8", errors="replace")
        self._filename = filename
        root = self.parser.parse(self._src).root_node
        self._env: FileEnv = build_file_env(root, self._src)
        self._program = Program(language="go", exact_spec_lookup=True)
        self._program.source_files.append(filename)
        self._ident_counter = 0
        self._variant_counter = 0
        self._literal_names: Dict[int, str] = {}
        self._literal_counts: Dict[str, int] = {}
        self._site_callees: Dict[str, str] = {}
        self._handler_nodes: Set[int] = set()
        self._handler_funcs: Set[str] = set()
        self._handler_method_names: Set[str] = set()
        self._proc: Optional[Procedure] = None
        self._node: Optional[Node] = None
        self._last_call_key: Optional[str] = None
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, 20000))
        try:
            self._collect_handler_registrations(root)
            self._before_lowering(root)
            self._lower_package_init(root)
            for node in root.named_children:
                if node.type in ("function_declaration", "method_declaration"):
                    try:
                        self._lower_function(node)
                    except RecursionError:
                        continue          # pathological nesting: skip this function
            self._after_lowering()
        finally:
            sys.setrecursionlimit(old_limit)
        return self._program

    # Hooks replaced by Tasks 5 and 6.
    def _before_lowering(self, root) -> None:
        pass

    def _after_lowering(self) -> None:
        pass

    def _on_branch(self, cond_node, truth: bool, node: Node) -> None:
        pass

    def _on_assign(self, name: str, value_node) -> None:
        pass

    def _on_multi_assign(self, names: List[str], value_node) -> None:
        pass

    def _on_function_start(self, node, receiver_name: str, param_names: Set[str]) -> None:
        pass

    def _on_function_end(self) -> None:
        pass

    def _facts_snapshot(self):
        return None

    def _facts_restore(self, snap) -> None:
        pass

    def _facts_join(self, snaps) -> None:
        pass

    def _facts_clear(self) -> None:
        pass

    def _adjust_site_spec(self, key: str, spec: Optional[ProcSpec], arg_nodes, arg_exps):
        return self._base_adjust_site_spec(key, spec, arg_nodes)

    # ---------------------------------------------------------------- helpers
    def _t(self, node) -> str:
        return node_text(node, self._src)

    def _loc(self, node) -> Location:
        return Location(file=self._filename, line=node.start_point[0] + 1,
                        column=node.start_point[1])

    def _new_ident(self, prefix: str) -> Ident:
        self._ident_counter += 1
        return Ident(prefix, self._ident_counter)

    def _add(self, instr) -> None:
        if self._node is not None:
            self._node.add_instr(instr)

    def _new_node(self, kind: NodeKind = NodeKind.NORMAL) -> Node:
        node = self._proc.new_node(kind)
        self._proc.add_node(node)
        return node

    def _connect(self, a: Optional[Node], b: Node) -> None:
        if a is not None:
            self._proc.connect(a.id, b.id)

    def _register(self, name: str, spec: ProcSpec) -> None:
        self._program.library_specs[name] = spec

    def _variant(self, name: str) -> str:
        self._variant_counter += 1
        return f"{name}~{self._variant_counter}"

    def _opaque(self, loc: Location) -> Exp:
        """A value that is unknown but carries no taint. Not a constant, so the
        translator's constant folding cannot kill a branch that tests it."""
        ret = self._new_ident("o")
        self._add(Call(loc=loc, ret=(ret, Typ.unknown_type()),
                       func=ExpConst.string("go:opaque"), args=[]))
        self._register("go:opaque", _EMPTY)
        return ExpVar(ret)

    def _materialize(self, exp: Exp, loc: Location, prefix: str = "t") -> str:
        if isinstance(exp, ExpVar):
            return str(exp.var)
        ident = self._new_ident(prefix)
        self._add(Assign(loc=loc, id=ident, exp=exp))
        return str(ident)

    def _site_receiver(self, recv_exp: Exp, loc: Location) -> str:
        ident = self._new_ident("r")
        self._add(Assign(loc=loc, id=ident, exp=recv_exp))
        return str(ident)

    def _const_str(self, node) -> Optional[str]:
        if node is None:
            return None
        if node.type in _STRING_LITERALS:
            value = literal_value(node, self._src)
            return value if isinstance(value, str) else None
        if node.type == "identifier" and self._scope_lookup(self._t(node)) is None:
            value = self._env.consts.get(self._t(node))
            return value if isinstance(value, str) else None
        if node.type == "binary_expression" and self._op(node) == "+":
            left = self._const_str(node.child_by_field_name("left"))
            right = self._const_str(node.child_by_field_name("right"))
            return left + right if left is not None and right is not None else None
        if node.type == "parenthesized_expression" and node.named_children:
            return self._const_str(node.named_children[0])
        return None

    def _op(self, node) -> str:
        op = node.child_by_field_name("operator")
        return self._t(op) if op is not None else ""

    def _scope_lookup(self, name: str) -> Optional[GoType]:
        scope = getattr(self, "_scope", None)
        return scope.lookup(name) if scope is not None else None

    def _is_package_alias(self, node) -> bool:
        return (node is not None and node.type == "identifier"
                and self._scope_lookup(self._t(node)) is None
                and self._env.pkg_of(self._t(node)) is not None)

    @staticmethod
    def _arg_nodes(call) -> list:
        args = call.child_by_field_name("arguments")
        if args is None:
            return []
        return [a for a in args.named_children if a.type != "comment"]

    # --------------------------------------------------------- handler shape
    def _collect_handler_registrations(self, root) -> None:
        """Route registrations name the functions that are request handlers."""
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            args = self._arg_nodes(n)
            if fn is None or fn.type != "selector_expression" or not args:
                continue
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            pkg = self._env.pkg_of(self._t(operand)) if operand is not None and operand.type == "identifier" else None
            by_func = pkg is not None and f"{pkg}.{member}" in HANDLER_REGISTRAR_FUNCS
            by_method = (pkg is None and member in HANDLER_REGISTRAR_METHODS
                         and args[0].type in _STRING_LITERALS)
            if not (by_func or by_method):
                continue
            for arg in args:
                self._mark_handler(arg)

    def _mark_handler(self, arg) -> None:
        if arg.type == "func_literal":
            self._handler_nodes.add(arg.start_byte)
        elif arg.type == "identifier":
            self._handler_funcs.add(self._t(arg))
        elif arg.type == "selector_expression":
            self._handler_method_names.add(self._t(arg.child_by_field_name("field")))
        elif arg.type in ("call_expression", "type_conversion_expression"):
            for inner in self._arg_nodes(arg) if arg.type == "call_expression" else arg.named_children:
                self._mark_handler(inner)

    def _is_handler_shaped(self, node, receiver, params) -> bool:
        if any(t.path == RESPONSE_WRITER for _, t in params):
            return True
        if node.type == "func_literal":
            return node.start_byte in self._handler_nodes
        name = self._t(node.child_by_field_name("name"))
        if node.type == "method_declaration":
            return name == "ServeHTTP" or name in self._handler_method_names
        return name in self._handler_funcs

    # ------------------------------------------------------------- procedures
    def _lower_package_init(self, root) -> None:
        """Package-level var/const values, as Assigns in a synthetic procedure,
        so the literal-secret scan and the trust oracle see them."""
        specs = [s for d in root.named_children if d.type in ("var_declaration", "const_declaration")
                 for s in d.named_children if s.type in ("var_spec", "const_spec")]
        if not specs:
            return
        proc = Procedure(name="go:$package", loc=self._loc(root))
        self._begin_proc(proc, Scope())
        for spec in specs:
            names = spec.children_by_field_name("name")
            values = spec.child_by_field_name("value")
            vals = values.named_children if values is not None else []
            for i, n in enumerate(names):
                if i < len(vals):
                    self._add(Assign(loc=self._loc(n), id=PVar(self._t(n)),
                                     exp=self._lower_expr(vals[i])))
        self._end_proc()

    def _begin_proc(self, proc: Procedure, scope: Scope) -> None:
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        self._proc, self._node, self._exit, self._scope = proc, entry, exit_node, scope
        self._defers: List[tuple] = []
        self._breakables: List[_Breakable] = []
        self._labels: Dict[str, Node] = {}
        self._gotos: List[Tuple[Node, str]] = []
        self._facts_clear()

    def _end_proc(self) -> None:
        if self._node is not None:
            self._emit_defers()
            self._connect(self._node, self._exit)
        for src_node, label in self._gotos:
            target = self._labels.get(label)
            if target is not None:
                self._proc.connect(src_node.id, target.id)
        self._program.add_procedure(self._proc)

    _STATE = ("_proc", "_node", "_exit", "_scope", "_defers", "_breakables",
              "_labels", "_gotos", "_last_call_key")

    def _save(self):
        return {k: getattr(self, k, None) for k in self._STATE} | {"facts": self._facts_snapshot()}

    def _restore(self, saved) -> None:
        for k in self._STATE:
            setattr(self, k, saved[k])
        self._facts_restore(saved["facts"])

    def _lower_function(self, node, name: Optional[str] = None,
                        outer_scope: Optional[Scope] = None) -> str:
        is_method = node.type == "method_declaration"
        params = params_of(node.child_by_field_name("parameters"), self._src, self._env.imports)
        receiver = None
        if is_method:
            recv = params_of(node.child_by_field_name("receiver"), self._src, self._env.imports)
            receiver = recv[0] if recv else ("", UNKNOWN)
        if name is None:
            base = self._t(node.child_by_field_name("name"))
            name = f"go:{receiver[1].path}.{base}" if is_method else f"go:{base}"
        all_params = ([receiver] if receiver else []) + params
        proc = Procedure(
            name=name,
            params=[(PVar(n or f"$p{i}"), Typ.unknown_type()) for i, (n, _) in enumerate(all_params)],
            loc=self._loc(node), is_method=is_method,
            class_name=receiver[1].path if receiver else None)
        saved = self._save()
        self._begin_proc(proc, (outer_scope or Scope()).child())
        for pname, ptype in all_params:
            self._scope.declare(pname, ptype)
        self._on_function_start(node, receiver[0] if receiver else "",
                                {n for n, _ in params if n})
        self._emit_param_sources(node, proc, receiver, params)
        self._lower_block(node.child_by_field_name("body"))
        self._end_proc()
        self._on_function_end()
        self._restore(saved)
        return name

    def _emit_param_sources(self, node, proc, receiver, params) -> None:
        handler = self._is_handler_shaped(node, receiver, params)
        exported = self._is_exported(node)
        for pname, ptype in ([receiver] if receiver else []) + params:
            if not pname:
                continue
            why = None
            if ptype.path in SERVER_CONTEXT_TYPES:
                why = "server request context"
            elif ptype.path == REQUEST_TYPE and handler:
                why = "handler request"
            elif (self.taint_exported_params and exported and (pname, ptype) != receiver
                  and ptype.path in LIBRARY_PARAM_TYPES):
                why = "exported library parameter"
            if why:
                self._add(TaintSource(loc=proc.loc, var=PVar(pname), kind=TaintKind.USER_INPUT,
                                      description=f"Go {why}: {pname}"))

    def _is_exported(self, node) -> bool:
        if node.type == "func_literal":
            return False
        return self._t(node.child_by_field_name("name"))[:1].isupper()

    def _lower_func_literal(self, node) -> str:
        name = self._literal_names.get(node.start_byte)
        if name is None:
            outer = self._proc.name if self._proc is not None else "go:$package"
            k = self._literal_counts.get(outer, 0) + 1
            self._literal_counts[outer] = k
            name = f"{outer}$func{k}"
            self._literal_names[node.start_byte] = name
            self._lower_function(node, name=name, outer_scope=self._scope)
        return name

    # -------------------------------------------------------------- statements
    def _lower_block(self, block) -> None:
        if block is None:
            return
        outer = self._scope
        self._scope = outer.child()
        for stmt in statements_of(block):
            self._lower_stmt(stmt)
        self._scope = outer

    def _lower_stmt(self, node, label: Optional[str] = None) -> None:
        t = node.type
        self._last_call_key = None
        if t == "expression_statement":
            if node.named_children:
                self._lower_expr(node.named_children[0])
                self._maybe_terminate()
        elif t == "short_var_declaration":
            self._lower_assign(node.child_by_field_name("left"),
                               node.child_by_field_name("right"), declare=True)
        elif t == "assignment_statement":
            op = self._op(node)
            if op in ("=", ""):
                self._lower_assign(node.child_by_field_name("left"),
                                   node.child_by_field_name("right"), declare=False)
            else:
                self._lower_compound_assign(node, op[:-1])
        elif t in ("var_declaration", "const_declaration"):
            for spec in node.named_children:
                if spec.type in ("var_spec", "const_spec"):
                    self._lower_var_spec(spec)
        elif t == "return_statement":
            self._lower_return(node)
        elif t == "if_statement":
            self._lower_if(node)
        elif t == "for_statement":
            self._lower_for(node, label)
        elif t in ("expression_switch_statement", "type_switch_statement", "select_statement"):
            self._lower_switch(node, label)
        elif t == "defer_statement":
            self._lower_defer(node)
        elif t == "go_statement":
            if node.named_children:
                self._lower_expr(node.named_children[0])   # asynchronous: never terminates
        elif t == "labeled_statement":
            self._lower_labeled(node)
        elif t in ("break_statement", "continue_statement"):
            self._lower_jump(node, t == "continue_statement")
        elif t == "goto_statement":
            lab = next((c for c in node.named_children if c.type == "label_name"), None)
            if self._node is not None and lab is not None:
                self._gotos.append((self._node, self._t(lab)))
            self._node = None
        elif t == "block":
            self._lower_block(node)
        elif t == "send_statement":
            for c in node.named_children:
                self._lower_expr(c)
        # inc/dec, empty, fallthrough (handled in switch), comments: no taint effect

    def _maybe_terminate(self) -> None:
        key = self._last_call_key
        if key in NORETURN and self._node is not None:
            if NORETURN[key]:
                self._emit_defers()
            self._connect(self._node, self._exit)
            self._node = None

    def _lower_var_spec(self, spec) -> None:
        typ = type_of(spec.child_by_field_name("type"), self._src, self._env.imports)
        names = spec.children_by_field_name("name")
        values = spec.child_by_field_name("value")
        if values is None:
            for n in names:
                self._scope.declare(self._t(n), typ)
                self._add(Assign(loc=self._loc(n), id=PVar(self._t(n)), exp=self._opaque(self._loc(n))))
            return
        self._lower_assign_lists(names, values.named_children, declare=True, declared=typ)

    def _lower_assign(self, left, right, declare: bool) -> None:
        lefts = left.named_children if left is not None else []
        rights = right.named_children if right is not None else []
        self._lower_assign_lists(lefts, rights, declare)

    def _lower_assign_lists(self, lefts, rights, declare: bool, declared: GoType = UNKNOWN) -> None:
        if len(rights) == 1 and len(lefts) > 1:
            rnode = rights[0]
            value = self._lower_expr(rnode)
            result_types = self._result_types(rnode)
            for i, lnode in enumerate(lefts):
                if self._t(lnode) == "_":
                    continue
                typ = declared if declared.known else (result_types[i] if i < len(result_types) else UNKNOWN)
                untainted = (i > 0 and rnode.type in ("index_expression", "type_assertion_expression",
                                                      "unary_expression")) \
                    or typ.path == "error" \
                    or (i == len(lefts) - 1 and self._t(lnode) == "err")
                exp = self._opaque(self._loc(lnode)) if untainted else value
                self._assign_target(lnode, exp, declare, typ, rnode if not untainted else None)
            self._on_multi_assign([self._t(l) for l in lefts], rnode)
            return
        values = [self._lower_expr(r) for r in rights]      # all RHS first: a, b = b, a
        for lnode, value, rnode in zip(lefts, values, rights):
            typ = declared if declared.known else self._type_of(rnode)
            self._assign_target(lnode, value, declare, typ, rnode)

    def _assign_target(self, lnode, value: Exp, declare: bool, typ: GoType, value_node) -> None:
        loc = self._loc(lnode)
        t = lnode.type
        if t == "identifier":
            name = self._t(lnode)
            if name == "_":
                return
            if declare:
                self._scope.declare(name, typ)
            self._add(Assign(loc=loc, id=PVar(name), exp=value))
            self._on_assign(name, value_node)
        elif t in ("selector_expression", "index_expression"):
            # Field-insensitive weak update: the base object absorbs the value.
            base_node = lnode.child_by_field_name("operand")
            base = self._base_var(base_node)
            if base is not None:
                self._add(Assign(loc=loc, id=PVar(base),
                                 exp=ExpBinOp("+", ExpVar(PVar(base)), value)))
                self._on_assign(base, None)
            if t == "index_expression":
                self._lower_expr(lnode.child_by_field_name("index"))
        elif t == "unary_expression" and lnode.named_children:          # *p = v
            self._assign_target(lnode.named_children[-1], value, False, typ, value_node)
        elif t == "parenthesized_expression" and lnode.named_children:
            self._assign_target(lnode.named_children[0], value, declare, typ, value_node)

    def _base_var(self, node) -> Optional[str]:
        while node is not None and node.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression", "unary_expression"):
            node = (node.child_by_field_name("operand") if node.type != "parenthesized_expression"
                    else (node.named_children[0] if node.named_children else None))
            if node is not None and node.type == "unary_expression":
                node = node.named_children[-1] if node.named_children else None
        if node is not None and node.type == "identifier" and not self._is_package_alias(node):
            return self._t(node)
        return None

    def _lower_compound_assign(self, node, op: str) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        lnode = left.named_children[0] if left is not None and left.named_children else None
        rnode = right.named_children[0] if right is not None and right.named_children else None
        if lnode is None or rnode is None:
            return
        value = ExpBinOp(op, self._lower_expr(lnode), self._lower_expr(rnode))
        self._assign_target(lnode, value, False, self._type_of(lnode), None)

    def _lower_return(self, node) -> None:
        loc = self._loc(node)
        values = []
        for expr_list in node.named_children:
            items = expr_list.named_children if expr_list.type == "expression_list" else [expr_list]
            values.extend(self._lower_expr(v) for v in items)
        value = None
        results = self._proc_results()
        kept = [v for i, v in enumerate(values)
                if not (i < len(results) and results[i].path == "error")]
        for v in kept:
            value = v if value is None else ExpBinOp("+", value, v)
        if value is not None:
            ret_var = self._new_ident("ret")
            self._add(Assign(loc=loc, id=ret_var, exp=value))
            value = ExpVar(ret_var)
        self._emit_defers()                 # operands first, then deferred calls
        self._add(Return(loc=loc, value=value))
        self._connect(self._node, self._exit)
        self._node = None

    def _proc_results(self) -> List[GoType]:
        name = self._proc.name[3:] if self._proc.name.startswith("go:") else ""
        if "$" in name:
            return []
        sig = self._env.funcs.get(name)
        if sig is None and "." in name:
            sig = self._env.methods.get(tuple(name.rsplit(".", 1)))
        return sig.results if sig is not None else []

    def _branch(self, before: Optional[Node], cond: Exp, true_node: Node, false_node: Node,
                loc: Location, true_kind: PruneKind, false_kind: PruneKind) -> None:
        """A clean 2-way branch in the layout SILTranslator is built for: both
        prunes in the branching node, successor 0 = true side, successor 1 =
        false side. `_branch_edge_formula` derives the per-edge feasibility
        guards (CWE-770 bound check, infeasible-path filter) and constant-folding
        edge skips from exactly this shape."""
        if before is None:
            return
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=True, kind=true_kind))
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=False, kind=false_kind))
        self._proc.connect(before.id, true_node.id)
        self._proc.connect(before.id, false_node.id)

    def _lower_if(self, node) -> None:
        outer = self._scope
        self._scope = outer.child()
        init = node.child_by_field_name("initializer")
        if init is not None:
            self._lower_stmt(init)
        cond_node = node.child_by_field_name("condition")
        cond = self._lower_expr(cond_node) if cond_node is not None else ExpConst.boolean(True)
        before = self._node
        base = self._facts_snapshot()
        loc = self._loc(node)
        then_node, else_node = self._new_node(), self._new_node()
        join = self._new_node(NodeKind.JOIN)
        self._branch(before, cond, then_node, else_node, loc, PruneKind.IF_TRUE, PruneKind.IF_FALSE)
        ends = []
        for truth, branch, bnode in ((True, node.child_by_field_name("consequence"), then_node),
                                     (False, node.child_by_field_name("alternative"), else_node)):
            self._node = bnode
            self._facts_restore(base)
            if cond_node is not None:
                self._on_branch(cond_node, truth, bnode)
            if branch is not None:
                if branch.type == "if_statement":
                    self._lower_if(branch)
                else:
                    self._lower_block(branch)
            if self._node is not None:
                self._connect(self._node, join)
                ends.append(self._facts_snapshot())
        self._facts_join(ends)
        self._node = join if join.preds else None
        self._scope = outer

    def _lower_for(self, node, label: Optional[str]) -> None:
        outer = self._scope
        self._scope = outer.child()
        loc = self._loc(node)
        body = node.child_by_field_name("body")
        clause = next((c for c in node.named_children if c.type in ("for_clause", "range_clause")), None)
        cond_node = update = None
        range_value = None
        if clause is not None and clause.type == "for_clause":
            init = clause.child_by_field_name("initializer")
            if init is not None:
                self._lower_stmt(init)
            cond_node = clause.child_by_field_name("condition")
            update = clause.child_by_field_name("update")
        elif clause is not None:
            range_value = self._lower_expr(clause.child_by_field_name("right"))
        else:
            cond_node = next((c for c in node.named_children
                              if not _same(c, body) and c.type != "comment"), None)
        self._facts_clear()
        head = self._new_node(NodeKind.LOOP_HEAD)
        self._connect(self._node, head)
        exit_node = self._new_node(NodeKind.JOIN)
        body_node = self._new_node()
        self._node = head
        if cond_node is not None:
            cond = self._lower_expr(cond_node)          # calls in the condition run in the head
            self._branch(head, cond, body_node, exit_node, loc,
                         PruneKind.LOOP_ENTER, PruneKind.LOOP_EXIT)
        else:
            self._proc.connect(head.id, body_node.id)
            if range_value is not None:                 # range may run zero times
                self._proc.connect(head.id, exit_node.id)
        cont = self._new_node() if update is not None else head
        self._breakables.append(_Breakable(exit_node, cont, label))
        self._node = body_node
        if range_value is not None:
            left = clause.child_by_field_name("left")
            declare = any(c.type == ":=" for c in clause.children)
            for lnode in (left.named_children if left is not None else []):
                self._assign_target(lnode, range_value, declare, UNKNOWN, None)
        self._lower_block(body)
        self._breakables.pop()
        if self._node is not None:
            self._connect(self._node, cont)
        if update is not None:
            self._node = cont
            self._lower_stmt(update)
            self._connect(self._node, head)
        self._facts_clear()
        self._node = exit_node if exit_node.preds else None
        self._scope = outer

    def _lower_switch(self, node, label: Optional[str]) -> None:
        """Expression cases become a chain of clean 2-way tests (the translator's
        branch layout); type-switch and select cases, which have no value
        condition, are nondeterministic successors of the test node."""
        outer = self._scope
        self._scope = outer.child()
        loc = self._loc(node)
        init = node.child_by_field_name("initializer")
        if init is not None:
            self._lower_stmt(init)
        tag_node = node.child_by_field_name("value")
        tag = self._lower_expr(tag_node) if tag_node is not None and node.type != "select_statement" else None
        alias = node.child_by_field_name("alias")
        base = self._facts_snapshot()
        exit_node = self._new_node(NodeKind.JOIN)
        cases = [c for c in node.named_children
                 if c.type in ("expression_case", "type_case", "default_case", "communication_case")]
        case_nodes = [self._new_node() for _ in cases]
        default_idx = next((i for i, c in enumerate(cases) if c.type == "default_case"), None)
        ends = []
        test = self._node
        for i, case in enumerate(cases):
            if case.type == "expression_case":
                self._node = test
                vals = case.child_by_field_name("value")
                conds = []
                for v in (vals.named_children if vals is not None else []):
                    ve = self._lower_expr(v)
                    conds.append(ExpBinOp("==", tag, ve) if tag is not None else ve)
                if not conds:
                    continue
                cond = conds[0]
                for c in conds[1:]:
                    cond = ExpBinOp("||", cond, c)
                nxt = self._new_node()
                self._branch(test, cond, case_nodes[i], nxt, loc,
                             PruneKind.SWITCH_CASE, PruneKind.SWITCH_CASE)
                test = nxt if test is not None else None
            elif case.type in ("type_case", "communication_case"):
                self._connect(test, case_nodes[i])
        if default_idx is not None:
            self._connect(test, case_nodes[default_idx])
        elif node.type != "select_statement":
            self._connect(test, exit_node)
            ends.append(base)
        self._breakables.append(_Breakable(exit_node, None, label))
        for i, (case, cnode) in enumerate(zip(cases, case_nodes)):
            self._node = cnode if cnode.preds else None
            self._facts_restore(base)
            self._scope = self._scope.child()
            if case.type == "type_case" and alias is not None and alias.named_children and tag_node is not None:
                ctype = type_of(case.child_by_field_name("type"), self._src, self._env.imports)
                aname = self._t(alias.named_children[0])
                self._scope.declare(aname, ctype)
                self._add(Assign(loc=loc, id=PVar(aname), exp=self._lower_expr(tag_node)))
            elif case.type == "communication_case":
                comm = case.child_by_field_name("communication")
                if comm is not None:
                    self._lower_stmt(comm)
            header = ([case.child_by_field_name("value"), case.child_by_field_name("communication")]
                      + list(case.children_by_field_name("type")))
            stmts = [s for s in statements_of(case)
                     if not any(_same(s, h) for h in header)]
            falls = bool(stmts) and stmts[-1].type == "fallthrough_statement"
            for s in stmts:
                self._lower_stmt(s)
            self._scope = self._scope.parent
            if self._node is not None:
                target = case_nodes[i + 1] if falls and i + 1 < len(case_nodes) else exit_node
                self._connect(self._node, target)
                if target is exit_node:
                    ends.append(self._facts_snapshot())
        self._breakables.pop()
        self._facts_join(ends)
        self._node = exit_node if exit_node.preds else None
        self._scope = outer

    def _lower_labeled(self, node) -> None:
        lab = node.child_by_field_name("label")
        name = self._t(lab)
        target = self._new_node()
        self._connect(self._node, target)
        self._labels[name] = target
        self._node = target
        self._facts_clear()
        inner = [c for c in node.named_children if not _same(c, lab)]
        if inner:
            self._lower_stmt(inner[0], label=name)

    def _lower_jump(self, node, is_continue: bool) -> None:
        lab = next((c for c in node.named_children if c.type == "label_name"), None)
        name = self._t(lab) if lab is not None else None
        for b in reversed(self._breakables):
            if is_continue and b.continue_to is None:
                continue
            if name is None or b.label == name:
                self._connect(self._node, b.continue_to if is_continue else b.break_to)
                break
        self._node = None

    def _lower_defer(self, node) -> None:
        call = node.named_children[0] if node.named_children else None
        if call is None or call.type != "call_expression":
            return
        loc = self._loc(node)
        fn = call.child_by_field_name("function")
        pre_recv = None
        if fn is not None and fn.type == "selector_expression" and not self._is_package_alias(
                fn.child_by_field_name("operand")):
            pre_recv = ExpVar(PVar(self._materialize(
                self._lower_expr(fn.child_by_field_name("operand")), loc, "d")))
        pre_args = [ExpVar(PVar(self._materialize(self._lower_expr(a), loc, "d")))
                    for a in self._arg_nodes(call)]
        if fn is not None and fn.type == "func_literal":
            self._lower_func_literal(fn)
        self._defers.append((call, pre_args, pre_recv))

    def _emit_defers(self) -> None:
        if self._node is None:
            return
        pending, self._defers = self._defers, []
        for call, pre_args, pre_recv in reversed(pending):
            self._lower_call(call, pre_args=pre_args, pre_recv=pre_recv)
        self._defers = pending

    # ------------------------------------------------------------- expressions
    def _lower_expr(self, node) -> Exp:
        if node is None:
            return ExpConst.null()
        t = node.type
        loc = self._loc(node)
        if t in _STRING_LITERALS or t == "rune_literal":
            value = literal_value(node, self._src)
            return ExpConst.string(value if isinstance(value, str) else self._t(node))
        if t == "int_literal":
            value = literal_value(node, self._src)
            return ExpConst.integer(value) if isinstance(value, int) else self._opaque(loc)
        if t in ("float_literal", "imaginary_literal"):
            return self._opaque(loc)
        if t == "true":
            return ExpConst.boolean(True)
        if t == "false":
            return ExpConst.boolean(False)
        if t == "nil":
            return ExpConst.null()
        if t == "identifier":
            name = self._t(node)
            if self._scope_lookup(name) is None:
                if name in self._env.consts and self._env.consts[name] is not None:
                    value = self._env.consts[name]
                    return ExpConst.string(value) if isinstance(value, str) else (
                        ExpConst.integer(value) if isinstance(value, int) and not isinstance(value, bool)
                        else self._opaque(loc))
                if name in ("true", "false"):
                    return ExpConst.boolean(name == "true")
                if name in ("nil", "iota"):
                    return self._opaque(loc)
            return ExpVar(PVar(name))
        if t == "parenthesized_expression":
            return self._lower_expr(node.named_children[0]) if node.named_children else ExpConst.null()
        if t == "call_expression":
            return self._lower_call(node)
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            field_name = self._t(node.child_by_field_name("field"))
            if self._is_package_alias(operand):
                return ExpVar(PVar(f"go:{self._env.pkg_of(self._t(operand))}.{field_name}"))
            base_type = self._type_of(operand)
            if base_type.known and f"{base_type.path}.{field_name}" in NON_PROPAGATING_FIELDS:
                return self._opaque(loc)
            return ExpFieldAccess(self._lower_expr(operand), field_name)
        if t == "index_expression":
            base = self._lower_expr(node.child_by_field_name("operand"))
            self._lower_expr(node.child_by_field_name("index"))       # side effects only
            return ExpFieldAccess(base, "[]")
        if t == "slice_expression":
            for f in ("start", "end", "capacity"):
                part = node.child_by_field_name(f)
                if part is not None:
                    self._lower_expr(part)
            return self._lower_expr(node.child_by_field_name("operand"))
        if t in ("type_assertion_expression", "type_conversion_expression"):
            return self._lower_expr(node.child_by_field_name("operand"))
        if t == "unary_expression":
            op = self._op(node)
            operand = self._lower_expr(node.child_by_field_name("operand"))
            if op in ("&", "*", "+"):
                return operand
            return ExpUnOp(op, operand)
        if t == "binary_expression":
            return ExpBinOp(self._op(node), self._lower_expr(node.child_by_field_name("left")),
                            self._lower_expr(node.child_by_field_name("right")))
        if t == "composite_literal":
            return self._lower_composite(node, loc)
        if t == "func_literal":
            return ExpConst.string(self._lower_func_literal(node))
        return self._opaque(loc)

    def _lower_composite(self, node, loc) -> Exp:
        values: List[Exp] = []
        stack = [node.child_by_field_name("body")]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            for c in n.named_children:
                if c.type == "keyed_element":
                    kids = c.named_children
                    if len(kids) >= 2:
                        stack.append(kids[-1])
                elif c.type == "literal_element":
                    stack.append(c)
                elif c.type == "literal_value":
                    stack.append(c)
                else:
                    values.append(self._lower_expr(c))
        dynamic = [v for v in values if not isinstance(v, ExpConst)]
        if not dynamic:
            return self._opaque(loc)
        acc = dynamic[0]
        for v in dynamic[1:]:
            acc = ExpBinOp("+", acc, v)
        return acc

    # ------------------------------------------------------------------ calls
    def _lower_call(self, node, pre_args=None, pre_recv=None) -> Exp:
        loc = self._loc(node)
        fn = node.child_by_field_name("function")
        arg_nodes = self._arg_nodes(node)
        while fn is not None and fn.type in ("parenthesized_expression", "index_expression",
                                             "generic_type"):
            fn = (fn.child_by_field_name("operand") or fn.child_by_field_name("type")
                  or (fn.named_children[0] if fn.named_children else None))
        if fn is None:
            return self._opaque(loc)

        def args() -> List[Exp]:
            return pre_args if pre_args is not None else [self._lower_expr(a) for a in arg_nodes]

        if fn.type == "func_literal":
            name = self._lower_func_literal(fn)
            return self._emit_call(loc, name, args(), callee_proc=name)
        if fn.type == "identifier":
            name = self._t(fn)
            if self._scope_lookup(name) is None:
                if name in BUILTIN_TYPES or name in self._env.local_types:
                    return args()[0] if (arg_nodes or pre_args) else self._opaque(loc)
                if name in ("make", "append", "copy", "panic", "min", "max") or name in EMPTY_BUILTINS:
                    return self._lower_builtin(name, node, arg_nodes, args(), loc)
                if name in self._env.funcs:
                    return self._emit_call(loc, f"go:{name}", args(), callee_proc=f"go:{name}")
            return self._emit_call(loc, name, args())
        if fn.type == "selector_expression":
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            if pre_recv is None and self._is_package_alias(operand):
                pkg = self._env.pkg_of(self._t(operand))
                return self._lower_package_call(pkg, member, arg_nodes, args(), loc)
            recv_exp = pre_recv if pre_recv is not None else self._lower_expr(operand)
            return self._lower_method_call(operand, recv_exp, self._type_of(operand),
                                           member, arg_nodes, args(), loc)
        callee = self._lower_expr(fn)
        return self._emit_call(loc, f"{self._materialize(callee, loc)}()", args())

    def _emit_call(self, loc, name: str, arg_exps: List[Exp], spec: Optional[ProcSpec] = None,
                   callee_proc: Optional[str] = None, key: Optional[str] = None) -> Exp:
        ret = self._new_ident("c")
        self._add(Call(loc=loc, ret=(ret, Typ.unknown_type()), func=ExpConst.string(name),
                       args=[(a, Typ.unknown_type()) for a in arg_exps]))
        if spec is not None:
            self._register(name, spec)
        if callee_proc is not None:
            self._site_callees[name] = callee_proc
        self._last_call_key = key
        return ExpVar(ret)

    def _lower_builtin(self, name, node, arg_nodes, arg_exps, loc) -> Exp:
        if name == "make":
            first = arg_nodes[0] if arg_nodes else None
            type_exp = ExpConst.string(self._t(first) if first is not None else "")
            if first is not None and first.type == "slice_type":
                out = self._emit_call(loc, "go:make", [type_exp] + arg_exps[1:], spec=MAKE_SLICE_SPEC)
            else:
                out = self._emit_call(loc, "go:make$other", [type_exp] + arg_exps[1:], spec=_EMPTY)
            return out
        if name == "copy" and len(arg_nodes) >= 2:
            base = self._base_var(arg_nodes[0])
            if base is not None:
                self._add(Assign(loc=loc, id=PVar(base),
                                 exp=ExpBinOp("+", ExpVar(PVar(base)), arg_exps[1])))
            return self._opaque(loc)
        if name in EMPTY_BUILTINS or name == "panic":
            return self._emit_call(loc, f"go:{name}", arg_exps, spec=_EMPTY, key=name)
        return self._emit_call(loc, f"go:{name}", arg_exps)          # append, min, max: default

    def _lower_package_call(self, pkg: str, member: str, arg_nodes, arg_exps, loc) -> Exp:
        key = f"{pkg}.{member}"
        name = f"go:{key}"
        base = self.specs.get(key)
        spec = self._adjust_site_spec(key, base, arg_nodes, arg_exps)
        if spec is not base:
            name = self._variant(name)
        out = self._emit_call(loc, name, arg_exps, spec=spec, key=key)
        self._apply_out_params(key, arg_nodes, out, loc)
        return out

    def _lower_method_call(self, operand, recv_exp, recv_type: GoType, member, arg_nodes,
                           arg_exps, loc) -> Exp:
        key = f"{recv_type.path}.{member}" if recv_type.known else None
        if key is not None and key in NON_PROPAGATING_CALLS:
            self._last_call_key = key
            return self._opaque(loc)
        if key is not None and (recv_type.path, member) in self._env.methods:
            site = self._site_receiver(recv_exp, loc)
            return self._emit_call(loc, f"{site}.{member}", arg_exps,
                                   callee_proc=f"go:{key}", key=key)
        base = self.specs.get(key) if key is not None else None
        if key is not None and (base is not None or key in OUT_PARAMS or key in RECEIVER_MUTATION):
            spec = self._adjust_site_spec(key, base, arg_nodes, arg_exps)
            site = self._site_receiver(recv_exp, loc)
            out = self._emit_call(loc, f"{site}.{member}", arg_exps, spec=spec, key=key)
            self._apply_out_params(key, arg_nodes, out, loc)
            if key in RECEIVER_MUTATION:
                self._assign_target(operand, ExpBinOp("+", recv_exp, self._join(arg_exps)),
                                    False, recv_type, None)
            return out
        recv_var = self._materialize(recv_exp, loc)
        return self._emit_call(loc, f"{recv_var}.{member}", arg_exps, key=key)

    @staticmethod
    def _join(exps: List[Exp]) -> Exp:
        if not exps:
            return ExpConst.string("")
        acc = exps[0]
        for e in exps[1:]:
            acc = ExpBinOp("+", acc, e)
        return acc

    def _apply_out_params(self, key: str, arg_nodes, out: Exp, loc) -> None:
        for idx in OUT_PARAMS.get(key, ()):
            if idx >= len(arg_nodes):
                break
            target = arg_nodes[idx]
            if target.type == "unary_expression" and target.named_children:
                target = target.named_children[-1]
            if target.type in ("identifier", "selector_expression", "index_expression"):
                self._assign_target(target, out, False, self._type_of(target), None)

    def _base_adjust_site_spec(self, key: str, spec: Optional[ProcSpec], arg_nodes):
        """Per-site spec changes that need only the call's own arguments."""
        if key in SHELL_COMMAND_KEYS and spec is not None:
            off = SHELL_COMMAND_KEYS[key]
            if (len(arg_nodes) > off + 2 and self._const_str(arg_nodes[off]) in SHELL_NAMES
                    and self._const_str(arg_nodes[off + 1]) in SHELL_FLAGS):
                return replace(spec, sink_args=[off + 2])
        if key in CONST_ARG0_EXEMPT and arg_nodes and self._const_str(arg_nodes[0]) is not None:
            return replace(spec, is_sink=None, sink_args=[]) if spec is not None else None
        return spec

    def _call_key(self, node) -> Optional[str]:
        """The canonical key of a call node (package function or typed method),
        resolved syntactically; None when the callee cannot be resolved."""
        if node is None or node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            return None
        operand = fn.child_by_field_name("operand")
        member = self._t(fn.child_by_field_name("field"))
        if self._is_package_alias(operand):
            return f"{self._env.pkg_of(self._t(operand))}.{member}"
        recv = self._type_of(operand)
        return f"{recv.path}.{member}" if recv.known else None

    # ------------------------------------------------------------------- types
    def _type_of(self, node) -> GoType:
        if node is None:
            return UNKNOWN
        t = node.type
        if t == "identifier":
            name = self._t(node)
            local = self._scope_lookup(name)
            if local is not None:
                return local
            return self._env.package_vars.get(name, UNKNOWN)
        if t == "parenthesized_expression" and node.named_children:
            return self._type_of(node.named_children[0])
        if t == "unary_expression":
            inner = self._type_of(node.child_by_field_name("operand"))
            return GoType(inner.path, True) if self._op(node) == "&" and inner.known else inner
        if t == "composite_literal":
            return type_of(node.child_by_field_name("type"), self._src, self._env.imports)
        if t in ("type_assertion_expression", "type_conversion_expression"):
            return type_of(node.child_by_field_name("type"), self._src, self._env.imports)
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            field_name = self._t(node.child_by_field_name("field"))
            if self._is_package_alias(operand):
                return UNKNOWN
            base = self._type_of(operand)
            if not base.known:
                return UNKNOWN
            local = self._env.struct_fields.get(base.path, {}).get(field_name)
            if local is not None:
                return local
            known = FIELD_TYPES.get(f"{base.path}.{field_name}")
            return GoType(known) if known else UNKNOWN
        if t == "call_expression":
            results = self._result_types(node)
            return results[0] if results else UNKNOWN
        return UNKNOWN

    def _result_types(self, node) -> List[GoType]:
        if node is None or node.type != "call_expression":
            return []
        fn = node.child_by_field_name("function")
        if fn is None:
            return []
        if fn.type == "identifier" and self._scope_lookup(self._t(fn)) is None:
            name = self._t(fn)
            if name in self._env.funcs:
                return self._env.funcs[name].results
            if name in BUILTIN_TYPES or name in self._env.local_types:
                return [GoType(name)]
            return []
        if fn.type == "selector_expression":
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            if self._is_package_alias(operand):
                key = f"{self._env.pkg_of(self._t(operand))}.{member}"
            else:
                recv = self._type_of(operand)
                if not recv.known:
                    return []
                sig = self._env.methods.get((recv.path, member))
                if sig is not None:
                    return sig.results
                key = f"{recv.path}.{member}"
            known = RESULT_TYPES.get(key)
            return [GoType(known, True)] if known else []
        return []
```

In `frame/sil/frontends/__init__.py`, after the C# block add:

```python
# Go frontend
try:
    from frame.sil.frontends.go_frontend import GoFrontend, TREE_SITTER_GO_AVAILABLE
    GO_FRONTEND_AVAILABLE = TREE_SITTER_GO_AVAILABLE
except ImportError:
    GO_FRONTEND_AVAILABLE = False
    GoFrontend = None
```

and add `"GoFrontend", "GO_FRONTEND_AVAILABLE",` to `__all__`; add `- GoFrontend: Go source code` to the module docstring list.

In `frame/sil/scanner.py` `_get_frontend`, before the final `else:` add:

```python
        elif language == "go":
            from frame.sil.frontends.go_frontend import GoFrontend
            fe = GoFrontend()
            fe.taint_exported_params = self.library_mode
            return fe
```

- [ ] **Step 5: Run the Task 4 tests**

Run: `.venv/bin/python -m pytest tests/test_go_frontend.py tests/test_go_taint.py -v`
Expected: all PASS. When a test fails, debug with the lowered program rather than by loosening the assertion:

```bash
.venv/bin/python - <<'EOF'
from frame.sil.frontends.go_frontend import GoFrontend
src = open("/tmp/x.go").read()          # paste the failing fixture here
p = GoFrontend().translate(src, "t.go")
for name, proc in p.procedures.items():
    print(name); [print(" ", n) for n in proc.nodes.values()]
print({k: (v.is_sink, v.sink_args) for k, v in p.library_specs.items()})
EOF
```

`test_guarded_exit_still_ends_that_path` is deliberately weak (it pins "no crash"); leave it as written.

- [ ] **Step 6: Run the full suite against the baseline**

Run: `.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3`
Expected: baseline + new tests passing, no new failures.

- [ ] **Step 7: Commit**

```bash
git add frame/sil/frontends/go_frontend.py frame/sil/frontends/__init__.py frame/sil/scanner.py tests/test_go_frontend.py tests/test_go_taint.py
git commit -m "Go frontend: lowering, site-unique call registration, handler-shaped sources

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---
### Task 5: Same-file summaries and into-callee taint

Out of callees: every Go procedure gets an explicit summary spec (spec § "Same-file interprocedural flow"), registered under each call site that resolves to it. Into callees: a tainted argument taints the callee's parameter at entry.

**Files:**
- Create: `frame/sil/frontends/_go_summaries.py`
- Modify: `frame/sil/frontends/go_frontend.py` (`_after_lowering`)
- Test: `tests/test_go_frontend.py`, `tests/test_go_taint.py` (append)

**Interfaces:**
- Consumes: `GoFrontend._site_callees` (Task 4), `Program.get_spec` in exact mode (Task 1).
- Produces: `apply_same_file_flow(program: Program, site_callees: Dict[str, str]) -> None`; constant `FIXPOINT_DESC: str`; `exp_vars(exp) -> List[str]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_go_frontend.py`:

```python
def test_method_call_site_resolves_to_callee_summary():
    src = '''package main
type Server struct{}
func (s *Server) H(x string) string { return x }
func use(s *Server, y string) string { return s.H(y) }'''
    p = _prog(src)
    call = next(c for c in _calls(p.procedures["go:use"]) if c.get_full_name().endswith(".H"))
    assert p.get_spec(call.get_full_name()) is p.procedures["go:Server.H"].spec
    assert p.procedures["go:Server.H"].spec.taint_propagates == [0]


def test_summary_marks_sanitizing_helper_and_constant_helper():
    src = '''package main
import "path/filepath"
func safe(p string) string { return filepath.Base(p) }
func pick(s string) string { return "static" }'''
    p = _prog(src)
    assert p.procedures["go:safe"].spec.is_sanitizer == ["filesystem"]
    assert p.procedures["go:pick"].spec.taint_propagates == []


def test_recursive_procedures_get_conservative_summary():
    src = '''package main
func a(s string, n int) string { if n == 0 { return "x" }; return b(s, n-1) }
func b(s string, n int) string { return a(s, n) }'''
    p = _prog(src)
    assert p.procedures["go:a"].spec.taint_propagates == [0, 1]
    assert p.procedures["go:a"].spec.is_sanitizer == []
```

Append to `tests/test_go_taint.py`:

```python
def test_identity_helper_keeps_taint():
    src = _handler('exec.Command(identity(r.FormValue("cmd")))',
                   '"net/http"\n"os/exec"', "func identity(s string) string { return s }")
    assert "CWE-78" in _cwes(src)


def test_sanitizing_helper_clears_only_its_kind():
    extra = "func safe(p string) string { return filepath.Base(p) }"
    imports = '"net/http"\n"os"\n"os/exec"\n"path/filepath"'
    assert "CWE-22" not in _cwes(_handler('os.Open(safe(r.FormValue("f")))', imports, extra))
    assert "CWE-78" in _cwes(_handler('exec.Command(safe(r.FormValue("f")))', imports, extra))


def test_constant_helper_does_not_propagate():
    src = _handler('os.Open(pick(r.FormValue("f")))', '"net/http"\n"os"',
                   'func pick(s string) string { return "static.txt" }')
    assert "CWE-22" not in _cwes(src)


def test_helper_that_returns_request_data_is_a_source():
    src = '''package main
import ("net/http"; "os/exec")
func q(w http.ResponseWriter, r *http.Request) string { return r.FormValue("a") }
func run() { exec.Command(q(nil, nil)) }'''
    assert "CWE-78" in _cwes(src)


def test_tainted_argument_reaches_sink_in_callee():
    src = _handler('run(r.FormValue("cmd"))', '"net/http"\n"os/exec"',
                   "func run(c string) { exec.Command(c).Run() }")
    assert "CWE-78" in _cwes(src)


def test_tainted_argument_reaches_sink_in_method_callee():
    src = _handler('s.run(r.FormValue("cmd"))', '"net/http"\n"os/exec"',
                   "type S struct{}\nvar s *S\nfunc (x *S) run(c string) { exec.Command(c).Run() }")
    assert "CWE-78" in _cwes(src)
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_go_frontend.py tests/test_go_taint.py -q -k "summary or helper or callee or recursive"`
Expected: FAIL (summaries empty; e.g. `taint_propagates == []` where `[0]` expected, and missing CWE-78).

- [ ] **Step 3: Implement `_go_summaries.py`**

Create `frame/sil/frontends/_go_summaries.py`:

```python
"""Same-file procedure summaries and into-callee taint for the Go frontend.

Out of callees: Program.get_spec returns a same-file procedure's own ProcSpec,
which is empty unless filled, so the translator never applies its unknown-call
propagation and `identity(r.FormValue("x"))` would lose its taint. Every Go
procedure therefore gets an explicit summary: which parameters (and receiver)
reach a return, which sink kinds EVERY such flow is sanitized for, and whether
a return can carry a source of its own. Callees are summarised before callers;
a recursive cycle gets the conservative summary.

Into callees: a tainted argument taints the callee's parameter at entry
(a TaintSource tagged FIXPOINT_DESC), mirroring the Java frontend's fixpoint.
Those tagged sources are excluded from `is_source`, so the two directions
cannot feed each other.

Both are flow-insensitive over the lowered SIL: a may-analysis for taint, a
must-analysis (intersection) for sanitization.
"""

from typing import Dict, FrozenSet, List, Optional, Set

from frame.sil.instructions import Assign, Call, Return, TaintKind, TaintSource
from frame.sil.procedure import Procedure, Program, ProcSpec
from frame.sil.types import (
    ExpBinOp, ExpConst, ExpFieldAccess, ExpIndex, ExpStringConcat, ExpUnOp, ExpVar,
)

FIXPOINT_DESC = "Go same-file flow: tainted argument from a caller"
_SRC = "src"
_RETURN = "$return"
_PACKAGE_PROC = "go:$package"

Flows = Dict[str, Dict[object, FrozenSet[str]]]


def exp_vars(exp) -> List[str]:
    """Variable names in an expression, as SILTranslator._get_exp_vars names them."""
    if isinstance(exp, ExpVar):
        return [str(exp.var)]
    if isinstance(exp, ExpBinOp):
        return exp_vars(exp.left) + exp_vars(exp.right)
    if isinstance(exp, ExpUnOp):
        return exp_vars(exp.operand)
    if isinstance(exp, ExpFieldAccess):
        return exp_vars(exp.base)
    if isinstance(exp, ExpIndex):
        return exp_vars(exp.base) + exp_vars(exp.index)
    if isinstance(exp, ExpStringConcat):
        return [v for part in exp.parts for v in exp_vars(part)]
    return []


def _instrs(proc: Procedure):
    for node in proc.nodes.values():
        yield from node.instrs


def _receiver_of(name: str) -> Optional[str]:
    if "." not in name or name.startswith("go:"):
        return None
    return name.rsplit(".", 1)[0]


def _call_inputs(ins: Call, name: str, spec: Optional[ProcSpec]):
    """(variable, sanitizer kinds added) pairs whose taint reaches the result,
    mirroring SILTranslator._exec_call."""
    args = [exp_vars(a) for a, _ in ins.args]
    recv = _receiver_of(name)
    if spec is None:
        out = [(v, frozenset()) for vs in args for v in vs]
        if recv:
            out.append((recv, frozenset()))
        return out
    extra = frozenset(spec.is_sanitizer or ())
    out = []
    if spec.is_sanitizer and args:
        out += [(v, extra) for v in args[0]]
    for i in spec.taint_propagates:
        if i < len(args):
            out += [(v, extra) for v in args[i]]
    if spec.propagates_taint() and recv and (spec.taint_from_receiver or "." in name):
        out.append((recv, extra))
    return out


def _flow(proc: Procedure, program: Program, seeds: Flows, include_fixpoint: bool) -> Flows:
    flows: Flows = {v: dict(ls) for v, ls in seeds.items()}
    instrs = list(_instrs(proc))

    def add(var: str, label, kinds: FrozenSet[str]) -> bool:
        cur = flows.setdefault(var, {})
        if label not in cur:
            cur[label] = kinds
            return True
        narrowed = cur[label] & kinds
        if narrowed != cur[label]:
            cur[label] = narrowed
            return True
        return False

    changed = True
    while changed:
        changed = False
        for ins in instrs:
            if isinstance(ins, TaintSource):
                if include_fixpoint or ins.description != FIXPOINT_DESC:
                    changed |= add(str(ins.var), _SRC, frozenset())
            elif isinstance(ins, Assign):
                target = str(ins.id)
                for u in exp_vars(ins.exp):
                    for label, kinds in list(flows.get(u, {}).items()):
                        changed |= add(target, label, kinds)
            elif isinstance(ins, Call) and ins.ret is not None:
                ret = str(ins.ret[0])
                name = ins.get_full_name()
                spec = program.get_spec(name)
                for u, extra in _call_inputs(ins, name, spec):
                    for label, kinds in list(flows.get(u, {}).items()):
                        changed |= add(ret, label, kinds | extra)
                if spec is not None and spec.is_source:
                    changed |= add(ret, _SRC, frozenset())
            elif isinstance(ins, Return) and ins.value is not None:
                for u in exp_vars(ins.value):
                    for label, kinds in list(flows.get(u, {}).items()):
                        changed |= add(_RETURN, label, kinds)
    return flows


def _sccs(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """Tarjan, iterative. Components come out callees-first."""
    index: Dict[str, int] = {}
    low: Dict[str, int] = {}
    on_stack: Set[str] = set()
    stack: List[str] = []
    out: List[List[str]] = []
    counter = 0
    for root in graph:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(sorted(graph[root])))]
        while work:
            v, it = work[-1]
            nxt = next(it, None)
            if nxt is not None:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(graph[nxt]))))
                elif nxt in on_stack:
                    low[v] = min(low[v], index[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                out.append(comp)
    return out


def _has_own_source(proc: Procedure) -> bool:
    return any(isinstance(i, TaintSource) and i.description != FIXPOINT_DESC
               for i in _instrs(proc))


def _summarize(proc: Procedure, program: Program, conservative: bool) -> None:
    spec = proc.spec
    offset = 1 if proc.is_method else 0
    n_args = max(0, len(proc.params) - offset)
    spec.description = f"Go same-file summary of {proc.name}"
    if conservative:
        spec.taint_propagates = list(range(n_args))
        spec.taint_from_receiver = proc.is_method
        spec.is_sanitizer = []
        spec.is_source = "user" if _has_own_source(proc) else None
        return
    seeds: Flows = {p.name: {("p", i): frozenset()} for i, (p, _) in enumerate(proc.params)}
    ret = _flow(proc, program, seeds, include_fixpoint=False).get(_RETURN, {})
    params = sorted(label[1] for label in ret if isinstance(label, tuple))
    spec.taint_propagates = [i - offset for i in params if i >= offset]
    spec.taint_from_receiver = proc.is_method and 0 in params
    spec.is_source = "user" if _SRC in ret else None
    kinds = None
    for k in ret.values():
        kinds = set(k) if kinds is None else kinds & k
    spec.is_sanitizer = sorted(kinds) if kinds else []


def _mark_param(proc: Procedure, idx: int) -> bool:
    pvar = proc.params[idx][0]
    entry = proc.nodes[proc.entry_node]
    if any(isinstance(i, TaintSource) and i.var == pvar for i in entry.instrs):
        return False
    entry.instrs.insert(0, TaintSource(loc=proc.loc, var=pvar, kind=TaintKind.USER_INPUT,
                                       description=FIXPOINT_DESC))
    return True


def apply_same_file_flow(program: Program, site_callees: Dict[str, str],
                         max_rounds: int = 10) -> None:
    procs = {n: p for n, p in program.procedures.items() if n != _PACKAGE_PROC}
    # 1. Every site that resolves to a same-file procedure shares its spec object.
    for site, callee in site_callees.items():
        if callee in procs and site != callee:
            program.library_specs[site] = procs[callee].spec
    # 2. Summaries, callees first.
    graph: Dict[str, Set[str]] = {n: set() for n in procs}
    for n, p in procs.items():
        for ins in _instrs(p):
            if isinstance(ins, Call):
                callee = site_callees.get(ins.get_full_name())
                if callee in procs:
                    graph[n].add(callee)
    for comp in _sccs(graph):
        recursive = len(comp) > 1 or any(n in graph[n] for n in comp)
        for n in comp:
            _summarize(procs[n], program, conservative=recursive)
    # 3. Into callees, to a fixpoint.
    for _ in range(max_rounds):
        changed = False
        for proc in procs.values():
            flows = _flow(proc, program, {}, include_fixpoint=True)
            tainted = {v for v, labels in flows.items() if _SRC in labels}
            for ins in _instrs(proc):
                if not isinstance(ins, Call):
                    continue
                callee = procs.get(site_callees.get(ins.get_full_name(), ""))
                if callee is None:
                    continue
                offset = 1 if callee.is_method else 0
                hits = {j + offset for j, (a, _) in enumerate(ins.args)
                        if set(exp_vars(a)) & tainted}
                if callee.is_method and _receiver_of(ins.get_full_name()) in tainted:
                    hits.add(0)
                for idx in sorted(hits):
                    if idx < len(callee.params) and _mark_param(callee, idx):
                        changed = True
        if not changed:
            break
```

In `frame/sil/frontends/go_frontend.py`, add the import next to the other `_go_*` imports:

```python
from frame.sil.frontends._go_summaries import apply_same_file_flow
```

and replace the `_after_lowering` stub with:

```python
    def _after_lowering(self) -> None:
        apply_same_file_flow(self._program, self._site_callees)
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_frontend.py tests/test_go_taint.py -v`
Expected: all PASS (Task 4's tests included).

- [ ] **Step 5: Commit**

```bash
git add frame/sil/frontends/_go_summaries.py frame/sil/frontends/go_frontend.py tests/test_go_frontend.py tests/test_go_taint.py
git commit -m "Go frontend: same-file summaries and into-callee taint

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Guard facts, trusted roots, and site sanitizers

Implements spec § "Sanitizers" in full: guard facts in CNF, the complete FILE_PATH / REDIRECT / SSRF rules, in-file provenance for trusted roots, the `Join(root, Clean("/"+x))` and Contains-in-Join site sanitizers, and constant-prefix destinations.

**Files:**
- Create: `frame/sil/frontends/_go_guards.py`
- Modify: `frame/sil/frontends/go_frontend.py` (override the Task 4 hooks)
- Test: `tests/test_go_frontend.py`, `tests/test_go_taint.py` (append)

**Interfaces:**
- Consumes: Task 4 hooks and helpers (`_call_key`, `_const_str`, `_arg_nodes`, `_t`, `_is_package_alias`).
- Produces (`frame.sil.frontends._go_guards`):
  - `TrustOracle(root, src: bytes, env: FileEnv, key_of, is_alias, text)` with `enter(fn_node, receiver: str, params: Set[str])`, `leave()`, `trusted(node, checked: Optional[str] = None) -> bool`.
  - `GuardTracker(src, trust: TrustOracle, key_of, arg_nodes, const_str, text)` with `clear()`, `snapshot()`, `restore(snap)`, `join(snaps)`, `on_assign(name, value_node)`, `on_multi_assign(names, value_node)`, `on_branch(cond_node, truth) -> Dict[str, Set[str]]`, `sanitized_kinds(var) -> Set[str]`, `implies(*lits) -> bool`.

- [ ] **Step 1: Write the failing end-to-end tests (twins and bypasses)**

Append to `tests/test_go_taint.py`:

```python
# ---- CWE-22 twins (must be silent) and bypasses (must fire) -----------------
FS = '"net/http"\n"os"\n"path/filepath"\n"strings"'


def test_fs_twin_base():
    _pair("CWE-22", _handler('os.Open(r.FormValue("f"))', FS),
          _handler('os.Open(filepath.Base(r.FormValue("f")))', FS))


def test_fs_twin_securejoin():
    imports = FS + '\n"github.com/cyphar/filepath-securejoin"'
    _pair("CWE-22", _handler('p := filepath.Join("/srv", r.FormValue("f"))\nos.Open(p)', imports),
          _handler('p, _ := securejoin.SecureJoin("/srv", r.FormValue("f"))\nos.Open(p)', imports))


def test_fs_twin_rooted_clean_join():
    _pair("CWE-22", _handler('os.ReadFile(filepath.Join("/srv", r.FormValue("f")))', FS),
          _handler('os.ReadFile(filepath.Join("/srv", filepath.Clean("/" + r.FormValue("f"))))', FS))


def test_fs_twin_separator_aware_prefix():
    body = ('p := filepath.Clean(filepath.Join(root, r.FormValue("f")))\n'
            'if !strings.HasPrefix(p, root+string(filepath.Separator)) { return }\n'
            'os.ReadFile(p)')
    vulnerable = body.replace('if !strings.HasPrefix(p, root+string(filepath.Separator)) { return }\n', '')
    _pair("CWE-22", _handler(vulnerable, FS, 'const root = "/srv/www"'),
          _handler(body, FS, 'const root = "/srv/www"'))


def test_fs_twin_rel():
    body = ('p := filepath.Join(root, r.FormValue("f"))\n'
            'rel, err := filepath.Rel(root, p)\n'
            'if err != nil || strings.HasPrefix(rel, "..") { return }\n'
            'os.ReadFile(p)')
    vulnerable = 'p := filepath.Join(root, r.FormValue("f"))\nos.ReadFile(p)'
    _pair("CWE-22", _handler(vulnerable, FS, 'const root = "/srv/www"'),
          _handler(body, FS, 'const root = "/srv/www"'))


def test_fs_twin_islocal():
    body = 'f := r.FormValue("f")\nif !filepath.IsLocal(f) { return }\nos.ReadFile(f)'
    _pair("CWE-22", _handler('f := r.FormValue("f")\nos.ReadFile(f)', FS), _handler(body, FS))


def test_fs_twin_dotdot_free_inside_join():
    body = ('f := r.FormValue("f")\nif strings.Contains(f, "..") { return }\n'
            'os.ReadFile(filepath.Join("/srv", f))')
    _pair("CWE-22", _handler('f := r.FormValue("f")\nos.ReadFile(filepath.Join("/srv", f))', FS),
          _handler(body, FS))


def test_fs_twin_receiver_root_assigned_constant():
    extra = ('type S struct{ root string }\n'
             'func New() *S { return &S{root: "/srv"} }\n'
             'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n'
             '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}')
    vulnerable = extra.replace('filepath.Clean("/" + r.FormValue("f"))', 'r.FormValue("f")')
    _pair("CWE-22", _handler("", FS, vulnerable), _handler("", FS, extra))


def test_fs_bypass_rooted_clean_alone():
    src = _handler('os.ReadFile(filepath.Clean("/" + r.FormValue("f")))', FS)
    assert "CWE-22" in _cwes(src)


def test_fs_bypass_prefix_without_separator():
    body = ('p := filepath.Clean(r.FormValue("f"))\n'
            'if !strings.HasPrefix(p, "/srv/www") { return }\nos.ReadFile(p)')
    assert "CWE-22" in _cwes(_handler(body, FS))


def test_fs_bypass_dotdot_check_without_root():
    body = 'f := r.FormValue("f")\nif strings.Contains(f, "..") { return }\nos.ReadFile(f)'
    assert "CWE-22" in _cwes(_handler(body, FS))


def test_fs_bypass_attacker_chosen_receiver_root():
    extra = ('type S struct{ root string }\n'
             'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n'
             '  s.root = r.FormValue("root")\n'
             '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_fs_bypass_reassigned_after_guard():
    body = ('f := r.FormValue("f")\nif !filepath.IsLocal(f) { return }\n'
            'f = r.FormValue("g")\nos.ReadFile(f)')
    assert "CWE-22" in _cwes(_handler(body, FS))


# ---- CWE-601 --------------------------------------------------------------------
RD = '"net/http"\n"net/url"\n"strings"'


def test_redirect_twin_relative_path_full_check():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "\\\\") || strings.ContainsAny(next, "\\r\\n\\t") { return }\n'
            'http.Redirect(w, r, next, 302)')
    _pair("CWE-601", _handler('next := r.FormValue("next")\nhttp.Redirect(w, r, next, 302)', RD),
          _handler(body, RD))


def test_redirect_twin_url_parse_full_check():
    body = ('next := r.FormValue("next")\nu, err := url.Parse(next)\n'
            'if err != nil || u.IsAbs() || u.Host != "" || strings.Contains(next, "\\\\") { return }\n'
            'http.Redirect(w, r, next, 302)')
    vulnerable = 'next := r.FormValue("next")\nu, _ := url.Parse(next)\n_ = u\nhttp.Redirect(w, r, next, 302)'
    _pair("CWE-601", _handler(vulnerable, RD), _handler(body, RD))


def test_redirect_twin_host_allowlist():
    body = ('u, err := url.Parse(r.FormValue("next"))\n'
            'if err != nil || u.Hostname() != "example.com" { return }\n'
            'http.Redirect(w, r, u.String(), 302)')
    vulnerable = body.replace('if err != nil || u.Hostname() != "example.com" { return }\n', '_ = err\n')
    _pair("CWE-601", _handler(vulnerable, RD), _handler(body, RD))


def test_redirect_twin_constant_prefix_with_query():
    _pair("CWE-601", _handler('http.Redirect(w, r, r.FormValue("q"), 302)', RD),
          _handler('http.Redirect(w, r, "/search?q="+r.FormValue("q"), 302)', RD))


def test_redirect_bypass_isabs_only():
    body = ('next := r.FormValue("next")\nu, err := url.Parse(next)\n'
            'if err != nil || u.IsAbs() { return }\nhttp.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_no_backslash_check():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") { return }\n'
            'http.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_leading_backslash_only():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.HasPrefix(next, "/\\\\") { return }\nhttp.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_no_control_char_check():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "\\\\") { return }\nhttp.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_slash_prefix():
    assert "CWE-601" in _cwes(_handler('http.Redirect(w, r, "/"+r.FormValue("n"), 302)', RD))


def test_redirect_bypass_constant_path_prefix():
    assert "CWE-601" in _cwes(_handler('http.Redirect(w, r, "/safe/"+r.FormValue("n"), 302)', RD))


# ---- CWE-918 ------------------------------------------------------------------------
def test_ssrf_twin_constant_authority():
    _pair("CWE-918", _handler('http.Get(r.FormValue("id"))', RD),
          _handler('http.Get("https://api.example.com/v1/items?id=" + r.FormValue("id"))', RD))


def test_ssrf_twin_host_allowlist():
    body = ('u, err := url.Parse(r.FormValue("u"))\n'
            'if err != nil || u.Hostname() != "api.example.com" { return }\nhttp.Get(u.String())')
    vulnerable = body.replace('if err != nil || u.Hostname() != "api.example.com" { return }\n', '_ = err\n')
    _pair("CWE-918", _handler(vulnerable, RD), _handler(body, RD))


def test_ssrf_bypass_query_escaped_host():
    src = _handler('http.Get("http://" + url.QueryEscape(r.FormValue("h")) + "/latest/meta-data/")', RD)
    assert "CWE-918" in _cwes(src)


def test_ssrf_bypass_open_authority():
    assert "CWE-918" in _cwes(_handler('http.Get("https://" + r.FormValue("h"))', RD))


# ---- CWE-79 / CWE-770 -----------------------------------------------------------------
HT = '"html"\n"html/template"\n"net/http"'


def test_html_twin_escaped():
    _pair("CWE-79", _handler('_ = template.HTML(r.FormValue("x"))', HT),
          _handler('_ = template.HTML(html.EscapeString(r.FormValue("x")))', HT))


def test_html_bypass_unescaped():
    assert "CWE-79" in _cwes(_handler('_ = template.HTML(r.FormValue("x"))', HT))


def test_template_js_is_out_of_scope():
    assert "CWE-79" not in _cwes(_handler('_ = template.JS(html.EscapeString(r.FormValue("x")))', HT))


def test_alloc_twin_bounded():
    body = ('n, _ := strconv.Atoi(r.FormValue("n"))\nif n > 1048576 { return }\n'
            'buf := make([]byte, n)\n_ = buf')
    imports = '"net/http"\n"strconv"'
    _pair("CWE-770", _handler(body.replace('if n > 1048576 { return }\n', ''), imports),
          _handler(body, imports))
```

- [ ] **Step 2: Write the failing unit tests**

Append to `tests/test_go_frontend.py`:

```python
from frame.sil.instructions import Sanitize


def _sanitizes(proc):
    return [(i.var.name, sorted(k.value for k in i.sanitizes))
            for n in proc.nodes.values() for i in n.instrs if isinstance(i, Sanitize)]


def test_guard_emits_sanitize_on_continuation():
    src = '''package main
import ("net/http"; "path/filepath")
func h(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	if !filepath.IsLocal(f) { return }
	_ = f
}'''
    assert ("f", ["filesystem"]) in _sanitizes(_prog(src).procedures["go:h"])


def test_unrecognised_guard_emits_nothing():
    src = '''package main
import ("net/http")
func h(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	if !check(f) { return }
	_ = f
}
func check(s string) bool { return true }'''
    assert _sanitizes(_prog(src).procedures["go:h"]) == []


def test_facts_do_not_survive_a_join_with_an_unguarded_path():
    src = '''package main
import ("net/http"; "path/filepath")
func h(w http.ResponseWriter, r *http.Request, b bool) {
	f := r.FormValue("f")
	if b {
		if !filepath.IsLocal(f) { return }
	}
	g := f
	_ = g
}'''
    # The Sanitize exists only inside the guarded branch; nothing after the join.
    proc = _prog(src).procedures["go:h"]
    assert _sanitizes(proc) == [("f", ["filesystem"])]
```

- [ ] **Step 3: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_go_taint.py tests/test_go_frontend.py -q`
Expected: the twin tests and the first unit test FAIL (findings present / no Sanitize); bypass tests mostly already PASS.

- [ ] **Step 4: Implement `_go_guards.py`**

Create `frame/sil/frontends/_go_guards.py`:

```python
"""Guard facts, sanitizer rules and trusted-root provenance for the Go frontend.

A guard such as `if !strings.HasPrefix(p, root+string(filepath.Separator)) { return }`
proves something about `p` on the continuation. Conditions are converted to
CNF clauses over literals (var, atom, arg, polarity); a rule is satisfied when
some clause implies each required literal (a clause implies a set of literals
when it is a subset of that set). Unrecognised conditions contribute a clause
containing an unknown literal, which implies nothing. Facts are killed when a
mentioned variable is reassigned and intersected at joins. Only complete checks
sanitize (docs/superpowers/specs/2026-09-23-go-frontend-design.md, "Guard facts").
"""

from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from frame.sil.frontends._go_env import FileEnv, literal_value
from frame.sil.specs.go_specs import NORMALIZING_KEYS, TRUSTED_PURE_CALLS

FS, REDIRECT, SSRF = "filesystem", "redirect", "ssrf"
Literal = Tuple[str, str, str, bool]          # (var, atom, arg, polarity)
Clause = FrozenSet[Literal]
_UNKNOWN: Clause = frozenset({("", "?", "", True)})
_MAX_CLAUSES = 64
_SEPARATOR_TEXTS = frozenset({
    'string(filepath.Separator)', 'string(os.PathSeparator)', '"/"'})
_URL_PARSE = frozenset({"net/url.Parse", "net/url.ParseRequestURI"})


def _strip(node):
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


# --------------------------------------------------------------------------- trust
class TrustOracle:
    """Decides syntactically whether a root / allowlist expression is trusted,
    from in-file reaching definitions (spec: "Trusted (untainted) root")."""

    def __init__(self, root, src: bytes, env: FileEnv,
                 key_of: Callable, is_alias: Callable, text: Callable):
        self.src, self.env = src, env
        self.key_of, self.is_alias, self.text = key_of, is_alias, text
        self.pkg_assign: Dict[str, List] = {}
        self.field_assign: Dict[str, List] = {}
        self.frames: List[Tuple[Dict[str, List], Set[str], str]] = []
        self._collect(root)

    def _record_target(self, lnode, rnode) -> None:
        lnode = _strip(lnode)
        if lnode is None:
            return
        if lnode.type == "identifier":
            name = self.text(lnode)
            if name in self.env.package_vars:
                self.pkg_assign.setdefault(name, []).append(rnode)
        elif lnode.type in ("selector_expression", "index_expression"):
            node = lnode
            while node is not None and node.type in ("selector_expression", "index_expression"):
                if node.type == "selector_expression":
                    self.field_assign.setdefault(
                        self.text(node.child_by_field_name("field")), []).append(rnode)
                node = node.child_by_field_name("operand")

    def _collect(self, root) -> None:
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type in ("assignment_statement", "short_var_declaration"):
                lefts = n.child_by_field_name("left")
                rights = n.child_by_field_name("right")
                ls = lefts.named_children if lefts is not None else []
                rs = rights.named_children if rights is not None else []
                for i, l in enumerate(ls):
                    self._record_target(l, rs[i] if len(rs) == len(ls) else None)
            elif n.type == "keyed_element":
                kids = n.named_children
                if len(kids) >= 2:
                    key = _strip(kids[0].named_children[0] if kids[0].type == "literal_element"
                                 and kids[0].named_children else kids[0])
                    if key is not None and key.type in ("identifier", "field_identifier"):
                        value = kids[-1].named_children[0] if kids[-1].type == "literal_element" \
                            and kids[-1].named_children else kids[-1]
                        self.field_assign.setdefault(self.text(key), []).append(value)
            elif n.type == "var_spec" and n.parent is not None and n.parent.type == "var_declaration" \
                    and n.parent.parent is not None and n.parent.parent.type == "source_file":
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    self.pkg_assign.setdefault(self.text(name), []).append(
                        vals[i] if i < len(vals) else "zero")

    def enter(self, fn_node, receiver: str, params: Set[str]) -> None:
        defs: Dict[str, List] = {}
        body = fn_node.child_by_field_name("body")
        stack = [body] if body is not None else []
        while stack:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type in ("assignment_statement", "short_var_declaration"):
                lefts = n.child_by_field_name("left")
                rights = n.child_by_field_name("right")
                ls = lefts.named_children if lefts is not None else []
                rs = rights.named_children if rights is not None else []
                for i, l in enumerate(ls):
                    if l.type == "identifier":
                        defs.setdefault(self.text(l), []).append(
                            rs[i] if len(rs) == len(ls) else None)
            elif n.type in ("var_spec", "const_spec"):
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    defs.setdefault(self.text(name), []).append(vals[i] if i < len(vals) else "zero")
            elif n.type == "range_clause":
                left = n.child_by_field_name("left")
                for l in (left.named_children if left is not None else []):
                    defs.setdefault(self.text(l), []).append(None)
        self.frames.append((defs, set(params), receiver))

    def leave(self) -> None:
        if self.frames:
            self.frames.pop()

    def trusted(self, node, checked: Optional[str] = None, _seen: Optional[Set] = None) -> bool:
        node = _strip(node)
        if node is None:
            return False
        seen = _seen if _seen is not None else set()
        t = node.type
        if t in ("interpreted_string_literal", "raw_string_literal", "int_literal", "rune_literal"):
            return True
        if t == "binary_expression":
            return (self.trusted(node.child_by_field_name("left"), checked, seen)
                    and self.trusted(node.child_by_field_name("right"), checked, seen))
        if t == "identifier":
            return self._trusted_name(self.text(node), checked, seen)
        if t == "selector_expression":
            return self._trusted_field_path(node, checked, seen)
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            args = [a for a in (args_node.named_children if args_node is not None else [])]
            if fn is not None and fn.type == "identifier" and self.text(fn) == "string":
                return len(args) == 1 and (self.text(args[0]) in (
                    "filepath.Separator", "os.PathSeparator") or self.trusted(args[0], checked, seen))
            key = self.key_of(node)
            return key in TRUSTED_PURE_CALLS and all(self.trusted(a, checked, seen) for a in args)
        return False

    def _trusted_name(self, name: str, checked, seen) -> bool:
        if name == checked:
            return False
        if self.frames:
            defs, params, receiver = self.frames[-1]
            if name in params or name == receiver:
                return False
            if name in defs:
                return self._all_trusted(("local", name), defs[name], checked, seen)
        if name in self.env.consts:
            return True
        if name in self.env.package_vars:
            return self._all_trusted(("pkg", name), self.pkg_assign.get(name, []), checked, seen)
        return False

    def _trusted_field_path(self, node, checked, seen) -> bool:
        operand = node.child_by_field_name("operand")
        field_name = self.text(node.child_by_field_name("field"))
        if self.is_alias(operand):
            return field_name in ("Separator", "PathSeparator")
        fields = [field_name]
        base = _strip(operand)
        while base is not None and base.type == "selector_expression":
            fields.append(self.text(base.child_by_field_name("field")))
            base = _strip(base.child_by_field_name("operand"))
        if base is None or base.type != "identifier":
            return False
        base_name = self.text(base)
        if base_name == checked:
            return False
        receiver = self.frames[-1][2] if self.frames else ""
        base_ok = base_name == receiver or (
            base_name in self.env.package_vars and self._trusted_name(base_name, checked, seen)) or (
            bool(self.frames) and base_name in self.frames[-1][0]
            and self._trusted_name(base_name, checked, seen))
        if not base_ok:
            return False
        return all(self._all_trusted(("field", f), self.field_assign.get(f, []), checked, seen)
                   for f in fields)

    def _all_trusted(self, key, rhs_nodes, checked, seen) -> bool:
        if key in seen:
            return False
        seen = seen | {key}
        for rhs in rhs_nodes:
            if rhs == "zero":
                continue
            if rhs is None or not self.trusted(rhs, checked, seen):
                return False
        return True


# --------------------------------------------------------------------------- guards
class GuardTracker:
    def __init__(self, src: bytes, trust: TrustOracle, key_of: Callable,
                 arg_nodes: Callable, const_str: Callable, text: Callable):
        self.src, self.trust = src, trust
        self.key_of, self.arg_nodes, self.const_str, self.text = key_of, arg_nodes, const_str, text
        self.clear()

    # ---- state
    def clear(self) -> None:
        self.clauses: FrozenSet[Clause] = frozenset()
        self.emitted: Dict[str, FrozenSet[str]] = {}
        self.normalized: FrozenSet[str] = frozenset()
        self.url_src: Dict[str, str] = {}
        self.url_err: Dict[str, str] = {}
        self.rel_src: Dict[str, Tuple[Optional[str], str]] = {}
        self.rel_err: Dict[str, str] = {}

    def snapshot(self):
        return (self.clauses, dict(self.emitted), self.normalized, dict(self.url_src),
                dict(self.url_err), dict(self.rel_src), dict(self.rel_err))

    def restore(self, snap) -> None:
        if snap is None:
            self.clear()
            return
        (self.clauses, emitted, self.normalized, url_src, url_err, rel_src, rel_err) = snap
        self.emitted, self.url_src, self.url_err = dict(emitted), dict(url_src), dict(url_err)
        self.rel_src, self.rel_err = dict(rel_src), dict(rel_err)

    def join(self, snaps: list) -> None:
        live = [s for s in snaps if s is not None]
        if not live:
            self.clear()
            return
        first = live[0]
        clauses = first[0]
        normalized = first[2]
        emitted = dict(first[1])
        for s in live[1:]:
            clauses &= s[0]
            normalized &= s[2]
            emitted = {k: v & s[1][k] for k, v in emitted.items() if k in s[1]}
        maps = []
        for idx in (3, 4, 5, 6):
            merged = dict(first[idx])
            for s in live[1:]:
                merged = {k: v for k, v in merged.items() if s[idx].get(k) == v}
            maps.append(merged)
        self.clauses, self.emitted, self.normalized = clauses, emitted, normalized
        self.url_src, self.url_err, self.rel_src, self.rel_err = maps

    def kill(self, var: str) -> None:
        self.clauses = frozenset(c for c in self.clauses if all(l[0] != var for l in c))
        self.emitted.pop(var, None)
        self.normalized = self.normalized - {var}
        for m in (self.url_src, self.url_err, self.rel_err):
            for k in [k for k, v in m.items() if k == var or v == var]:
                del m[k]
        for k in [k for k, (_, p) in self.rel_src.items() if k == var or p == var]:
            del self.rel_src[k]

    # ---- assignments
    def on_assign(self, name: str, value_node) -> None:
        self.kill(name)
        value_node = _strip(value_node)
        if value_node is not None and value_node.type == "call_expression" \
                and self.key_of(value_node) in NORMALIZING_KEYS:
            self.normalized = self.normalized | {name}

    def on_multi_assign(self, names: List[str], value_node) -> None:
        value_node = _strip(value_node)
        if value_node is None or value_node.type != "call_expression" or len(names) < 2:
            return
        key = self.key_of(value_node)
        args = self.arg_nodes(value_node)
        first, err = names[0], names[1]
        if key in NORMALIZING_KEYS and first != "_":
            self.normalized = self.normalized | {first}
        if key in _URL_PARSE and args and _strip(args[0]).type == "identifier":
            s = self.text(_strip(args[0]))
            if first != "_":
                self.url_src[first] = s
            if err != "_":
                self.url_err[err] = s
        if key == "path/filepath.Rel" and len(args) == 2 and _strip(args[1]).type == "identifier":
            p = self.text(_strip(args[1]))
            root = self.text(args[0]) if self.trust.trusted(args[0], checked=p) else None
            if first != "_":
                self.rel_src[first] = (root, p)
            if err != "_":
                self.rel_err[err] = p

    # ---- conditions
    def on_branch(self, cond_node, truth: bool) -> Dict[str, Set[str]]:
        added = frozenset(c for c in self._cnf(cond_node, truth) if c != _UNKNOWN)
        self.clauses = self.clauses | added
        out: Dict[str, Set[str]] = {}
        for var in {l[0] for c in self.clauses for l in c if l[0]}:
            new = self.sanitized_kinds(var) - set(self.emitted.get(var, frozenset()))
            if new:
                out[var] = new
                self.emitted[var] = frozenset(set(self.emitted.get(var, frozenset())) | new)
        return out

    def implies(self, *lits: Literal) -> bool:
        allowed = frozenset(lits)
        return any(c <= allowed for c in self.clauses)

    def _cnf(self, node, truth: bool) -> List[Clause]:
        node = _strip(node)
        if node is None:
            return [_UNKNOWN]
        if node.type == "unary_expression" and self._op(node) == "!":
            return self._cnf(node.child_by_field_name("operand"), not truth)
        if node.type == "binary_expression" and self._op(node) in ("&&", "||"):
            left = self._cnf(node.child_by_field_name("left"), truth)
            right = self._cnf(node.child_by_field_name("right"), truth)
            conjunctive = (self._op(node) == "&&") == truth
            if conjunctive:
                return left + right
            product = [a | b for a in left for b in right]
            return product if len(product) <= _MAX_CLAUSES else [_UNKNOWN]
        return self._atom(node, truth)

    def _op(self, node) -> str:
        op = node.child_by_field_name("operator")
        return self.text(op) if op is not None else ""

    def _var(self, node) -> Optional[str]:
        node = _strip(node)
        return self.text(node) if node is not None and node.type == "identifier" else None

    def _url_vars(self, u: str) -> List[str]:
        return [u] + ([self.url_src[u]] if u in self.url_src else [])

    def _host_var(self, node) -> Optional[str]:
        """`u.Host` or `u.Hostname()` where u came from url.Parse."""
        node = _strip(node)
        if node is None:
            return None
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "selector_expression" \
                    and self.text(fn.child_by_field_name("field")) == "Hostname":
                return self._var(fn.child_by_field_name("operand"))
        if node.type == "selector_expression" and self.text(node.child_by_field_name("field")) == "Host":
            return self._var(node.child_by_field_name("operand"))
        return None

    def _clauses(self, vars_: List[str], atom: str, arg: str, pol: bool) -> List[Clause]:
        return [frozenset({(v, atom, arg, pol)}) for v in vars_]

    def _atom(self, node, truth: bool) -> List[Clause]:
        t = node.type
        if t == "call_expression":
            return self._call_atom(node, truth)
        if t == "binary_expression" and self._op(node) in ("==", "!="):
            return self._compare_atom(node, truth)
        if t == "index_expression":
            host_u = self._host_var(node.child_by_field_name("index"))
            if host_u and self.trust.trusted(node.child_by_field_name("operand")):
                return self._clauses(self._url_vars(host_u), "host_allowed", "", truth)
        return [_UNKNOWN]

    def _call_atom(self, node, truth: bool) -> List[Clause]:
        key = self.key_of(node)
        args = self.arg_nodes(node)
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "selector_expression" \
                and self.text(fn.child_by_field_name("field")) == "IsAbs":
            u = self._var(fn.child_by_field_name("operand"))
            if u in self.url_src:
                return self._clauses(self._url_vars(u), "url_abs", "", truth)
        v0 = self._var(args[0]) if args else None
        if key == "path/filepath.IsLocal" and v0:
            return self._clauses([v0], "is_local", "", truth)
        if key == "strings.HasPrefix" and v0 and len(args) == 2:
            return self._prefix_atom(v0, args[1], truth)
        if key in ("strings.Contains", "strings.ContainsAny", "strings.ContainsRune") and v0 and len(args) == 2:
            needle = self.const_str(args[1])
            if needle is None and _strip(args[1]).type == "rune_literal":
                needle = literal_value(_strip(args[1]), self.src)
            if needle is None:
                return [_UNKNOWN]
            atoms = []
            if key == "strings.Contains" and needle == "..":
                atoms.append("has_dotdot")
            if "\\" in needle:
                atoms.append("has_bs")
            if key == "strings.ContainsAny" and {"\t", "\n", "\r"} <= set(needle):
                atoms.append("has_ctrl")
            if not atoms:
                return [_UNKNOWN]
            if truth:
                return [frozenset((v0, a, "", True) for a in atoms)]
            return [frozenset({(v0, a, "", False)}) for a in atoms]
        if key == "strings.ContainsFunc" and v0 and len(args) == 2 \
                and self.text(args[1]) == "unicode.IsControl":
            return self._clauses([v0], "has_ctrl", "", truth)
        if key == "slices.Contains" and len(args) == 2:
            host_u = self._host_var(args[1])
            if host_u and self.trust.trusted(args[0]):
                return self._clauses(self._url_vars(host_u), "host_allowed", "", truth)
        return [_UNKNOWN]

    def _prefix_atom(self, v: str, prefix_node, truth: bool) -> List[Clause]:
        const = self.const_str(prefix_node)
        if v in self.rel_src:                       # HasPrefix(rel, "..") / (rel, ".."+sep)
            p = self.rel_src[v][1]
            if const == "..":
                return self._clauses([p], "rel_prefix", "..", truth)
            node = _strip(prefix_node)
            if node is not None and node.type == "binary_expression" and self._op(node) == "+" \
                    and self.const_str(node.child_by_field_name("left")) == ".." \
                    and self.text(node.child_by_field_name("right")) in _SEPARATOR_TEXTS:
                return self._clauses([p], "rel_prefix", "..sep", truth)
            return [_UNKNOWN]
        if const in ("/", "//", "/\\"):
            return self._clauses([v], "prefix", const, truth)
        node = _strip(prefix_node)
        if node is not None and node.type == "binary_expression" and self._op(node) == "+":
            root = node.child_by_field_name("left")
            sep = node.child_by_field_name("right")
            if self.text(sep) in _SEPARATOR_TEXTS and self.trust.trusted(root, checked=v):
                return self._clauses([v], "prefix_sep", self.text(root), truth)
        return [_UNKNOWN]

    def _compare_atom(self, node, truth: bool) -> List[Clause]:
        left = _strip(node.child_by_field_name("left"))
        right = _strip(node.child_by_field_name("right"))
        equal = (self._op(node) == "==") == truth          # does equality hold?
        for a, b in ((left, right), (right, left)):
            av = self._var(a)
            if b is not None and b.type == "nil" and av:
                if av in self.url_err:
                    return self._clauses([self.url_err[av]], "url_err", "", not equal)
                if av in self.rel_err:
                    return self._clauses([self.rel_err[av]], "rel_err", "", not equal)
            host_u = self._host_var(a)
            if host_u:
                c = self.const_str(b)
                if c == "" and a.type == "selector_expression":
                    return self._clauses(self._url_vars(host_u), "url_host_nonempty", "", not equal)
                if c and self.trust.trusted(b):
                    return self._clauses(self._url_vars(host_u), "host_allowed", "", equal)
            if av in self.rel_src and self.const_str(b) == "..":
                return self._clauses([self.rel_src[av][1]], "rel_eq_dotdot", "", equal)
            if av and b is not None and self.trust.trusted(b, checked=av):
                return self._clauses([av], "eq_root", self.text(b), equal)
        return [_UNKNOWN]

    # ---- rules
    def sanitized_kinds(self, v: str) -> Set[str]:
        imp = self.implies
        kinds: Set[str] = set()
        if v in self.normalized:
            roots = {l[2] for c in self.clauses for l in c
                     if l[0] == v and l[1] in ("eq_root", "prefix_sep") and l[3]}
            if any(imp((v, "eq_root", r, True), (v, "prefix_sep", r, True)) for r in roots):
                kinds.add(FS)
            rel_ok = any(p == v and root is not None for (root, p) in self.rel_src.values())
            if rel_ok and imp((v, "rel_err", "", False)) and (
                    imp((v, "rel_prefix", "..", False))
                    or (imp((v, "rel_prefix", "..sep", False)) and imp((v, "rel_eq_dotdot", "", False)))):
                kinds.add(FS)
        if imp((v, "is_local", "", True)):
            kinds.add(FS)
        no_bs = imp((v, "has_bs", "", False))
        no_ctrl = imp((v, "has_ctrl", "", False)) or imp((v, "url_err", "", False))
        if imp((v, "prefix", "/", True)) and imp((v, "prefix", "//", False)) and no_bs and no_ctrl:
            kinds.add(REDIRECT)
        if (imp((v, "url_err", "", False)) and imp((v, "url_abs", "", False))
                and imp((v, "url_host_nonempty", "", False)) and no_bs):
            kinds.add(REDIRECT)
        if imp((v, "host_allowed", "", True)):
            kinds |= {REDIRECT, SSRF}
        return kinds
```

- [ ] **Step 5: Wire the hooks into `GoFrontend`**

In `frame/sil/frontends/go_frontend.py` add imports:

```python
import re
from frame.sil.instructions import Sanitize, SinkKind
from frame.sil.frontends._go_guards import GuardTracker, TrustOracle
```

Replace the Task 4 hook stubs (`_before_lowering`, `_on_branch`, `_on_assign`, `_on_multi_assign`, `_on_function_start`, `_on_function_end`, `_facts_snapshot`, `_facts_restore`, `_facts_join`, `_facts_clear`, `_adjust_site_spec`) with:

```python
    def _before_lowering(self, root) -> None:
        self._trust = TrustOracle(root, self._src, self._env, key_of=self._call_key,
                                  is_alias=self._is_package_alias, text=self._t)
        self._guards = GuardTracker(self._src, self._trust, key_of=self._call_key,
                                    arg_nodes=self._arg_nodes, const_str=self._const_str,
                                    text=self._t)

    def _on_branch(self, cond_node, truth: bool, node: Node) -> None:
        for var, kinds in sorted(self._guards.on_branch(cond_node, truth).items()):
            node.add_instr(Sanitize(loc=self._loc(cond_node), var=PVar(var),
                                    sanitizes=[SinkKind(k) for k in sorted(kinds)],
                                    description="Go guard: " + self._t(cond_node)[:80]))

    def _on_assign(self, name: str, value_node) -> None:
        self._guards.on_assign(name, value_node)

    def _on_multi_assign(self, names: List[str], value_node) -> None:
        self._guards.on_multi_assign(names, value_node)

    def _on_function_start(self, node, receiver_name: str, param_names: Set[str]) -> None:
        self._trust.enter(node, receiver_name, param_names)

    def _on_function_end(self) -> None:
        self._trust.leave()

    def _facts_snapshot(self):
        return self._guards.snapshot() if hasattr(self, "_guards") else None

    def _facts_restore(self, snap) -> None:
        if hasattr(self, "_guards"):
            self._guards.restore(snap)

    def _facts_join(self, snaps) -> None:
        if hasattr(self, "_guards"):
            self._guards.join(snaps)

    def _facts_clear(self) -> None:
        if hasattr(self, "_guards"):
            self._guards.clear()

    def _adjust_site_spec(self, key: str, spec: Optional[ProcSpec], arg_nodes, arg_exps):
        spec = self._base_adjust_site_spec(key, spec, arg_nodes)
        if key in ("path/filepath.Join", "path.Join") and len(arg_nodes) == 2 \
                and self._trust.trusted(arg_nodes[0]):
            second = arg_nodes[1]
            dotdot_free = second.type == "identifier" and self._guards.implies(
                (self._t(second), "has_dotdot", "", False))
            if self._is_rooted_clean(second) or dotdot_free:
                return ProcSpec(is_sanitizer=["filesystem"], taint_propagates=[0, 1],
                                description="Go: path confined under a trusted root")
        if spec is not None and spec.is_sink in ("redirect", "ssrf") and spec.sink_args:
            idx = spec.sink_args[0]
            if idx < len(arg_nodes) and self._fixed_destination(spec.is_sink, arg_nodes[idx]):
                return replace(spec, is_sink=None, sink_args=[])
        return spec

    def _is_rooted_clean(self, node) -> bool:
        if node.type != "call_expression" or self._call_key(node) not in (
                "path/filepath.Clean", "path.Clean"):
            return False
        args = self._arg_nodes(node)
        arg = args[0] if args else None
        return (arg is not None and arg.type == "binary_expression" and self._op(arg) == "+"
                and self._const_str(arg.child_by_field_name("left")) == "/")

    def _const_prefix(self, node) -> Tuple[str, bool]:
        """(constant prefix, whole expression constant?)."""
        whole = self._const_str(node)
        if whole is not None:
            return whole, True
        if node.type == "parenthesized_expression" and node.named_children:
            return self._const_prefix(node.named_children[0])
        if node.type == "binary_expression" and self._op(node) == "+":
            left, left_full = self._const_prefix(node.child_by_field_name("left"))
            if not left_full:
                return left, False
            right, right_full = self._const_prefix(node.child_by_field_name("right"))
            return left + right, right_full
        if node.type == "call_expression" and self._call_key(node) == "fmt.Sprintf":
            args = self._arg_nodes(node)
            fmt_s = self._const_str(args[0]) if args else None
            if fmt_s is not None:
                cut = fmt_s.find("%")
                return (fmt_s, True) if cut < 0 else (fmt_s[:cut], False)
        return "", False

    def _fixed_destination(self, kind: str, node) -> bool:
        prefix, full = self._const_prefix(node)
        if full:
            return False                    # constant: carries no taint anyway
        if kind == "ssrf":
            return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+/", prefix) is not None
        return (len(prefix) >= 2 and prefix[0] == "/" and prefix[1] not in "/\\"
                and "?" in prefix)
```

Also: `_lower_function` stores `_save()` before `_on_function_start`; nothing else changes. Note `_begin_proc` calls `_facts_clear()`, which is why the `hasattr` guards exist (package init runs after `_before_lowering`, so they are true from then on).

- [ ] **Step 6: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_taint.py tests/test_go_frontend.py -v`
Expected: all PASS. For a failing twin, print the procedure and its `Sanitize` instrs (debug snippet from Task 4 Step 5) and check which literal of the rule is missing; fix the atom extraction, not the rule. For a failing bypass, the rule is too weak: tighten it and add a unit test that pins the literal set.

- [ ] **Step 7: Full suite and commit**

Run: `.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3`
Expected: no new failures against the baseline.

```bash
git add frame/sil/frontends/_go_guards.py frame/sil/frontends/go_frontend.py tests/test_go_taint.py tests/test_go_frontend.py
git commit -m "Go frontend: guard facts, trusted-root provenance, complete sanitizer rules

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Sink matrix completion and structural detectors on Go

Closes every remaining sink row of spec § "Sinks" with a vulnerable/twin pair, and pins the language-agnostic detectors' behaviour on Go (spec § "Loops and the structural detectors").

**Files:**
- Test: `tests/test_go_taint.py` (append)
- Modify (only if a test fails): `frame/sil/specs/go_specs.py`, `frame/sil/frontends/go_frontend.py`

**Interfaces:**
- Consumes: Tasks 3–6. Produces nothing new.

- [ ] **Step 1: Write the tests**

Append to `tests/test_go_taint.py`:

```python
# ---- remaining sink rows ---------------------------------------------------------
def test_sqlx_select_fires_and_param_twin_is_silent():
    imports = '"net/http"\n"github.com/jmoiron/sqlx"'
    extra = "var db *sqlx.DB"
    assert "CWE-89" in _cwes(_handler(
        'var out []string\ndb.Select(&out, "SELECT * FROM t WHERE n = \'"+r.FormValue("n")+"\'")',
        imports, extra))
    assert "CWE-89" not in _cwes(_handler(
        'var out []string\ndb.Select(&out, "SELECT * FROM t WHERE n = ?", r.FormValue("n"))',
        imports, extra))


def test_gorm_raw_and_where():
    imports = '"net/http"\n"gorm.io/gorm"'
    extra = "var db *gorm.DB"
    assert "CWE-89" in _cwes(_handler('db.Raw("SELECT * FROM t WHERE n = " + r.FormValue("n"))', imports, extra))
    assert "CWE-89" in _cwes(_handler('db.Where("name = \'" + r.FormValue("n") + "\'").Find(nil)', imports, extra))
    assert "CWE-89" not in _cwes(_handler('db.Where("name = ?", r.FormValue("n")).Find(nil)', imports, extra))


def test_command_context_and_shell_retarget():
    imports = '"context"\n"net/http"\n"os/exec"'
    assert "CWE-78" in _cwes(_handler(
        'exec.CommandContext(context.Background(), r.FormValue("c"))', imports))
    assert "CWE-78" in _cwes(_handler('exec.Command("sh", "-c", r.FormValue("c"))', imports))
    assert "CWE-78" not in _cwes(_handler('exec.Command("sh", "-c", "ls -l", r.FormValue("c"))', imports))
    assert "CWE-78" not in _cwes(_handler('exec.Command("git", "log", r.FormValue("c"))', imports))


def test_servefile_and_http_dir():
    imports = '"net/http"'
    assert "CWE-22" in _cwes(_handler('http.ServeFile(w, r, r.URL.Query().Get("f"))', imports))
    assert "CWE-22" in _cwes(_handler('_ = http.FileServer(http.Dir(r.FormValue("d")))', imports))


def test_framework_redirects():
    assert "CWE-601" in _cwes('''package main
import "github.com/gin-gonic/gin"
func h(c *gin.Context) { c.Redirect(302, c.Query("next")) }''')
    assert "CWE-601" in _cwes('''package main
import "github.com/labstack/echo/v4"
func h(c echo.Context) error { return c.Redirect(302, c.QueryParam("next")) }''')


def test_ssrf_request_constructors():
    imports = '"context"\n"net/http"'
    assert "CWE-918" in _cwes(_handler('http.NewRequest("GET", r.FormValue("u"), nil)', imports))
    assert "CWE-918" in _cwes(_handler(
        'http.NewRequestWithContext(context.Background(), "GET", r.FormValue("u"), nil)', imports))
    assert "CWE-918" in _cwes(_handler('c := &http.Client{}\nc.Get(r.FormValue("u"))', imports))


def test_strings_repeat_alloc():
    assert "CWE-770" in _cwes(_handler(
        'n, _ := strconv.Atoi(r.FormValue("n"))\n_ = strings.Repeat("a", n)',
        '"net/http"\n"strconv"\n"strings"'))


def test_fiber_source_and_unmarshal_out_param():
    assert "CWE-78" in _cwes('''package main
import ("github.com/gofiber/fiber/v2"; "os/exec")
func h(c *fiber.Ctx) error { exec.Command(c.Query("x")); return nil }''')
    assert "CWE-78" in _cwes(_handler(
        'body, _ := io.ReadAll(r.Body)\nvar in struct{ C string }\njson.Unmarshal(body, &in)\nexec.Command(in.C)',
        '"encoding/json"\n"io"\n"net/http"\n"os/exec"'))


def test_builder_receiver_mutation():
    assert "CWE-89" in _cwes(_handler(
        'var b strings.Builder\nb.WriteString("SELECT * FROM t WHERE n = ")\n'
        'b.WriteString(r.FormValue("n"))\ndb.Query(b.String())',
        '"database/sql"\n"net/http"\n"strings"', "var db *sql.DB"))


def test_library_mode_exported_params():
    src = '''package lib
import "os/exec"
func Run(cmd string) { exec.Command(cmd).Run() }
func run(cmd string) { exec.Command(cmd).Run() }'''
    assert "CWE-78" not in _cwes(src)
    result = FrameScanner(language="go", verify=False, library_mode=True).scan(src, "t.go")
    procs = {v.procedure for v in result.vulnerabilities if v.cwe_id == "CWE-78"}
    assert procs == {"go:Run"}


# ---- structural detectors on Go ------------------------------------------------------
def test_daemon_loop_is_not_cwe_835():
    src = '''package main
import "net"
func serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil { continue }
		go handle(c)
	}
}
func handle(c net.Conn) {}'''
    assert "CWE-835" not in _cwes(src)


def test_recursion_with_base_case_is_silent():
    src = '''package main
func fact(n int) int { if n <= 1 { return 1 }; return n * fact(n-1) }'''
    assert "CWE-674" not in _cwes(src)


def test_recursion_without_base_case_fires():
    src = '''package main
func loop(n int) int { return loop(n + 1) }'''
    assert "CWE-674" in _cwes(src)


def test_hardcoded_secret_scan_runs_on_go():
    assert "CWE-798" in _cwes('package main\nconst apiKey = "sk_live_51HxQ8rT9vYdZ3kP"\n')
    assert "CWE-798" not in _cwes('package main\nconst greeting = "hello there, friend"\n')
```

- [ ] **Step 2: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_taint.py -v`
Expected: all PASS. If one fails, it is a gap in the frontend or the tables, not in the test. Fix the cause and keep the assertion:
- missing sink: the resolved key is wrong. Print `_call_key` for the call, then fix `RESULT_TYPES` / `FIELD_TYPES` or the spec key.
- missing source: check `SERVER_CONTEXT_TYPES` against `type_of`'s canonical path (e.g. `/v2` dropped).
- CWE-674 not firing: check that the self-call is emitted as `go:loop` inside procedure `go:loop`.
- CWE-798 not firing: check the package-level const reaches `go:$package` as an `Assign` to `PVar("apiKey")`.

- [ ] **Step 3: Full suite and commit**

Run: `.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3`

```bash
git add tests/test_go_taint.py frame/sil/specs/go_specs.py frame/sil/frontends/go_frontend.py
git commit -m "Go frontend: complete sink matrix and structural-detector fixtures

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Scanner integration: file discovery, exclusions, CLI, LLM coverage

**Files:**
- Modify: `frame/sil/scanner.py` (`scan_file` ext map ~line 988 and read ~line 1010; module `scan_file` map ~line 1870; `scan_directory` loop ~line 1057; `_apply_llm_detect` gate ~line 926)
- Modify: `frame/sil/cli.py` (help text ~line 49)
- Test: `tests/test_go_scanner.py`, `tests/test_go_llm_coverage.py`

**Interfaces:**
- Produces: `skip_go_file(path: Path, root: Path) -> bool` in `frame.sil.scanner`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_go_scanner.py`:

```python
"""Go file discovery, exclusions and file-level robustness in FrameScanner."""

from pathlib import Path

from frame.sil import FrameScanner
from frame.sil.scanner import skip_go_file

VULN = '''package main
import ("net/http"; "os/exec")
func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")).Run() }
'''


def test_skip_rules(tmp_path: Path):
    files = {
        "main.go": VULN,
        "vendor/x/a.go": VULN,
        "pkg/testdata/b.go": VULN,
        "third_party/c.go": VULN,
        "main_test.go": VULN,
        "api.pb.go": VULN,
        "zz_generated.deepcopy.go": VULN,
        "store_mock.go": VULN,
        "gen.go": "// Code generated by stringer; DO NOT EDIT.\n\n" + VULN,
    }
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    kept = {rel for rel in files if not skip_go_file(tmp_path / rel, tmp_path)}
    assert kept == {"main.go"}


def test_directory_scan_uses_exclusions(tmp_path: Path):
    (tmp_path / "main.go").write_text(VULN)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "v.go").write_text(VULN)
    results = FrameScanner(language="go", verify=False).scan_directory(str(tmp_path), "**/*.go")
    assert [Path(r.filename).name for r in results] == ["main.go"]
    assert "CWE-78" in {v.cwe_id for v in results[0].vulnerabilities}


def test_scan_file_detects_go_from_extension(tmp_path: Path):
    p = tmp_path / "main.go"
    p.write_text(VULN)
    result = FrameScanner(verify=False).scan_file(str(p))        # default language: python
    assert "CWE-78" in {v.cwe_id for v in result.vulnerabilities}


def test_scan_file_tolerates_crlf_bom_and_bad_bytes(tmp_path: Path):
    p = tmp_path / "main.go"
    p.write_bytes(b"\xef\xbb\xbf" + VULN.replace("\n", "\r\n").encode() + b"// \xff\xfe\r\n")
    result = FrameScanner(language="go", verify=False).scan_file(str(p))
    assert "CWE-78" in {v.cwe_id for v in result.vulnerabilities}


def test_explicit_scan_of_generated_file_still_analyses_it():
    src = "// Code generated by x; DO NOT EDIT.\n\n" + VULN
    result = FrameScanner(language="go", verify=False).scan(src, "gen.go")
    assert "CWE-78" in {v.cwe_id for v in result.vulnerabilities}
```

Create `tests/test_go_llm_coverage.py`:

```python
"""`--ai` coverage on Go must not shrink when the symbolic frontend lands.

Before the Go frontend, Go ran the LLM layer on every file under --ai. With a
frontend, _apply_llm_detect would gate on is_detection_candidate, whose patterns
do not know Go. Go therefore bypasses that gate. Stubbed LLM: no network.
"""

from types import SimpleNamespace

import frame.sil.llm_detect as llm_detect
import frame.sil.llm_triage as llm_triage
from frame.sil import FrameScanner


def _run(monkeypatch, language, src, filename):
    calls = []
    monkeypatch.setattr(llm_detect, "detect_agentic",
                        lambda *a, **k: calls.append(a) or [])
    monkeypatch.setattr(llm_triage, "LLMTriageClient", lambda config: SimpleNamespace())
    cfg = SimpleNamespace(base_url="http://127.0.0.1:9", model="stub", repo_root="")
    FrameScanner(language=language, verify=False, llm_detect=True,
                 llm_config=cfg).scan(src, filename)
    return calls


def test_go_file_without_symbolic_finding_still_reaches_llm(monkeypatch):
    src = 'package main\nimport "os/exec"\nfunc run(command string) { exec.Command(command).Run() }\n'
    assert len(_run(monkeypatch, "go", src, "run.go")) == 1


def test_go_file_with_symbolic_finding_reaches_llm(monkeypatch):
    src = ('package main\nimport ("net/http"; "os/exec")\n'
           'func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")) }\n')
    assert len(_run(monkeypatch, "go", src, "h.go")) == 1


def test_other_languages_keep_the_candidate_gate(monkeypatch):
    assert _run(monkeypatch, "python", "def f(x):\n    return x\n", "f.py") == []
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_go_scanner.py tests/test_go_llm_coverage.py -v`
Expected: FAIL: `ImportError: cannot import name 'skip_go_file'`, and `test_go_file_without_symbolic_finding_still_reaches_llm` gets 0 calls.

- [ ] **Step 3: Implement**

In `frame/sil/scanner.py`, after `is_generated_source` (module level) add:

```python
_GO_SKIP_DIRS = frozenset({"vendor", "testdata", "third_party"})
_GO_GENERATED_HEADER = re.compile(r"^// Code generated .* DO NOT EDIT\.\s*$", re.MULTILINE)


def skip_go_file(path: Path, root: Path) -> bool:
    """Go files a directory scan leaves out: vendored, test-data and
    third-party trees, tests, and generated code (the standard `// Code
    generated ... DO NOT EDIT.` header, with common generated filenames as a
    fast path). None of them is the project's attack surface, and in
    Kubernetes-scale repositories they dominate the file count."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    if any(p in _GO_SKIP_DIRS for p in parts[:-1]):
        return True
    name = path.name
    if (name.endswith("_test.go") or name.endswith(".pb.go")
            or name.startswith("zz_generated") or name.endswith("_mock.go")):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192).decode("utf-8", errors="replace")
    except OSError:
        return False
    return _GO_GENERATED_HEADER.search(head) is not None
```

In `FrameScanner.scan_directory`, replace

```python
            for filepath in dir_path.glob(pattern):
                if filepath.is_file():
```

with

```python
            for filepath in dir_path.glob(pattern):
                if filepath.is_file():
                    if filepath.suffix == ".go" and skip_go_file(filepath, dir_path):
                        continue
```

(keeping the existing body of the `if` indented under it).

In `FrameScanner.scan_file`, add `'.go': 'go',` to `ext_to_lang`, and replace

```python
        source_code = path.read_text(encoding='utf-8-sig')
```

with

```python
        # Go sources in the wild carry the odd invalid byte in comments or
        # string literals; tree-sitter recovers, so decode with replacement
        # rather than failing the whole file.
        errors = "replace" if path.suffix.lower() == ".go" else "strict"
        source_code = path.read_text(encoding='utf-8-sig', errors=errors)
```

In the module-level `scan_file`, add `".go": "go",` to `language_map`.

In `_apply_llm_detect`, replace

```python
        if self.frontend is not None and not is_detection_candidate(source_code, bool(vulns)):
            return vulns
```

with

```python
        # Go keeps the always-run behaviour it had before its frontend existed:
        # the candidate patterns are tuned for the other languages and would
        # silently drop Go files with no symbolic finding from the LLM pass.
        if (self.frontend is not None and self.language != "go"
                and not is_detection_candidate(source_code, bool(vulns))):
            return vulns
```

In `frame/sil/cli.py`, change the `--language` help to:

```python
        help="Source language (default: python). Symbolic frontends: python, "
             "javascript, typescript, java, c, cpp, csharp, go. Any other language "
             "(e.g. php, ruby, rust) runs LLM-detect only under --ai."
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_go_scanner.py tests/test_go_llm_coverage.py -v`
Expected: all PASS. If `test_go_file_with_symbolic_finding_reaches_llm` fails because a later step of `_apply_llm_detect` needs a real client attribute, add that attribute to the `SimpleNamespace` stub (e.g. `_explored=set()`), not a code change.

- [ ] **Step 5: CLI smoke check**

```bash
mkdir -p /tmp/gosmoke && printf '%s\n' 'package main' 'import ("net/http"; "os/exec")' 'func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")).Run() }' > /tmp/gosmoke/main.go
.venv/bin/python -m frame.sil.cli scan /tmp/gosmoke -l go -p "**/*.go" -f json | head -40
```

Expected: JSON with one CWE-78 finding in `main.go`.

- [ ] **Step 6: Full suite and commit**

Run: `.venv/bin/python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning 2>&1 | tail -3`

```bash
git add frame/sil/scanner.py frame/sil/cli.py tests/test_go_scanner.py tests/test_go_llm_coverage.py
git commit -m "Scanner: Go file discovery, exclusions, and unchanged --ai coverage

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Documentation and the VLoC measurement

The measurement is reported, not gated (spec § "Measurement"). Steps that call an LLM endpoint or download benchmark data **stop and ask the user first**; do not run them on your own.

**Files:**
- Modify: `benchmarks/vloc/README.md`
- Modify: `README.md` (language list, if it enumerates symbolic frontends)
- Create: `benchmarks/vloc/go_subset.py`

**Interfaces:**
- Produces: `python benchmarks/vloc/go_subset.py --workspace WS [--seed N] [--extra K]` printing comma-separated alpha ids for `run.py --only`.

- [ ] **Step 1: Write the subset selector with a test-by-run**

Create `benchmarks/vloc/go_subset.py`:

```python
"""Go task ids for a VLoC measurement run.

Every Go task in the prepared workspace whose CWEs are taint-shaped or CWE-770
(the subset Frame's Go frontend targets), plus a seeded random slice of the
remaining Go tasks, printed as the comma-separated list `run.py --only` takes.
"""

import argparse
import csv
import json
import random
from pathlib import Path

TARGET = {"CWE-22", "CWE-23", "CWE-89", "CWE-78", "CWE-77", "CWE-601", "CWE-74",
          "CWE-79", "CWE-918", "CWE-770"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--extra", type=int, default=20, help="random non-target Go tasks")
    args = ap.parse_args()
    ws = Path(args.workspace).expanduser()
    manifest = ws / "manifest_subset.csv"
    if not manifest.is_file():
        manifest = ws / "vulnerability-localization-benchmark" / "data" / "manifest.csv"
    rows = [r for r in csv.DictReader(manifest.open()) if r["ecosystem"].lower() == "go"]
    target = [r["alpha_id"] for r in rows if set(json.loads(r["cwes"] or "[]")) & TARGET]
    rest = sorted(r["alpha_id"] for r in rows if r["alpha_id"] not in set(target))
    random.Random(args.seed).shuffle(rest)
    print(",".join(sorted(target) + rest[: args.extra]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run: `.venv/bin/python benchmarks/vloc/go_subset.py --help`
Expected: usage text, exit 0.

- [ ] **Step 2: Update the docs**

In `benchmarks/vloc/README.md` change the coverage row to:

```
| go | 215 | yes (taint + CWE-770); rest LLM-only |
```

and append a section:

````markdown
## Go measurement (symbolic frontend)

The Go frontend targets the taint-shaped and CWE-770 Go tasks (about 45 plus
the CWE-770 slice of 44 resource tasks); the rest of the Go set stays LLM-only.
Measure it in three runs over the same task ids:

`run.py` launches `sys.executable -m frame.sil.cli` with the extracted snapshot
as its working directory and discards stdout, so a wrong interpreter or a
missing `PYTHONPATH` makes every scan fail silently and look like "no
findings". Always run it with an interpreter that has tree-sitter, and point
`PYTHONPATH` at the checkout being measured:

```bash
PY=/path/to/frame/.venv/bin/python
IDS=$($PY benchmarks/vloc/go_subset.py --workspace "$WS" --extra 20)
# 1. LLM-only baseline: a checkout of main from BEFORE the Go frontend
(cd ../frame-main && PYTHONPATH=$PWD $PY benchmarks/vloc/run.py --workspace "$WS" --out "$OUT/go-baseline" --only "$IDS")
# 2. symbolic only, this branch (baseline: zero findings, TNR 1.0)
PYTHONPATH=$PWD $PY benchmarks/vloc/run.py --workspace "$WS" --out "$OUT/go-symbolic" --only "$IDS" --no-ai
# 3. symbolic + LLM, this branch
PYTHONPATH=$PWD $PY benchmarks/vloc/run.py --workspace "$WS" --out "$OUT/go-ai" --only "$IDS"
$PY benchmarks/vloc/score.py --workspace "$WS" --results "$OUT/go-symbolic"
```

Every Phase B finding in run 2 is a false positive on patched code; triage
each one. Because Go bypasses the LLM candidate gate, runs 1 and 3 call the
LLM on the same files, so their difference isolates the symbolic layer and
sink grounding.
````

If `README.md` lists the symbolic-frontend languages, add Go to that list with the same scope note ("taint + CWE-770").

- [ ] **Step 3: Commit docs**

```bash
git add benchmarks/vloc/go_subset.py benchmarks/vloc/README.md README.md
git commit -m "VLoC: Go subset selector and measurement runbook

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: STOP: ask the user before measuring**

Ask, verbatim in substance:
1. "The baseline must run on `main` before this branch merges, and it calls your LLM endpoint (`FRAME_LLM_*`). How many tasks should the prepared sample contain (`prepare.py --sample N`; the full set is 15 GB), and may I run it now?"
2. "May I run the timing probe (one Kubernetes-scale snapshot, `--no-ai`) first?"

Do nothing further in this task until the user answers.

- [ ] **Step 5: Timing probe (after approval)**

`run.py` runs the scanner as `sys.executable -m frame.sil.cli` from inside the snapshot directory and discards its stdout. Bare `python` on this machine is `/usr/bin/python`, which has no tree-sitter, and without `PYTHONPATH` the snapshot directory cannot import `frame` at all. Either mistake makes every scan fail silently and look like "no findings". So pin the interpreter and the checkout, and verify both before trusting any number:

```bash
export WS=/tmp/frame-vloc OUT=/tmp/vloc-results
export PY="$PWD/.venv/bin/python" PYTHONPATH="$PWD"
(cd /tmp && $PY -c "import frame, frame.sil.frontends as f; print(frame.__file__, getattr(f, 'GO_FRONTEND_AVAILABLE', 'absent'))")
```

Expected: a path inside this worktree and `True`. Then:

```bash
$PY benchmarks/vloc/prepare.py --workspace "$WS" --sample <N from the user>
K8S=$($PY -c '
import csv, os
rows = list(csv.DictReader(open(os.path.join(os.environ["WS"], "manifest_subset.csv"))))
go = [r for r in rows if r["ecosystem"].lower() == "go"]
k8s = [r for r in go if r["repo_full_name"] == "kubernetes/kubernetes"]
pick = k8s[0] if k8s else max(go, key=lambda r: float(r["vulnerable_unzip_kb"] or 0))
print(pick["alpha_id"])')
time $PY benchmarks/vloc/run.py --workspace "$WS" --out "$OUT/probe" --only "$K8S" --phases a --no-ai
$PY -c '
import glob, json, os, sys
files = glob.glob(os.path.join(os.environ["OUT"], "probe", "*_phase_a.json"))
if not files:
    sys.exit("probe produced no output JSON: the scan did not run")
data = json.load(open(files[0]))
errors = data.get("errors") or []
print(json.dumps({k: data[k] for k in data if k != "findings"}, indent=1)[:2000])
if errors:
    sys.exit("probe reported errors: %s" % errors[:3])'
```

Report the wall-clock time and the files scanned versus skipped. Any exit from the checker above is a failed probe. Do not proceed to Step 6 until it passes.

- [ ] **Step 6: Baseline on main (after approval)**

```bash
git worktree add ../frame-main main
IDS=$($PY benchmarks/vloc/go_subset.py --workspace "$WS" --extra 20)
(cd ../frame-main && export PYTHONPATH="$PWD" \
  && (cd /tmp && $PY -c "import frame, frame.sil.frontends as f; print(frame.__file__, getattr(f, 'GO_FRONTEND_AVAILABLE', 'absent'))") \
  && $PY benchmarks/vloc/run.py --workspace "$WS" --out "$OUT/go-baseline" --only "$IDS")
git worktree remove ../frame-main
```

The check line must print a path inside `../frame-main` and `absent`: that is the proof the baseline ran without the Go frontend. Any other output means stop.

- [ ] **Step 7: Branch runs and report**

With `PYTHONPATH="$PWD"` exported in this worktree (re-run the Step 5 check: this worktree's path and `True`), run runs 2 and 3 from the README section, then score all three, and report File F1 and TNR for the target subset and for the whole sampled Go set, plus the triage of every Phase B finding from run 2. Record the numbers in `benchmarks/vloc/README.md` under the Go measurement section and commit:

```bash
git add benchmarks/vloc/README.md
git commit -m "VLoC: Go frontend measurement

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
