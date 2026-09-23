# Go symbolic frontend (taint + CWE-770): design

Date: 2026-09-23
Status: approved in brainstorming, pending written-spec review

## Goal

Give Go source files sound symbolic findings through the same pipeline the other
languages use (tree-sitter → SIL → `SILTranslator`), instead of the LLM-only
fallback they get today (`FrameScanner._get_frontend` returns `None` for Go).

Scope of this milestone: **taint/injection sinks plus CWE-770 tainted allocation
size**. Separation-logic heap detectors (the C/C++ Phase 1–4 work) are not part of
it.

### Success criteria

- **Gate:** every vulnerable fixture in `tests/test_go_taint.py` fires with the
  correct CWE; every patched twin is silent; the full existing test suite passes
  unchanged.
- **Measured, reported, not gated:** VLoC Go File F1 and Phase B TNR, symbolic-only
  and `--ai`, against an LLM-only baseline captured on `main` before merge
  (see Measurement).

### Why VLoC is not the gate

The pinned VLoC manifest has 215 Go tasks. Only 45 are injection-shaped
(CWE-22: 17, CWE-89: 7, CWE-78/77: 7, CWE-601: 5, CWE-74: 5, other) and 44 are
resource tasks (CWE-400: 32, CWE-770: 9, CWE-789: 3), of which only the tainted
allocation-size slice is taint-shaped. The rest (CWE-20, CWE-200, authz,
races) is outside taint analysis. The top repositories (kubernetes, cert-manager,
cilium, fabric, go-ethereum) mostly receive attacker data through API objects,
CRDs and gRPC messages rather than `*http.Request`. A per-file, net/http-rooted
frontend is expected to move File F1 modestly; the measurement says by how much.

## Approach

Per-file tree-sitter frontend with a syntactic type environment (approach A).
Go declares parameter, receiver, field and most variable types in source, so a
per-file import table and type table give package-qualified call resolution
without a Go toolchain. Rejected for now: a `go/ssa` helper binary (needs a Go
toolchain and module resolution, which fails offline on many VLoC snapshots, and
breaks the pure-Python pattern). Package-level cross-file summaries are the next
phase (see Phase B).

## Architecture

```
.go file ──tree-sitter-go──► GoFrontend ──► SIL Program(language="go") ──► SILTranslator ──► findings
                                  ▲
                        per-file GoEnv (built first):
                          • imports: alias → package path
                          • types:   declared var/param/field/receiver types
                        go_specs.py: ProcSpec table + Go lowering hints
```

### New files

| File | Purpose |
|------|---------|
| `frame/sil/frontends/go_frontend.py` | `GoFrontend.translate(source, filename) -> Program` |
| `frame/sil/frontends/_go_env.py` | Import alias table and syntactic type table; standalone so Phase B reuses it |
| `frame/sil/specs/go_specs.py` | `GO_SPECS` (`ProcSpec`s, package-qualified keys) and Go lowering-hint tables |
| `tests/test_go_frontend.py` | Lowering unit tests |
| `tests/test_go_taint.py` | End-to-end vulnerable / patched-twin fixtures |

### Edited files

- `requirements.txt`, `pyproject.toml`: add `tree-sitter-go`. Pin a version
  only after confirming `Language(tree_sitter_go.language())` loads under the
  installed `tree-sitter` binding; fall back to the newest 0.23.x that does.
- `frame/sil/frontends/__init__.py`, `frame/sil/specs/__init__.py`: try/except
  import with `GO_FRONTEND_AVAILABLE`, matching the other languages.
- `frame/sil/scanner.py`: `"go"` branch in `_get_frontend` (honours
  `library_mode`, as the JS frontend does); `.go` in both extension maps
  (around lines 995 and 1877); Go directory-scan exclusions.
- `frame/cli.py` (extension map near line 517) and `frame/sil/cli.py` (help text
  near line 51 that lists Go as LLM-only).
- `benchmarks/vloc/README.md`: coverage row for `go`.

### Translator gates

- Go stays out of `_is_c_lang`: no C heap detectors run.
- Go stays out of `_IMPLICIT_RECEIVER_LANGUAGES`: Go methods are always called
  through an explicit receiver.
- No change to translator semantics.

### Spec resolution: frontend resolves, translator matches exactly

`Program.get_spec` falls back to suffix and method-name matching with Java/Python
prefixes. For Go that is a false-positive source (`.Query` exists on `sql.DB` and
`url.URL`). Therefore:

1. The frontend resolves each call against `GO_SPECS` using the import and type
   tables, yielding a package-qualified key such as `database/sql.DB.Query`.
2. It emits the `Call` with a `recv.Method` function name (this shape keeps the
   translator's receiver → return propagation working) and registers the
   resolved `ProcSpec` under that exact name in the program's own copy of
   `library_specs`.
3. `GO_SPECS` keys are package-qualified, so an unresolved call can never
   suffix-match a spec.
4. If the same emitted name resolves to different types within one file, the
   frontend registers nothing for it (abstains): the call gets default
   propagation and no sink.

### `--ai` behaviour change

`_apply_llm_detect` calls `collect_sinks(program)`. Go files will now supply a
`Program`, so the LLM layer receives sink hints and `--ai` output on Go changes.
This is why the baseline is captured before merge.

## Lowering Go to SIL

Follows the Java/Python frontends' conventions; Go-specific decisions below.

### Procedures

- `func F` → procedure `F`. `func (s *Server) H` → procedure `Server.H`, receiver
  is param 0 with its declared type.
- Function literals become their own procedures, named `Outer$func1`,
  `Outer$func2`, ... in source order. In the enclosing procedure the literal is a
  function-value constant. Handler registrations such as
  `http.HandleFunc("/", func(w, r) {...})` depend on this.
- Captured variables are not propagated into literals. The literal's typed
  parameters still act as sources. This is a documented recall gap.

### Multi-value results

`v, err := f()` → one `Call` into temp `$t`, then `Assign lhs_i = $t` for each
non-blank LHS. Exception: an LHS whose declared or inferred type is `error`, or
which is named `err` in the trailing position, receives a fresh untainted value,
so `err.Error()` does not become a false-positive source. `_` is dropped.
`v, ok := m[k]` and `v, ok := x.(T)` lower the same way with `ok` untainted.

### Statements

- `if`, `switch`, type switch, `for` (three-clause, condition-only, infinite,
  `range`) → `Prune` edges carrying the real condition expression, so the
  existing feasibility check and the CWE-770 bounded-branch check see them.
- `range` over a tainted value taints the key and value variables.
- `go f(x)` and `defer f(x)` → an ordinary call at the statement's position
  (arguments are evaluated there, matching Go semantics).
- `return`, `panic`, `os.Exit`, `log.Fatal*` terminate the path; the latter three
  reuse the Phase 1 no-return modelling.
- `select` → nondeterministic branch over its cases.
- `goto`, labelled `break` and `continue` resolve to their targets.

### Expressions

- Call chains, selectors and index expressions (`r.URL.Query().Get("id")`)
  flatten into temps.
- String `+` propagates; `fmt.Sprintf`, `strings.Join` and similar propagate via
  spec `taint_propagates`.
- Conversions (`string(b)`, `[]byte(s)`), composite literals (from their fields)
  and `&x` propagate.

### Go lowering hints (in `go_specs.py`, applied by the frontend)

| Hint | Examples | Lowering |
|------|----------|----------|
| Out-param | `json.Unmarshal(data, &v)`, `(*json.Decoder).Decode(&v)`, `fmt.Sscanf`, gin/echo `c.Bind*` / `ShouldBind*` | extra `Assign v = $ret` |
| Receiver mutation | `strings.Builder.WriteString`, `bytes.Buffer.Write*`, `url.Values.Set` / `Add` | `Assign recv = recv + arg` |
| Guard validator | see Sanitizers | `Sanitize(var, kinds)` at the start of the guarded continuation |
| Non-propagating accessor | `r.Context()`, `r.Method`, `r.TLS`, `c.Request.Context()` | result is untainted |

Guard placement: for `if <guard> { return | continue | panic | ...; return }`,
the `Sanitize` goes at the start of the continuation after the `if`. For the
positive form `if <validated> { use }`, it goes at the start of the then-branch.

### Same-file interprocedural flow

Mirrors the Java frontend's fixpoint (`java_frontend.py`, around line 280): a
tainted argument passed to a same-file function or method taints that parameter
via a `TaintSource` at the callee's entry. Return taint already flows through the
translator's default propagation for unknown calls. Cross-file flow is Phase B.

### Parse errors

Tree-sitter recovers from them. Lowering skips `ERROR` nodes. A file with no
procedures yields an empty `Program`; the frontend never raises on user code.
Unsupported constructs lower to an opaque `Call` with default propagation.

## Sources, sinks, sanitizers

All map onto existing `TaintKind` / `SinkKind` values. This is the complete
milestone-1 set.

### Sources

- **Typed parameters:** any parameter or receiver declared `*http.Request` /
  `http.Request`, `*gin.Context` / `gin.Context`, `echo.Context`, `*fiber.Ctx`
  gets `TaintSource(USER_INPUT)` at procedure entry. Receiver → return
  propagation then covers `r.FormValue`, `r.URL.Query().Get`, `r.Header.Get`,
  `r.Body`, `r.URL.Path`, `r.PathValue`, `c.Query`, `c.Param` and the like,
  subject to the non-propagating accessor table.
- **Explicit:** `mux.Vars(r)`, `chi.URLParam(r, ...)` (listed for clarity);
  `os.Args`, `os.Getenv` as `ENV_VAR` (same convention as C `getenv`);
  `bufio.Reader.ReadString` / `bufio.Scanner.Text` over `os.Stdin` as
  `USER_INPUT`.
- **`library_mode`:** parameters of exported functions typed `string`, `[]byte`
  or `io.Reader` are tainted. Off by default.

### Sinks

Bracketed numbers are the sink argument index.

| CWE | SinkKind | APIs |
|-----|----------|------|
| 89 | `SQL_QUERY` | `database/sql` `DB` / `Tx` / `Conn`: `Query`, `QueryRow`, `Exec`, `Prepare` [0]; their `*Context` variants [1]. `sqlx`: `Select`, `Get` [1]; `Queryx`, `MustExec` [0]. `gorm`: `Raw`, `Exec` [0]; `Where`, `Order`, `Group` when arg 0 is a non-constant string |
| 78 | `SHELL_COMMAND` | `exec.Command` [0]; `exec.CommandContext` [1]; `syscall.Exec` [0]. For `exec.Command("sh"\|"bash", "-c", x)` the frontend retargets the sink to `x` |
| 22 | `FILE_PATH` | `os.Open`, `OpenFile`, `Create`, `ReadFile`, `WriteFile`, `Remove`, `RemoveAll`, `Mkdir`, `MkdirAll`, `Rename`; `ioutil.ReadFile`, `WriteFile` [0]; `http.ServeFile` [2]; `os.DirFS`, `http.Dir` [0] |
| 601 | `REDIRECT` | `http.Redirect` [2]; gin / echo `c.Redirect` [1] |
| 918 | `SSRF` | `http.Get`, `Head`, `Post`, `PostForm` [0]; `http.NewRequest` [1]; `http.NewRequestWithContext` [2]; `(*http.Client).Get`, `Post` [0] |
| 79 | `HTML_OUTPUT` | `template.HTML`, `template.JS`, `template.URL`, `template.HTMLAttr` conversions [0] only |
| 770 | `ALLOC_SIZE` | `make([]T, n)` [len and cap]; `strings.Repeat`, `bytes.Repeat` [1] |

Deliberate exclusions: parameter arguments of parameterized queries;
`exec.Command("git", tainted...)` (CWE-88, out of scope); `os.Root` and its
methods (traversal-resistant); writes to `http.ResponseWriter` (XSS precision
risk, deferred).

### Sanitizers

Return-value sanitizers:

| API | Clean for |
|-----|-----------|
| `filepath.Base`, `securejoin.SecureJoin` | `FILE_PATH` |
| `html.EscapeString`, `template.HTMLEscapeString` | `HTML_OUTPUT` |
| `url.QueryEscape`, `url.PathEscape` | `REDIRECT`, `SSRF` |
| `strconv.Atoi`, `ParseInt`, `ParseUint`, `ParseBool`, `ParseFloat` | `SQL_QUERY`, `SHELL_COMMAND`, `FILE_PATH`, `REDIRECT`, `SSRF`, `HTML_OUTPUT`; taint **kept** for `ALLOC_SIZE` |
| `filepath.Clean` / `path.Clean` of a `"/" + x` concatenation (constant `/` prefix) | `FILE_PATH` |

`filepath.Clean` / `path.Clean` in any other form are not sanitizers
(`Clean("../x")` keeps the `..`).

The `strconv` row needs per-sink-kind sanitization combined with propagation. The
first implementation task verifies the translator supports that combination and
adjusts the spec encoding if it does not.

Guard validators (lowered to `Sanitize` per the lowering section):

| Guard | Clean for |
|-------|-----------|
| `strings.HasPrefix(p, base)` (typically after `Clean` / `Abs` / `Join`) | `FILE_PATH` |
| `filepath.IsLocal(p)` | `FILE_PATH` |
| `!strings.Contains(p, "..")` | `FILE_PATH` |
| `filepath.Rel(base, p)` then `!strings.HasPrefix(rel, "..")` | `FILE_PATH` |
| `u.IsAbs()` / `u.Host != ""` rejected; `u.Hostname()` compared to an allowed value | `REDIRECT` |
| `strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")` | `REDIRECT` |
| `if n > K { return }` (or `n < K` on the continuation) | `ALLOC_SIZE`, through the existing bounded-branch check; no hint needed |

Each guard gets a patched-twin fixture.

## Directory-scan scope (Go only)

Skipped in directory scans, next to the existing minified-file detection:

- anything under `vendor/`, `testdata/`, `third_party/`;
- `*_test.go`;
- generated files: the `// Code generated ... DO NOT EDIT.` header, with
  `*.pb.go`, `zz_generated*.go`, `*_mock.go` as fast filename checks.

`scan()` on an explicitly supplied file still analyses it.

## Error handling

The frontend never raises on user code (see Parse errors). A frontend exception
is caught by `scan()`'s existing handler, recorded in `result.errors`, and the
file yields no findings.

## Testing

`tests/test_go_frontend.py` (lowering):

- import alias table and type table;
- multi-value results, including the untainted `err`;
- function literals as procedures; method receivers;
- out-param and receiver-mutation hints; guard → `Sanitize` placement;
- `go` / `defer`, `range`, `switch`, `select`;
- parse-error recovery.

`tests/test_go_taint.py` (end to end through `FrameScanner(language="go")`):

- for every sink row, a vulnerable fixture that must fire with the right CWE and
  at least one patched twin that must not (parameterized query; `Base` /
  `SecureJoin` / `HasPrefix` / `IsLocal` guard; URL host check; `Atoi` before
  SQL; bounded `make`);
- shapes: handler function literal; same-file helper flow; `json.Decode` into a
  struct; gin and echo handlers; aliased import (`osexec "os/exec"`); a `.Query`
  call on a non-SQL type that must not fire.

Regression: the full existing suite passes unchanged; non-Go results do not move.

## Measurement (reported, not gated)

1. **Baseline, before merge, on `main`:** VLoC `--ai` on a Go-only stratified
   sample (the taint + CWE-770 subset plus a random slice of the remaining Go
   tasks). Records the LLM-only Go baseline, which does not exist yet. Needs the
   user's LLM endpoint; the exact command and sample size are confirmed with the
   user before running.
2. **Timing probe:** one kubernetes-scale snapshot, no `--ai`; report wall clock
   and files skipped versus scanned before any full-subset run.
3. **After:** symbolic-only run (no `--ai`), whose baseline is exactly zero
   findings and TNR 1.0, so every Phase B finding is a visible false positive to
   triage; then an `--ai` run compared with step 1.
4. Report File F1 and TNR for the subset and the whole Go sample. Update the VLoC
   README coverage row to `go | 215 | yes (taint + CWE-770); rest LLM-only`.

## Phase B (next phase, not built here)

Package-level summaries: scan all non-excluded `.go` files of a package together,
build per-function summaries (param → return, param → sink, param → out-param)
using `_go_env`, and apply them at call sites across files; imported in-repo
packages after that. Enters with evidence from this milestone's VLoC measurement
that cross-file flow is where recall is lost.

Also deferred, each needing its own decision: closure capture;
`http.ResponseWriter` XSS; sources from Kubernetes API objects, CRDs and gRPC
messages; `io.ReadAll(r.Body)` and decompression-bomb CWE-400; CWE-88 argument
injection.
