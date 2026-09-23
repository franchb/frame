# Go symbolic frontend (taint + CWE-770): design

Date: 2026-09-23
Status: revised after written-spec review (rev 4), pending re-review

## Goal

Give Go source files sound symbolic findings through the same pipeline the other
languages use (tree-sitter → SIL → `SILTranslator`), instead of the LLM-only
fallback they get today (`FrameScanner._get_frontend` returns `None` for Go).

Scope of this milestone: **taint/injection sinks plus CWE-770 tainted allocation
size**. Separation-logic heap detectors (the C/C++ Phase 1–4 work) are not part of
it.

### Success criteria

- **Gate:** every vulnerable fixture and every sanitizer-bypass fixture in
  `tests/test_go_taint.py` fires with the correct CWE; every patched twin is
  silent; the `--ai` coverage tests pass; the full existing test suite passes
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
.go file ──tree-sitter-go──► GoFrontend ──► SIL Program(language="go",       ──► SILTranslator ──► findings
                                  ▲           exact_spec_lookup=True,
                                  │           per-procedure summaries)
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
| `frame/sil/frontends/_go_guards.py` | Guard-fact analysis for sanitization (see Sanitizers) |
| `frame/sil/frontends/_go_summaries.py` | Same-file procedure summaries (see Same-file interprocedural flow); Phase B extends it to packages |
| `frame/sil/specs/go_specs.py` | `GO_SPECS` (`ProcSpec`s, package-qualified keys) and Go lowering-hint tables |
| `tests/test_go_frontend.py` | Lowering, guard-fact and summary unit tests |
| `tests/test_go_taint.py` | End-to-end vulnerable / patched-twin / bypass fixtures |
| `tests/test_go_llm_coverage.py` | `--ai` coverage on Go files with no symbolic finding |

### Edited files

- `requirements.txt`, `pyproject.toml`: add `tree-sitter-go`. Pin a version
  only after confirming `Language(tree_sitter_go.language())` loads under the
  installed `tree-sitter` binding; fall back to the newest 0.23.x that does.
- `frame/sil/frontends/__init__.py`, `frame/sil/specs/__init__.py`: try/except
  import with `GO_FRONTEND_AVAILABLE`, matching the other languages.
- `frame/sil/procedure.py`: `Program.exact_spec_lookup` flag (see Spec
  resolution). Default `False`; no other language changes behaviour.
- `frame/sil/translator.py`: `_is_noreturn_call` returns `False` when the
  program's language is `go` (see Termination). Gated; no other language
  changes behaviour.
- `frame/sil/scanner.py`: `"go"` branch in `_get_frontend` (honours
  `library_mode`, as the JS frontend does); `.go` in both extension maps
  (around lines 995 and 1877); Go directory-scan exclusions; the LLM candidate
  gate change (see LLM coverage).
- `frame/cli.py` (extension map near line 517) and `frame/sil/cli.py` (help text
  near line 51 that lists Go as LLM-only).
- `benchmarks/vloc/README.md`: coverage row for `go`.

### Translator gates

- Go stays out of `_is_c_lang`: no C heap detectors run.
- Go stays out of `_IMPLICIT_RECEIVER_LANGUAGES`: Go methods are always called
  through an explicit receiver.
- The only translator edit is the Go gate in `_is_noreturn_call`.

### Spec resolution: frontend resolves, lookup is exact

`Program.get_spec` falls back, after an exact miss, to suffix matching, to a
hard-coded list of Java/Python type prefixes (`bytes`, `connection`,
`statement`, ...) and to the bare method name. Package-qualified keys do not
close those paths: `custom.Repeat` reaches `bytes.Repeat` through the `bytes`
prefix, and a resolved SQL call registered as `connection.Query` would make any
unrelated `x.Query` match through the `connection` prefix. Therefore:

1. `Program` gains `exact_spec_lookup: bool = False`. When `True`, `get_spec`
   returns the user-procedure spec for a same-file procedure name, else an exact
   `library_specs` hit, else `None`. No suffix, prefix or bare-name fallback.
   The Go frontend sets it to `True`.
2. The Go program's `library_specs` does **not** contain `GO_SPECS`. It contains
   only the specs the frontend resolved for call sites in this file.
3. **Registered names are unique per call site, so a registration can never
   match another call.** A file-global name such as `x.Query` is unsafe even with
   conflict detection: one function's `x` may be a `*sql.DB` that resolves while
   another function's `x` has an unsupported external type that does not, and
   both calls would share the registration. So:
   - **Resolved method call** (`db.Query(q)` with `db` typed `*sql.DB`): the
     frontend emits `Assign $rN = db` into a fresh site-unique temp, then the
     `Call` with function name `$rN.Query`, and registers the resolved
     `ProcSpec` under `$rN.Query`. The `recv.Method` shape keeps the
     translator's receiver → return propagation working, and `$rN` carries
     `db`'s taint through the `Assign`.
   - **Resolved package function** (`exec.Command(x)`, `osexec.Command(x)`):
     emitted and registered under a canonical name in a reserved namespace,
     `go:os/exec.Command`. The `go:` prefix cannot come from Go source.
   - **Same-file function** `F`: the procedure is named `go:F`, and calls that
     resolve to it are emitted as `go:F`, so `get_spec` finds the procedure's
     own summary spec directly. **Same-file method** `Server.H`: the procedure
     is named `go:Server.H`; a call `s.H(x)` that resolves to it is emitted as
     `$rN.H` through a site-unique temp, with the callee's summary registered
     under `$rN.H`. The name `_exec_call` looks up (`Call.get_full_name()`) is
     therefore always the registered key.
   - **Unresolved call:** emitted under its source text (`x.Query`, `F` through
     a shadowing local). Source text never starts with `$` or `go:`, so with
     exact lookup it cannot equal any registered key or procedure name. It gets
     the translator's default unknown-call propagation (arguments and receiver
     taint the result) and no sink.
4. Because every key is site-unique or canonical, no conflict detection is
   needed. The into-callee fixpoint uses the same resolution.

Tests: `x.Repeat(n)` on a non-`bytes`/`strings` receiver and `x.Query(s)` on a
non-SQL receiver in the same file as a resolved SQL call both produce no sink;
two functions that each call `x.Query(s)`, one with `x` typed `*sql.DB` and one
with `x` of an unsupported external type, produce exactly one CWE-89 finding
(in the first);
for a same-file method call `s.H(x)`, `program.get_spec(instr.get_full_name())`
returns `Server.H`'s summary.

### LLM coverage (`--ai`)

Today Go has no frontend, so `_apply_llm_detect` skips the
`is_detection_candidate` gate and always runs the LLM under `--ai`. Adding a
frontend would activate that gate, and `_CANDIDATE_RE` has no Go patterns: a
file such as `func run(command string) { exec.Command(command).Run() }`, whose
source lives in another file, has no symbolic finding and would silently lose
the LLM pass it gets today.

Decision: for Go, `_apply_llm_detect` bypasses `is_detection_candidate`, exactly
preserving today's `--ai` coverage. Tuning a Go-aware candidate heuristic is
deferred until the VLoC measurement shows the cost is worth cutting.

Other `--ai` changes are intended: `collect_sinks(program)` now receives a Go
`Program`, and explored files are translated for cross-file grounding. Grounding
only promotes a finding to `llm_verified`; ungrounded findings are still added,
so nothing is dropped. One existing rule now applies to Go: an LLM finding whose
CWE already has a symbolic finding in the same file is not duplicated (the file
is still reported). Repository-scale detection (`detect_repo`) has no frontend
or candidate gate and is unchanged. This is why the baseline is captured before
merge.

Tests (`tests/test_go_llm_coverage.py`, stub LLM client, no network): a Go file
with no symbolic finding and no `_CANDIDATE_RE` match still invokes detection
under `--ai`; a file with a symbolic finding still gets both tiers.

## Lowering Go to SIL

Follows the Java/Python frontends' conventions; Go-specific decisions below.

### Procedures

- `func F` → procedure `go:F`. `func (s *Server) H` → procedure `go:Server.H`,
  receiver is param 0 with its declared type. The `go:` namespace is explained
  in Spec resolution.
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
- `select` → nondeterministic branch over its cases.
- `goto`, labelled `break` and `continue` resolve to their targets.

### Immediate, deferred and asynchronous calls

Go evaluates the arguments of `defer f(x)` and `go f(x)` at the statement, but
runs the call later (defer) or concurrently (go). Lowering keeps the three
apart:

- **Immediate** `f(x)`: an ordinary `Call` in place.
- **Deferred** `defer f(x)`: arguments are evaluated into fresh temps at the
  `defer` statement. The `Call` on those temps is emitted at every normal exit of
  the procedure (at each `return` after its operands are evaluated, at fall-off
  end, and on `panic` paths), in LIFO order of registration. Not on `os.Exit` /
  `log.Fatal*` paths, which do not run deferred calls in Go. A `defer` inside a
  loop is lowered once (one registration, one emitted call per exit).
- **Asynchronous** `go f(x)`: arguments are evaluated into fresh temps; the
  `Call` is emitted in place (so sinks inside it and taint into its callee are
  seen) but never terminates the caller's path.

### Termination

The frontend owns path termination structurally. After an immediate call to
`panic`, `os.Exit`, `log.Fatal*` / `log.Panic*`, or `runtime.Goexit`, the node's
only successor is the procedure exit (via the deferred calls where Go runs them,
per above), and the rest of the block is unreachable. Deferred and asynchronous
calls to those functions do not terminate anything at their statement.

Because termination is structural, the translator's name-based
`_is_noreturn_call` is disabled for Go. Its C list includes `exit` and `err`,
which are ordinary Go identifiers and would otherwise cut paths wrongly.

Tests: `defer os.Exit(0); exec.Command(u).Run()` fires CWE-78; `go os.Exit(0)`
followed by a sink fires; `if bad { os.Exit(1) }` still clears the guarded path.

### Expressions

- Call chains, selectors and index expressions (`r.URL.Query().Get("id")`)
  flatten into temps.
- String `+` propagates; `fmt.Sprintf`, `strings.Join` and similar propagate via
  spec `taint_propagates`.
- Conversions (`string(b)`, `[]byte(s)`), composite literals (from their fields)
  and `&x` propagate.
- The builtins `len` and `cap` return untainted values. Otherwise
  `make([]byte, len(body))`, present in nearly every Go file that reads a body,
  becomes a CWE-770 false positive. A twin fixture asserts it.

### Loops and the structural detectors

The shared translator's language-agnostic detectors now run on Go. Per
detector:

- **CWE-835 (non-terminating loop):** fires only where a frontend sets
  `loop_body_can_exit = False`. The Go frontend never sets it (leaves `None`),
  so it cannot fire on Go. `for { conn, _ := l.Accept(); go handle(conn) }`
  and `for { select { ... } }` worker loops are idiomatic Go, and
  `loop_exit.py`'s exit set does not cover Go's `panic` / `os.Exit` calls.
  Fixture: a daemon accept loop stays silent.
- **CWE-674 (uncontrolled recursion):** left on. A self-call to a function
  `F` is emitted as `go:F` inside procedure `go:F`, so it is recognised. A
  method self-call is emitted through a site-unique `$rN.H` temp and is not
  recognised, so the detector abstains on method recursion (recall loss only). Fixtures: a recursive function
  with a base case stays silent; one without fires.
- **Hardcoded-secret literal scan:** left on (it is language-agnostic by
  design). Fixtures: a credential-shaped `const` fires; an ordinary string
  constant does not.
- **Spec-driven structural detectors** (CWE-252, CWE-732, CWE-789): inert,
  because no Go spec sets `return_must_be_checked`, `permission_mode_arg` or
  `stack_allocation_size_arg` in this milestone.

### Go lowering hints (in `go_specs.py`, applied by the frontend)

| Hint | Examples | Lowering |
|------|----------|----------|
| Out-param | `json.Unmarshal(data, &v)`, `(*json.Decoder).Decode(&v)`, `fmt.Sscanf`, gin/echo `c.Bind*` / `ShouldBind*` | extra `Assign v = $ret` |
| Receiver mutation | `strings.Builder.WriteString`, `bytes.Buffer.Write*`, `url.Values.Set` / `Add` | `Assign recv = recv + arg` |
| Non-propagating accessor | `r.Context()`, `r.Method`, `r.TLS`, `c.Request.Context()`; gin/echo `c.Get`, `c.MustGet`, `c.GetString` (values set server-side by middleware) | result is untainted |

Guard-based sanitization is not a per-call hint; it is the guard-fact analysis
in Sanitizers.

### Same-file interprocedural flow

Two directions, both needed:

- **Into callees.** Mirrors the Java frontend's fixpoint (`java_frontend.py`,
  around line 280): a tainted argument passed to a same-file function or method
  taints that parameter via a `TaintSource` at the callee's entry, so sinks inside
  the callee fire.
- **Out of callees.** `Program.get_spec` returns a same-file procedure's own
  `ProcSpec`, which is a default, empty, truthy spec unless someone fills it, so
  `_exec_call` never reaches the unknown-call propagation branch and
  `identity(r.FormValue("cmd"))` loses its taint. No frontend fills it today.
  `_go_summaries.py` computes one for every Go procedure:
  - `taint_propagates`: the parameter indices whose values may reach a `return`
    value (flow-insensitive def-use over the procedure's lowered SIL, through
    assignments, propagating calls and the default unknown-call rule);
    `taint_from_receiver` likewise for a method receiver;
  - `is_sanitizer`: the sink kinds for which **every** parameter-to-return flow
    passes a sanitizer for that kind (an intersection; one unsanitized flow
    empties it). This keeps same-file helpers like
    `func safe(p string) string { return filepath.Base(p) }` from re-tainting
    their result. The translator's sanitizer handling records per-kind
    sanitization on the result and still propagates taint, so
    `exec.Command(safe(x))` keeps firing (a fixture asserts it);
  - `is_source`: set when a `return` value may come from a source inside the
    procedure that is not a parameter (for example a handler-shaped function
    returning a value derived from its own request parameter when called with
    untainted arguments). The entry `TaintSource`s inserted by the into-callee
    fixpoint are excluded from this computation, so the fixpoint cannot feed
    itself.
  - Order: callees before callers; a recursive cycle, or a procedure the
    analysis cannot follow, gets the conservative summary (all parameters and
    the receiver propagate, no sanitizer kinds). Every Go procedure gets an
    explicit summary; none keeps the empty default.

Tests: `identity(r.FormValue("cmd"))` into `exec.Command` fires;
`safe(r.FormValue("f"))` into `os.Open` does not; a helper that returns a
constant does not propagate; mutual recursion falls back to conservative.

### Parse errors

Tree-sitter recovers from them. Lowering skips `ERROR` nodes. A file with no
procedures yields an empty `Program`; the frontend never raises on user code.
Unsupported constructs lower to an opaque `Call` with default propagation.

## Sources, sinks, sanitizers

All map onto existing `TaintKind` / `SinkKind` values. This is the complete
milestone-1 set.

### Sources

Milestone 1 roots taint only in server request handlers (plus `library_mode`).
The measured repositories are full of HTTP *client* code and CLIs, where the
same types and APIs carry trusted data.

- **Handler-shaped `*http.Request` parameters:** a parameter declared
  `*http.Request` / `http.Request` gets `TaintSource(USER_INPUT)` at procedure
  entry only when the procedure is handler-shaped:
  - its signature also has an `http.ResponseWriter` parameter; or
  - it is a method named `ServeHTTP`; or
  - it is a function literal or a same-file function identifier passed as the
    handler argument of a route registration (`http.HandleFunc`,
    `(*http.ServeMux).HandleFunc` / `Handle` with `http.HandlerFunc(...)`,
    gorilla/chi `HandleFunc` / `Get` / `Post` / ..., gin/echo route methods).

  Client-side uses such as `RoundTrip(req *http.Request)` and request builders
  are not sources. Helpers that receive a tainted request from a handler are
  still covered by the into-callee fixpoint.
- **Server context types:** a parameter declared `*gin.Context` /
  `gin.Context`, `echo.Context` or `*fiber.Ctx` is a source; these types exist
  only on the server side.
- Receiver → return propagation then covers `r.FormValue`, `r.URL.Query().Get`,
  `r.Header.Get`, `r.Body`, `r.URL.Path`, `r.PathValue`, `c.Query`, `c.Param`
  and the like, subject to the non-propagating accessor table. `mux.Vars(r)` and
  `chi.URLParam(r, ...)` return taint through their argument.
- **`library_mode`:** parameters of exported functions typed `string`, `[]byte`
  or `io.Reader` are tainted. Off by default.
- **Not sources in this milestone:** `os.Args`, `os.Getenv` and `os.Stdin`
  reads. `_filter_by_confidence` does not discount environment sources, and in
  operator and CLI repositories they would make `os.Open(os.Args[1])` a CWE-22
  finding on code whose caller is the trusted operator. Deferred with the CLI
  threat model.

### Sinks

Bracketed numbers are the sink argument index.

| CWE | SinkKind | APIs |
|-----|----------|------|
| 89 | `SQL_QUERY` | `database/sql` `DB` / `Tx` / `Conn`: `Query`, `QueryRow`, `Exec`, `Prepare` [0]; their `*Context` variants [1]. `sqlx`: `Select`, `Get` [1]; `Queryx`, `MustExec` [0]. `gorm`: `Raw`, `Exec` [0]; `Where`, `Order`, `Group` when arg 0 is a non-constant string |
| 78 | `SHELL_COMMAND` | `exec.Command` [0]; `exec.CommandContext` [1]; `syscall.Exec` [0]. For `exec.Command("sh"\|"bash", "-c", x)` the frontend retargets the sink to `x` |
| 22 | `FILE_PATH` | `os.Open`, `OpenFile`, `Create`, `ReadFile`, `WriteFile`, `Remove`, `RemoveAll`, `Mkdir`, `MkdirAll`, `Rename`; `ioutil.ReadFile`, `WriteFile` [0]; `http.ServeFile` [2]; `os.DirFS`, `http.Dir` [0] |
| 601 | `REDIRECT` | `http.Redirect` [2]; gin / echo `c.Redirect` [1] |
| 918 | `SSRF` | `http.Get`, `Head`, `Post`, `PostForm` [0]; `http.NewRequest` [1]; `http.NewRequestWithContext` [2]; `(*http.Client).Get`, `Post` [0] |
| 79 | `HTML_OUTPUT` | `template.HTML(x)` conversion [0] only |
| 770 | `ALLOC_SIZE` | `make([]T, n)` [len and cap]; `strings.Repeat`, `bytes.Repeat` [1] |

Deliberate exclusions: parameter arguments of parameterized queries;
`exec.Command("git", tainted...)` (CWE-88, out of scope); `os.Root` and its
methods (traversal-resistant); writes to `http.ResponseWriter` (XSS precision
risk, deferred); `template.JS`, `template.URL`, `template.CSS`,
`template.HTMLAttr` (HTML escaping does not make any of those contexts safe, and
this milestone has no context-specific sanitizer for them; they are deferred
rather than folded into `HTML_OUTPUT`, where `html.EscapeString` would wrongly
clear them).

### Sanitizers: principle

A sanitizer clears taint only for the sink kind whose threat it actually
removes. Encoders that protect a component's syntax (URL escaping, HTML
escaping) are not destination or confinement checks. Anything short of a
complete check (a prefix without a separator, a `..` scan without a root, an
`IsAbs` test without a host test) sanitizes nothing on its own. Every accepted
form below has a patched twin that must stay silent, and every rejected
near-miss listed has a bypass fixture that must still fire.

### Return-value sanitizers

| API | Clean for |
|-----|-----------|
| `filepath.Base` | `FILE_PATH` |
| `securejoin.SecureJoin(root, x)` | `FILE_PATH` |
| `filepath.Join(root, filepath.Clean("/" + x))` / the `path` equivalent, with `root` untainted (the complete trusted-root construction `http.Dir` uses) | `FILE_PATH` |
| `html.EscapeString`, `template.HTMLEscapeString` | `HTML_OUTPUT` (the `template.HTML` sink only) |
| `strconv.Atoi`, `ParseInt`, `ParseUint`, `ParseBool`, `ParseFloat` | `SQL_QUERY`, `SHELL_COMMAND`, `FILE_PATH`, `REDIRECT`, `SSRF`, `HTML_OUTPUT`; taint **kept** for `ALLOC_SIZE` |

Not sanitizers: `filepath.Clean` / `path.Clean` in any other form, including
`Clean("/" + x)` on its own (it roots the path but does not confine it:
`x = "etc/passwd"` gives `/etc/passwd`); `url.QueryEscape` / `url.PathEscape`
for any kind (they leave `169.254.169.254` and `evil.example` intact, so they do
not constrain a destination).

Translator behaviour this relies on, verified by reading `_exec_call` during
design review: a sanitizer spec records per-kind sanitization on the result
(`add_sanitization`) and still propagates taint from argument 0, so a result is
clean for the listed kinds and tainted for the rest; receiver propagation reads
the receiver from the emitted `recv.Method` name. The first implementation task
turns this into tests, adding three points not yet confirmed: (a) the later
`taint_propagates` step in the same call does not erase the recorded
sanitization; (b) `ALLOC_SIZE` still fires on an `Atoi` result; (c) a
`Sanitize` on `p` carries over through `q := p`. If any fails, the spec encoding
is adjusted before the frontend is built on it.

### Constant-prefix destinations

These replace the rejected URL-escaper sanitizers for the common safe shape. At
a `REDIRECT` or `SSRF` sink, if the argument is written inline (a `+`
concatenation or an `fmt.Sprintf` with a constant format) and its constant
prefix fixes the destination, the frontend does not emit the sink:

- `SSRF`: the constant prefix contains `scheme://host/`, with the authority
  terminated by `/` before any non-constant part (`"https://api.example/v1?q=" + x`
  is fixed; `"https://" + x` and `"https://api.example" + x` are not).
- `REDIRECT`: the constant prefix starts with `/` followed by a character that
  is neither `/` nor `\`, **and** contains a `?` before the non-constant part
  (`"/search?q=" + x` is fixed). A constant path prefix alone is not enough:
  `http.Redirect` path-cleans a relative destination, so `"/safe/" + x` with
  `x = "../\\evil.example"` becomes `Location: /\evil.example`, which browsers
  resolve to an external host (reproduced with `httptest` on Go 1.27.1). The
  query is not cleaned, so a `?` in the constant part pins the path. A `#` does
  not help (`"/p#/../\\evil"` also becomes `/\evil`).

A prefix reached through an intermediate variable is not recognised in this
milestone (recall loss, not a precision loss).

### Guard facts

`_go_guards.py` derives facts about a variable from conditions that dominate a
use, and emits `Sanitize(var, kinds)` only when the accumulated facts satisfy a
complete rule for a kind.

- **Where facts come from:** the negation of an early-exit guard's condition
  (`if cond { return | continue | panic | ...; return }`) holds in the
  continuation; a positive condition holds in its then-branch. `&&`, `||` and
  `!` decompose normally, and facts accumulate across several sequential guards.
- **What kills facts:** any reassignment of the variable drops its facts. At a
  join of two non-terminating branches, only facts established on both survive.
- **Normalized:** a variable is *normalized* if its reaching definition is the
  result of `filepath.Clean`, `filepath.Abs` or `filepath.Join` (which cleans), or
  the `path` equivalents.
- **Trusted (untainted) root or allowlist:** lowering runs before taint
  analysis, so trust is decided from in-file reaching definitions, never from
  the storage location alone. An expression is trusted if it is:
  - a constant (literal or `const`);
  - a local whose every reaching definition is trusted;
  - a package-level variable, or a field path on a receiver or struct value
    (`s.root`, `s.cfg.Root`), whose every assignment **anywhere in this file**
    (including its initializer and any assignment to a prefix of the path, such
    as `s.cfg = ...`) has a trusted right-hand side.

  An assignment whose right-hand side references a source-typed parameter, a
  `library_mode`-tainted parameter, a call result from one, or the variable
  being checked makes it untrusted, and so does anything the rules above cannot
  classify. Untrusted means the rule does not apply (the finding stays).
  Example: after `s.root = r.FormValue("root")` anywhere in the file,
  `filepath.Join(s.root, filepath.Clean("/" + f))` is not sanitized.

  Residual risk, stated: an assignment to the same package variable or field
  from another file of the package is not visible to a per-file frontend. Phase B
  (package scope) closes it by running the same check over every file of the
  package. This definition is used by every "root" and "allowlist" below and by
  the Join/Clean return-value sanitizer.

Rules (the `Sanitize` is emitted at the first point where the rule holds):

| Kind | Rule (all parts required) |
|------|---------------------------|
| `FILE_PATH` | `p` normalized **and** a component-aware containment check against an untainted root: `p == root \|\| strings.HasPrefix(p, root + string(filepath.Separator))` (or `+ "/"`); a bare `strings.HasPrefix(p, root)` is not enough (`/srv/www-secret` passes `HasPrefix(.., "/srv/www")`) |
| `FILE_PATH` | `rel, err := filepath.Rel(root, p)` with `root` untainted and `p` normalized, **and** a rejection of `err != nil`, of `rel == ".."`, and of `strings.HasPrefix(rel, ".." + sep)` (or the stricter `HasPrefix(rel, "..")`) |
| `FILE_PATH` | `filepath.IsLocal(p)` (rejects absolute paths, `..` escapes and reserved names by definition, so `p` stays under the working directory or under any root it is joined to) |
| `FILE_PATH` | `!strings.Contains(p, "..")` **only** when the sink argument is `filepath.Join(root, p)` with `root` untainted (Join keeps an absolute `p` under `root`, and without `..` it cannot climb out). With the sink taking `p` directly, it sanitizes nothing (`/etc/passwd` has no `..`) |
| `REDIRECT` | a relative-path check that survives `http.Redirect`'s path cleaning and browser URL parsing: `strings.HasPrefix(s, "/")` **and** rejection of `strings.HasPrefix(s, "//")` **and** of a backslash **anywhere** in `s` (`strings.Contains(s, "\\")`; rejecting only a leading `/\` is not enough, since cleaning can bring a later backslash to the front) **and** of ASCII control characters anywhere in `s` (`/\t/evil.example` is sent unchanged and browsers strip the tab, giving `//evil.example`). The control-character part is also met by a rejected `url.Parse(s)` error, since `url.Parse` refuses control characters |
| `REDIRECT` | for `u, err := url.Parse(s)`: rejection of `err != nil` (refuses control characters) **and** of `u.IsAbs()` **and** of `u.Host != ""` (catches `//evil.example`, which has no scheme so `IsAbs` is false) **and** of a backslash anywhere in `s` (catches `/\evil.example` and `/safe/../\evil.example`, which Go parses with an empty host but which clean to, or browsers resolve to, an external host) **and** of a `//` prefix on `s` (`strings.HasPrefix(s, "//")`; catches `///evil.example`, which Go parses with `Host == ""`, `IsAbs() == false` and no error, but which browsers resolve to `evil.example` -- echo's `c.Redirect` writes `Location` unchanged) |
| `REDIRECT`, `SSRF` | host allowlist: `u.Hostname()` (or `u.Host`) compared equal to an untainted constant, or checked for membership in an untainted map/slice, with the failing branch rejecting |
| `ALLOC_SIZE` | any `if n > K { return }` bound (or `n < K` on the continuation), through the existing bounded-branch check; no guard fact needed |

### Sanitizer fixtures

Each accepted form above gets a patched twin that must not fire. These
bypasses must still fire:

| Bypass | Must fire |
|--------|-----------|
| `os.ReadFile(filepath.Clean("/" + x))` | CWE-22 |
| `p := filepath.Clean(x); if !strings.HasPrefix(p, "/srv/www") { return }; os.ReadFile(p)` | CWE-22 |
| `if strings.Contains(x, "..") { return }; os.ReadFile(x)` | CWE-22 |
| `http.Get("http://" + url.QueryEscape(host) + "/latest/meta-data/")` | CWE-918 |
| `if u.IsAbs() { return }; http.Redirect(w, r, s, 302)` with `s = "//evil.example"` shape | CWE-601 |
| `if !strings.HasPrefix(s, "/") \|\| strings.HasPrefix(s, "//") { return }; http.Redirect(...)` (no backslash check) | CWE-601 |
| `http.Redirect(w, r, "/" + x, 302)` | CWE-601 |
| `http.Redirect(w, r, "/safe/" + x, 302)` (constant path prefix, no `?`; `x = "../\\evil.example"` cleans to `/\evil.example`) | CWE-601 |
| `if !strings.HasPrefix(s, "/") \|\| strings.HasPrefix(s, "//") \|\| strings.HasPrefix(s, "/\\") { return }; http.Redirect(...)` (leading-only backslash check) | CWE-601 |
| relative-path guard with a full backslash check but no control-character or `url.Parse` error check (`/\t/evil.example`) | CWE-601 |
| `url.Parse` guard rejecting `err`, `IsAbs()`, `Host != ""` and backslashes but not a `//` prefix (`///evil.example`, echo `c.Redirect`) | CWE-601 |
| `s.root = r.FormValue("root")` elsewhere in the file, then `os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + f)))` | CWE-22 |

`template.JS(html.EscapeString(x))` is out of scope, so it produces nothing; a
test asserts that, so adding a JS-context sink later is a deliberate change
rather than a silent one.

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
- exact spec lookup: unresolved `x.Repeat`, `x.Query` never match;
- multi-value results, including the untainted `err`;
- function literals as procedures; method receivers;
- immediate / deferred / asynchronous calls and structural termination;
- out-param and receiver-mutation hints;
- guard facts: accumulation, conjunction, kill on reassignment, join;
- procedure summaries: propagation, sanitizing helper, constant return,
  `is_source`, recursion fallback, lookup by `get_full_name()` for method calls;
- source shape: handler-shaped `*http.Request` is a source; `RoundTrip(req)` and
  a request builder are not;
- `len` / `cap` untainted;
- `range`, `switch`, `select`; parse-error recovery.

`tests/test_go_taint.py` (end to end through `FrameScanner(language="go")`):

- for every sink row, a vulnerable fixture that must fire with the right CWE and
  at least one patched twin that must not;
- every bypass in Sanitizer fixtures;
- shapes: handler function literal; same-file helper flow in both directions;
  `json.Decode` into a struct; gin and echo handlers; aliased import
  (`osexec "os/exec"`); `defer os.Exit` before a sink; `make([]byte, len(body))`
  silent; daemon accept loop silent (CWE-835); recursion with and without a base
  case (CWE-674); credential-shaped vs ordinary string constant;
  `os.Open(os.Args[1])` silent.

`tests/test_go_llm_coverage.py`: see LLM coverage.

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
   triage; then an `--ai` run compared with step 1. Because the candidate gate is
   bypassed for Go, the `--ai` run calls the LLM on the same files as the
   baseline, so the difference isolates the symbolic layer and sink grounding.
4. Report File F1 and TNR for the subset and the whole Go sample. Update the VLoC
   README coverage row to `go | 215 | yes (taint + CWE-770); rest LLM-only`.

## Phase B (next phase, not built here)

Package-level summaries: scan all non-excluded `.go` files of a package together
and extend `_go_summaries.py` from same-file to package scope (param → return,
param → sink, param → out-param), using `_go_env`; imported in-repo packages
after that. Enters with evidence from this milestone's VLoC measurement that
cross-file flow is where recall is lost. Phase B also runs the trusted-root
provenance check over every file of the package, closing the residual stated in
Guard facts.

Also deferred, each needing its own decision: closure capture;
`http.ResponseWriter` XSS; context-specific sinks and sanitizers for
`template.JS` / `URL` / `CSS` / `HTMLAttr`; sources from Kubernetes API objects,
CRDs and gRPC messages; `io.ReadAll(r.Body)` and decompression-bomb CWE-400;
CWE-88 argument injection; a Go-aware LLM candidate heuristic; constant-prefix
destinations through intermediate variables; the CLI threat model (`os.Args`,
`os.Getenv`, stdin as sources).
