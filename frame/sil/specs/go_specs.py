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

# Sink positions that do not fire on the default propagation of a call the
# frontend cannot resolve alone (go_frontend._unresolved_only): the exec
# program name and the redirect / SSRF destination.
UNRESOLVED_GUARDED_ARGS: Dict[str, int] = {
    **SHELL_COMMAND_KEYS,
    **{k: s.sink_args[0] for k, s in GO_SPECS.items()
       if s.is_sink in (REDIRECT, SSRF) and s.sink_args},
}

# --- CWE-79 (explicit escape bypass only) ---------------------------------------------------
GO_SPECS["html/template.HTML"] = _sink(HTML, [0], "template.HTML(x) marks x trusted", propagates=[0])

# --- CWE-770 ------------------------------------------------------------------------------------
GO_SPECS["strings.Repeat"] = _sink(ALLOC, [1], "strings.Repeat(s, count)", propagates=[0])
GO_SPECS["bytes.Repeat"] = _sink(ALLOC, [1], "bytes.Repeat(b, count)", propagates=[0])
MAKE_SLICE_SPEC = ProcSpec(is_sink=ALLOC, sink_args=[1, 2], description="make([]T, len, cap)")

# --- Sanitizers --------------------------------------------------------------------------------------
# NOTE: the brief's Step 3 code also registered "path.Base" as an FS sanitizer.
# Deliberately omitted here: the design spec's Return-value sanitizers table
# (the authority for this file) lists only `filepath.Base` and states the
# sinks/sanitizers section is "the complete milestone-1 set." `path.Base` only
# splits on "/", so on Windows `path.Base("..\\..\\etc\\passwd")` returns the
# input unchanged (no "/" to strip), which would falsely clear FILE_PATH taint
# for a value that still contains a full backslash-separated traversal. See
# task-3-report.md Concerns for the reasoning; flag for the controller if a
# later task needs `path.Base` sanitization after all.
GO_SPECS["path/filepath.Base"] = _sanitizer([FS], "filepath.Base")
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
