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
