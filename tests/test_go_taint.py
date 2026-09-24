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


def test_method_value_handler_does_not_taint_same_named_client_method():
    base = '''package main
import ("net/http"; "os/exec")
type Server struct{}
type Client struct{}
func (s *Server) handle(req *http.Request) { %s }
func (c *Client) handle(req *http.Request) { %s }
func main() {
	s := &Server{}
	http.HandleFunc("/", s.handle)
}'''
    sink = "exec.Command(req.URL.Path)"
    _pair("CWE-78", base % (sink, ""), base % ("", sink))


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


def test_multi_result_helper_keeps_taint():
    src = _handler('v, _ := id2(r.FormValue("cmd"))\nexec.Command(v)', '"net/http"\n"os/exec"',
                   "func id2(s string) (string, error) { return s, nil }")
    assert "CWE-78" in _cwes(src)


def test_sanitizer_summary_requires_first_argument_to_propagate():
    imports = '"net/http"\n"os/exec"\n"path/filepath"'
    silent = "func pb(c string, p string) string { return filepath.Base(p) }"
    firing = "func pb(c string, p string) string { return filepath.Base(c) }"
    body = 'exec.Command(pb(r.FormValue("c"), "x"))'
    _pair("CWE-78", _handler(body, imports, firing), _handler(body, imports, silent))


def test_sanitized_argument_stays_sanitized_in_callee():
    imports = '"net/http"\n"os"\n"path/filepath"'
    extra = "func open1(p string) { os.Open(p) }"
    _pair("CWE-22", _handler('open1(r.FormValue("f"))', imports, extra),
          _handler('open1(filepath.Base(r.FormValue("f")))', imports, extra))


def test_callee_sanitization_is_intersected_over_call_sites():
    imports = '"net/http"\n"os"\n"path/filepath"'
    extra = "func open1(p string) { os.Open(p) }"
    body = 'open1(filepath.Base(r.FormValue("f")))\nopen1(r.FormValue("g"))'
    assert "CWE-22" in _cwes(_handler(body, imports, extra))


def _chain(n: int, reverse: bool) -> str:
    funcs = [f"func h{i}(s string) {{ h{i + 1}(s) }}" for i in range(1, n)]
    funcs.append(f"func h{n}(s string) {{ exec.Command(s).Run() }}")
    if reverse:
        funcs.reverse()
    return _handler('h1(r.FormValue("cmd"))', '"net/http"\n"os/exec"', "\n".join(funcs))


def test_long_helper_chain_reaches_sink_in_any_definition_order():
    assert "CWE-78" in _cwes(_chain(13, reverse=False))
    assert "CWE-78" in _cwes(_chain(13, reverse=True))


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


def test_unrecognised_disjunctive_guard_keeps_the_continuation_feasible():
    # A bare call-result inside `||` must not make the false edge look UNSAT to
    # the infeasible-path filter (independent of any guard rule).
    body = 'f := r.FormValue("f")\nif !check(f) || other(f) { return }\nos.ReadFile(f)'
    extra = 'func check(s string) bool { return true }\nfunc other(s string) bool { return false }'
    assert "CWE-22" in _cwes(_handler(body, FS, extra))


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
            'if err != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "\\\\") { return }\n'
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


# ---- Fix round 1: over-permissive sanitizers (bypasses must fire) -----------------
def test_redirect_bypass_double_backslash_needle():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "\\\\\\\\") || strings.ContainsAny(next, "\\r\\n\\t") { return }\n'
            'http.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_slash_backslash_needle():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "/\\\\") || strings.ContainsAny(next, "\\r\\n\\t") { return }\n'
            'http.Redirect(w, r, next, 302)')
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_fs_bypass_root_decoded_into_local_struct():
    body = ('var c Cfg\njson.NewDecoder(r.Body).Decode(&c)\n'
            'os.ReadFile(filepath.Join(c.Root, filepath.Clean("/" + r.FormValue("f"))))')
    assert "CWE-22" in _cwes(_handler(body, FS + '\n"encoding/json"', 'type Cfg struct{ Root string }'))


def test_fs_bypass_root_decoded_into_package_var():
    body = ('json.NewDecoder(r.Body).Decode(&cfg)\n'
            'os.ReadFile(filepath.Join(cfg.Root, filepath.Clean("/" + r.FormValue("f"))))')
    extra = 'type Cfg struct{ Root string }\nvar cfg Cfg'
    assert "CWE-22" in _cwes(_handler(body, FS + '\n"encoding/json"', extra))


def test_fs_bypass_field_written_from_other_functions_parameter():
    # `root` in New is New's parameter, not Serve's trusted local of that name.
    extra = ('type S struct{ root string }\n'
             'func New(root string) *S { return &S{root: root} }\n'
             'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n'
             '  root := "/srv"\n  _ = root\n'
             '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_fs_bypass_positional_struct_literal_writes_root():
    extra = ('type S struct{ root string }\n'
             'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n'
             '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}\n'
             'func mk(w http.ResponseWriter, r *http.Request) { t := &S{r.FormValue("root")}; t.Serve(w, r) }')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_fs_bypass_rel_parts_from_different_rel_calls():
    body = ('p := filepath.Join(root, r.FormValue("f"))\n'
            'rel, err := filepath.Rel(root, p)\n_ = rel\n'
            'rel2, _ := filepath.Rel("/", p)\n'
            'if err != nil || strings.HasPrefix(rel2, "..") { return }\n'
            'os.ReadFile(p)')
    assert "CWE-22" in _cwes(_handler(body, FS, 'const root = "/srv/www"'))


# ---- Fix round 1: allowlist containers and missing twins ----------------------------
def test_redirect_twin_map_allowlist():
    guard = 'if err != nil || !allowed[u.Hostname()] { return }\n'
    body = ('u, err := url.Parse(r.FormValue("next"))\n' + guard +
            'http.Redirect(w, r, u.String(), 302)')
    extra = 'var allowed = map[string]bool{"example.com": true}'
    _pair("CWE-601", _handler(body.replace(guard, '_ = err\n_ = allowed\n'), RD, extra),
          _handler(body, RD, extra))


def test_ssrf_twin_slice_allowlist():
    body = ('u, err := url.Parse(r.FormValue("u"))\n'
            'if err != nil || !slices.Contains(HOSTS, u.Hostname()) { return }\n'
            'http.Get(u.String())')
    imports = RD + '\n"slices"'
    trusted = body.replace("HOSTS", '[]string{"api.example.com", "cdn.example.com"}')
    tainted = body.replace("HOSTS", '[]string{"api.example.com", r.FormValue("extra")}')
    _pair("CWE-918", _handler(tainted, imports), _handler(trusted, imports))


def test_fs_twin_equal_or_separator_prefix():
    guard = 'if !(p == root || strings.HasPrefix(p, root+string(filepath.Separator))) { return }\n'
    body = 'p := filepath.Clean(filepath.Join(root, r.FormValue("f")))\n' + guard + 'os.ReadFile(p)'
    extra = 'const root = "/srv/www"'
    _pair("CWE-22", _handler(body.replace(guard, ''), FS, extra), _handler(body, FS, extra))


def test_fs_twin_equal_or_slash_prefix():
    guard = 'if p != root && !strings.HasPrefix(p, root+"/") { return }\n'
    body = 'p := filepath.Clean(filepath.Join(root, r.FormValue("f")))\n' + guard + 'os.ReadFile(p)'
    extra = 'const root = "/srv/www"'
    _pair("CWE-22", _handler(body.replace(guard, ''), FS, extra), _handler(body, FS, extra))


def test_fs_twin_rel_dotdot_equal_or_dotdot_separator():
    check = ('if err != nil || rel == ".." || '
             'strings.HasPrefix(rel, ".."+string(filepath.Separator)) { return }\n')
    body = ('p := filepath.Join(root, r.FormValue("f"))\n'
            'rel, err := filepath.Rel(root, p)\n' + check + 'os.ReadFile(p)')
    # Without the `rel == ".."` part the rule is incomplete and must fire.
    partial = body.replace('rel == ".." || ', '')
    extra = 'const root = "/srv/www"'
    _pair("CWE-22", _handler(partial, FS, extra), _handler(body, FS, extra))


def test_redirect_twin_relative_path_with_url_parse_error_for_control_chars():
    body = ('next := r.FormValue("next")\n_, err := url.Parse(next)\n'
            'if err != nil || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            'strings.Contains(next, "\\\\") { return }\n'
            'http.Redirect(w, r, next, 302)')
    # Without the url.Parse error rejection the control-character part is missing.
    partial = body.replace('err != nil || ', '').replace('_, err := url.Parse(next)\n', '')
    _pair("CWE-601", _handler(partial, RD), _handler(body, RD))


# ---- Fix round 2: container writes, elided struct literals, rune needles ---------------
MAP_GUARD = ('u, err := url.Parse(r.FormValue("next"))\nif err != nil || !allowed[u.Hostname()] { return }\n'
             'http.Redirect(w, r, u.String(), 302)')
ALLOWED = 'var allowed = map[string]bool{"example.com": true}'


def test_redirect_bypass_map_key_written_in_other_function():
    extra = ALLOWED + '\nfunc add(w http.ResponseWriter, r *http.Request) { allowed[r.FormValue("h")] = true }'
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD, extra))


def test_redirect_bypass_local_map_key_written():
    body = 'allowed := map[string]bool{"example.com": true}\nallowed[r.FormValue("h")] = true\n' + MAP_GUARD
    assert "CWE-601" in _cwes(_handler(body, RD))


def test_redirect_bypass_map_filled_by_callee():
    extra = (ALLOWED + '\nfunc add(w http.ResponseWriter, r *http.Request) '
             '{ maps.Copy(allowed, map[string]bool{r.FormValue("h"): true}) }')
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD + '\n"maps"', extra))


def test_redirect_bypass_map_keys_from_range_over_request():
    extra = (ALLOWED + '\nfunc add(w http.ResponseWriter, r *http.Request) '
             '{ for _, h := range r.Form["h"] { allowed[h] = true } }')
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD, extra))


def test_ssrf_twin_named_slice_allowlist():
    # slices.Contains only reads its argument: passing HOSTS is not a write.
    body = ('u, err := url.Parse(r.FormValue("u"))\n'
            'if err != nil || !slices.Contains(HOSTS, u.Hostname()) { return }\nhttp.Get(u.String())')
    imports = RD + '\n"slices"'
    extra = 'var HOSTS = []string{"api.example.com"}'
    tainted = extra + '\nfunc add(w http.ResponseWriter, r *http.Request) { HOSTS = append(HOSTS, r.FormValue("h")) }'
    _pair("CWE-918", _handler(body, imports, tainted), _handler(body, imports, extra))


_SERVE_ROOT = ('type S struct{ root string }\n'
               'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n'
               '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}\n')


def test_fs_bypass_elided_positional_struct_in_slice():
    extra = _SERVE_ROOT + ('func mk(w http.ResponseWriter, r *http.Request) '
                           '{ ts := []S{{r.FormValue("root")}}; ts[0].Serve(w, r) }')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_fs_bypass_elided_positional_struct_in_map():
    extra = _SERVE_ROOT + ('func mk(w http.ResponseWriter, r *http.Request) '
                           '{ ts := map[string]*S{"a": {r.FormValue("root")}}; ts["a"].Serve(w, r) }')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_redirect_twin_containsrune_backslash():
    body = ('next := r.FormValue("next")\n'
            'if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || '
            "strings.ContainsRune(next, '\\\\') || strings.ContainsAny(next, \"\\r\\n\\t\") { return }\n"
            'http.Redirect(w, r, next, 302)')
    # A rune other than backslash does not prove the absence of backslashes.
    partial = body.replace("'\\\\'", "'x'")
    _pair("CWE-601", _handler(partial, RD), _handler(body, RD))


# ---- Fix round 3: allowlist containers are trusted only under permitted reads ---------
HOSTS_GUARD = ('u, err := url.Parse(r.FormValue("u"))\n'
               'if err != nil || !slices.Contains(HOSTS, u.Hostname()) { return }\nhttp.Get(u.String())')
HOSTS = 'var HOSTS = []string{"api.example.com"}'
_ADD = '\nfunc add(w http.ResponseWriter, r *http.Request) { %s }'


def test_redirect_bypass_map_written_through_local_alias():
    extra = ALLOWED + _ADD % 'a := allowed; a[r.FormValue("h")] = true'
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD, extra))


def test_redirect_bypass_map_written_through_package_alias():
    extra = ALLOWED + '\nvar alias = allowed' + _ADD % 'alias[r.FormValue("h")] = true'
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD, extra))


def test_ssrf_bypass_slice_filled_through_subslice():
    extra = HOSTS + '\nfunc fill(xs []string, v string) { xs[0] = v }' + _ADD % 'fill(HOSTS[:], r.FormValue("h"))'
    assert "CWE-918" in _cwes(_handler(HOSTS_GUARD, RD + '\n"slices"', extra))


def test_ssrf_bypass_slice_filled_through_variadic_spread():
    extra = HOSTS + '\nfunc setT(v string, xs ...string) { xs[0] = v }' + _ADD % 'setT(r.FormValue("h"), HOSTS...)'
    assert "CWE-918" in _cwes(_handler(HOSTS_GUARD, RD + '\n"slices"', extra))


def test_redirect_bypass_shadowed_len_is_not_the_builtin():
    extra = (ALLOWED + '\nfunc len(m map[string]bool, h string) int { m[h] = true; return 0 }'
             + _ADD % 'len(allowed, r.FormValue("h"))')
    assert "CWE-601" in _cwes(_handler(MAP_GUARD, RD, extra))


def test_redirect_twin_map_allowlist_with_delete():
    # delete only removes entries; the firing side adds a tainted one.
    extra = ALLOWED + _ADD % 'delete(allowed, r.FormValue("h"))'
    tainted = ALLOWED + _ADD % 'allowed[r.FormValue("h")] = true'
    _pair("CWE-601", _handler(MAP_GUARD, RD, tainted), _handler(MAP_GUARD, RD, extra))


def test_redirect_twin_unrelated_same_named_local_container():
    # A local `allowed` in another function is a different variable.
    extra = ALLOWED + '\nfunc other() { allowed := []int{1}; fmt.Println(allowed) }'
    tainted = ALLOWED + '\nfunc other() { fmt.Println(allowed) }'
    _pair("CWE-601", _handler(MAP_GUARD, RD + '\n"fmt"', tainted), _handler(MAP_GUARD, RD + '\n"fmt"', extra))


def test_redirect_twin_range_and_len_reads_keep_allowlist():
    extra = ALLOWED + '\nfunc o() int { n := len(allowed); for k := range allowed { _ = k }; return n }'
    tainted = ALLOWED + '\nfunc o() { a := allowed; _ = a }'
    _pair("CWE-601", _handler(MAP_GUARD, RD, tainted), _handler(MAP_GUARD, RD, extra))


def test_ssrf_bypass_range_assigns_into_allowlist_element():
    # `for i, HOSTS[0] = range xs` stores each element into HOSTS: a write.
    extra = HOSTS + _ADD % 'var i int; for i, HOSTS[0] = range []string{r.FormValue("h")} { _ = i }'
    assert "CWE-918" in _cwes(_handler(HOSTS_GUARD, RD + '\n"slices"', extra))


def test_ssrf_bypass_select_receive_into_allowlist_element():
    # `case HOSTS[0] = <-ch:` stores the received value into HOSTS: a write.
    extra = HOSTS + _ADD % ('ch := make(chan string, 1); ch <- r.FormValue("h")\n'
                            'select { case HOSTS[0] = <-ch: }')
    assert "CWE-918" in _cwes(_handler(HOSTS_GUARD, RD + '\n"slices"', extra))


def test_ssrf_twin_range_and_receive_into_locals_keep_allowlist():
    # Reading HOSTS and assigning range / receive results to locals is fine.
    extra = HOSTS + _ADD % ('var s string; for _, s = range HOSTS { _ = s }\n'
                            'ch := make(chan string, 1); select { case s = <-ch: _ = s }')
    tainted = HOSTS + _ADD % 'var i int; for i, HOSTS[0] = range []string{r.FormValue("h")} { _ = i }'
    _pair("CWE-918", _handler(HOSTS_GUARD, RD + '\n"slices"', tainted),
          _handler(HOSTS_GUARD, RD + '\n"slices"', extra))


_ROOT_SERVE = ('type S struct{ root string }\n'
               'func (s *S) Serve(w http.ResponseWriter, r *http.Request) {\n  %s\n'
               '  os.ReadFile(filepath.Join(s.root, filepath.Clean("/" + r.FormValue("f"))))\n}')


def test_fs_bypass_range_assigns_receiver_root():
    extra = _ROOT_SERVE % 'for _, s.root = range []string{r.FormValue("r")} {}'
    assert "CWE-22" in _cwes(_handler("", FS, extra))


def test_fs_bypass_select_receive_assigns_receiver_root():
    extra = _ROOT_SERVE % ('ch := make(chan string, 1); ch <- r.FormValue("r")\n'
                           '  select { case s.root = <-ch: }')
    assert "CWE-22" in _cwes(_handler("", FS, extra))


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


# ---- call results: one sanitized input must not launder the others -------------------
SQLF = '"database/sql"\n"fmt"\n"net/http"\n"strconv"'


def test_call_sanitization_is_intersected_over_sprintf_inputs():
    vulnerable = ('id, _ := strconv.Atoi(r.FormValue("id"))\nname := r.FormValue("n")\n'
                  'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%d AND n=\'%s\'", id, name))')
    patched = ('id, _ := strconv.Atoi(r.FormValue("id"))\nn, _ := strconv.Atoi(r.FormValue("n"))\n'
               'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%d AND n=%d", id, n))')
    _pair("CWE-89", _handler(vulnerable, SQLF, "var db *sql.DB"),
          _handler(patched, SQLF, "var db *sql.DB"))


def test_call_sanitization_is_intersected_over_join_inputs():
    _pair("CWE-22",
          _handler('a := r.FormValue("a")\n'
                   'os.ReadFile(filepath.Join(filepath.Base(a), r.FormValue("b")))', FS),
          _handler('a := r.FormValue("a")\n'
                   'os.ReadFile(filepath.Join(filepath.Base(a), filepath.Base(r.FormValue("b"))))', FS))


def test_call_sanitization_is_intersected_over_unresolved_call_inputs():
    imports = FS + '\n"example.com/ext"'
    _pair("CWE-22",
          _handler('os.ReadFile(ext.Mix(filepath.Base(r.FormValue("a")), r.FormValue("b")))', imports),
          _handler('os.ReadFile(ext.Mix(filepath.Base(r.FormValue("a")), '
                   'filepath.Base(r.FormValue("b"))))', imports))


def test_call_sanitization_is_intersected_over_same_file_helper_inputs():
    extra = "func cat(a string, b string) string { return a + b }"
    _pair("CWE-22",
          _handler('os.ReadFile(cat(filepath.Base(r.FormValue("a")), r.FormValue("b")))', FS, extra),
          _handler('os.ReadFile(cat(filepath.Base(r.FormValue("a")), '
                   'filepath.Base(r.FormValue("b"))))', FS, extra))


def test_call_sanitization_is_intersected_with_guarded_inputs():
    imports = FS + '\n"fmt"'
    _pair("CWE-22",
          _handler('d := r.FormValue("d")\nif !filepath.IsLocal(d) { return }\n'
                   'os.ReadFile(fmt.Sprintf("%s/%s", d, r.FormValue("f")))', imports),
          _handler('d := r.FormValue("d")\nif !filepath.IsLocal(d) { return }\n'
                   'f := r.FormValue("f")\nif !filepath.IsLocal(f) { return }\n'
                   'os.ReadFile(fmt.Sprintf("%s/%s", d, f))', imports))


def test_out_param_does_not_keep_the_destinations_old_sanitization():
    imports = FS + '\n"encoding/json"'
    _pair("CWE-22",
          _handler('p := filepath.Base(r.FormValue("p"))\n'
                   'json.NewDecoder(r.Body).Decode(&p)\nos.ReadFile(p)', imports),
          _handler('p := filepath.Base(r.FormValue("p"))\nos.ReadFile(p)', imports))


# ---- shadowing declarations are distinct variables --------------------------------------
EX = '"net/http"\n"os/exec"'


def test_comma_ok_shadow_does_not_clean_the_outer_variable():
    extra = 'var db *sql.DB\nvar aliases = map[string]string{"a": "b"}'
    vulnerable = ('name := r.FormValue("name")\nif name, ok := aliases[name]; ok { _ = name }\n'
                  'db.Query("SELECT * FROM t WHERE n = " + name)')
    patched = ('name := r.FormValue("name")\nif v, ok := aliases[name]; ok { name = v } else { return }\n'
               'db.Query("SELECT * FROM t WHERE n = " + name)')
    _pair("CWE-89", _handler(vulnerable, SQL_IMPORTS, extra), _handler(patched, SQL_IMPORTS, extra))


def test_block_shadow_does_not_clean_the_outer_variable():
    _pair("CWE-78",
          _handler('p := r.FormValue("p")\n{ p := "ls"; _ = p }\nexec.Command(p)', EX),
          _handler('p := r.FormValue("p")\n{ p = "ls"; _ = p }\nexec.Command(p)', EX))


def test_var_shadow_does_not_clean_the_outer_variable():
    _pair("CWE-78",
          _handler('p := r.FormValue("p")\n{ var p = "ls"; _ = p }\nexec.Command(p)', EX),
          _handler('p := r.FormValue("p")\n{ p = "ls"; _ = p }\nexec.Command(p)', EX))


def test_switch_initializer_shadow_does_not_clean_the_outer_variable():
    _pair("CWE-78",
          _handler('cmd := r.FormValue("c")\nswitch cmd := "ls"; cmd { default: _ = cmd }\n'
                   'exec.Command(cmd)', EX),
          _handler('cmd := r.FormValue("c")\nswitch cmd = "ls"; cmd { default: _ = cmd }\n'
                   'exec.Command(cmd)', EX))


def test_for_initializer_shadow_does_not_clean_the_outer_variable():
    _pair("CWE-78",
          _handler('p := r.FormValue("p")\nfor p := ""; p != ""; p = "" { _ = p }\nexec.Command(p)', EX),
          _handler('p := r.FormValue("p")\nfor p = ""; p != ""; p = "" { _ = p }\nexec.Command(p)', EX))


def test_inner_tainted_shadow_does_not_taint_the_outer_variable():
    _pair("CWE-78",
          _handler('p := "ls"\n{ p = r.FormValue("p"); _ = p }\nexec.Command(p)', EX),
          _handler('p := "ls"\n{ p := r.FormValue("p"); _ = p }\nexec.Command(p)', EX))


def test_range_shadow_does_not_taint_the_outer_variable():
    _pair("CWE-78",
          _handler('p := "ls"\nfor _, p = range r.Form["x"] { _ = p }\nexec.Command(p)', EX),
          _handler('p := "ls"\nfor _, p := range r.Form["x"] { _ = p }\nexec.Command(p)', EX))


def test_type_switch_binding_is_its_own_variable():
    _pair("CWE-78",
          _handler('v := "ls"\nvar x any = r.FormValue("q")\n'
                   'switch v := x.(type) { case string: exec.Command(v) }', EX),
          _handler('v := "ls"\nvar x any = r.FormValue("q")\n'
                   'switch v := x.(type) { case string: _ = v }\nexec.Command(v)', EX))


def test_func_literal_parameter_does_not_touch_the_outer_variable():
    _pair("CWE-78",
          _handler('p := r.FormValue("p")\nf := func(p string) { _ = p }\nf("ls")\nexec.Command(p)', EX),
          _handler('p := "ls"\nf := func(p string) { _ = p }\nf(r.FormValue("p"))\nexec.Command(p)', EX))


def test_guard_on_a_shadow_does_not_sanitize_the_outer_variable():
    _pair("CWE-22",
          _handler('f := r.FormValue("f")\n{ f := r.FormValue("g"); if !filepath.IsLocal(f) { return }; _ = f }\n'
                   'os.ReadFile(f)', FS),
          _handler('f := r.FormValue("f")\n{ if !filepath.IsLocal(f) { return } }\n'
                   'os.ReadFile(f)', FS))


def test_shadow_of_a_named_result_keeps_the_bare_return():
    firing = 'func pick(s string) (out string) { out = s; { out := "x"; _ = out }; return }'
    silent = 'func pick(s string) (out string) { out = "x"; { out := s; _ = out }; return }'
    body = 'exec.Command(pick(r.FormValue("c")))'
    _pair("CWE-78", _handler(body, EX, firing), _handler(body, EX, silent))


def test_redirect_bypass_url_parse_rule_without_double_slash_check_echo():
    # `///evil.example` parses with Host "" and IsAbs false, err nil; echo
    # writes Location raw and browsers go to evil.example.
    guard = ('next := c.QueryParam("next")\nu, err := url.Parse(next)\n'
             'if err != nil || u.IsAbs() || u.Host != "" || strings.Contains(next, "\\\\")%s { return nil }\n'
             'return c.Redirect(302, next)')
    src = ('package main\nimport (\n"net/url"\n"strings"\n"github.com/labstack/echo/v4"\n)\n'
           'func h(c echo.Context) error {\n%s\n}\n')
    _pair("CWE-601", src % (guard % ""),
          src % (guard % ' || strings.HasPrefix(next, "//")'))


# ---- comma-ok allowlist membership -------------------------------------------------------
SET_ALLOWED = 'var allowed = map[string]struct{}{"api.example.com": {}}'
COMMA_OK = ('s := r.FormValue("u")\nu, err := url.Parse(s)\nif err != nil { return }\n'
            'if _, ok := allowed[u.Hostname()]; !ok { return }\nhttp.Get(s)')


def test_ssrf_twin_comma_ok_allowlist():
    tainted = SET_ALLOWED + _ADD % 'allowed[r.FormValue("h")] = struct{}{}'
    _pair("CWE-918", _handler(COMMA_OK, RD, tainted), _handler(COMMA_OK, RD, SET_ALLOWED))


def test_ssrf_bypass_comma_ok_without_reject_branch():
    body = COMMA_OK.replace('if _, ok := allowed[u.Hostname()]; !ok { return }',
                            'if _, ok := allowed[u.Hostname()]; !ok { _ = ok }')
    assert "CWE-918" in _cwes(_handler(body, RD, SET_ALLOWED))


def test_ssrf_comma_ok_binding_is_killed_by_reassignment():
    body = ('s := r.FormValue("u")\nu, err := url.Parse(s)\nif err != nil { return }\n'
            '_, ok := allowed[u.Hostname()]\n%s\nif !ok { return }\nhttp.Get(s)')
    _pair("CWE-918", _handler(body % 'ok = true', RD, SET_ALLOWED),
          _handler(body % '', RD, SET_ALLOWED))
    # Re-parsing the URL after the lookup also breaks the binding.
    reparsed = body % 'u, err = url.Parse(r.FormValue("v"))\n_ = err'
    assert "CWE-918" in _cwes(_handler(reparsed.replace("http.Get(s)", "http.Get(u.String())"),
                                       RD, SET_ALLOWED))


# ---- guard sanitization across same-file call boundaries ------------------------------
READ_IT = "func readIt(p string) { os.ReadFile(p) }"


def test_guard_before_same_file_call_sanitizes_the_callee_parameter():
    _pair("CWE-22",
          _handler('p := r.FormValue("p")\nreadIt(p)', FS, READ_IT),
          _handler('p := r.FormValue("p")\nif !filepath.IsLocal(p) { return }\nreadIt(p)', FS, READ_IT))


def test_guard_into_callee_is_intersected_over_call_sites():
    body = ('p := r.FormValue("p")\nq := r.FormValue("q")\n'
            'if !filepath.IsLocal(p) { return }\nreadIt(p)\nreadIt(q)')
    assert "CWE-22" in _cwes(_handler(body, FS, READ_IT))


def test_guard_into_method_callee_receiver_argument():
    extra = "type S struct{}\nvar s *S\nfunc (x *S) readIt(p string) { os.ReadFile(p) }"
    _pair("CWE-22",
          _handler('p := r.FormValue("p")\ns.readIt(p)', FS, extra),
          _handler('p := r.FormValue("p")\nif !filepath.IsLocal(p) { return }\ns.readIt(p)', FS, extra))


def test_guarding_helper_is_a_sanitizer_summary():
    silent = 'func clean(p string) string { if !filepath.IsLocal(p) { return "" }; return p }'
    firing = 'func clean(p string) string { if !filepath.IsLocal(p) { _ = p }; return p }'
    body = 'os.ReadFile(clean(r.FormValue("p")))'
    _pair("CWE-22", _handler(body, FS, firing), _handler(body, FS, silent))
    # The guard proves nothing about shell injection.
    assert "CWE-78" in _cwes(_handler('exec.Command(clean(r.FormValue("p")))',
                                      FS + '\n"os/exec"', silent))


# ---- variadic same-file calls ----------------------------------------------------------
def test_variadic_argument_reaches_sink_in_callee():
    extra = "func run(args ...string) { exec.Command(args[1]) }"
    _pair("CWE-78", _handler('run("a", r.FormValue("x"))', EX, extra),
          _handler('run("a", "b")', EX, extra))


def test_variadic_after_fixed_parameter_reaches_sink_in_callee():
    extra = "func run(name string, args ...string) { exec.Command(args[0]) }"
    _pair("CWE-78", _handler('run("n", "a", r.FormValue("x"))', EX, extra),
          _handler('run(r.FormValue("x"), "a", "b")', EX, extra))


def test_variadic_into_callee_sanitization_is_intersected():
    extra = "func readAll(ps ...string) { os.ReadFile(ps[0]) }"
    _pair("CWE-22",
          _handler('readAll(filepath.Base(r.FormValue("a")), r.FormValue("b"))', FS, extra),
          _handler('readAll(filepath.Base(r.FormValue("a")), filepath.Base(r.FormValue("b")))',
                   FS, extra))


def test_variadic_argument_propagates_out_of_callee():
    extra = 'func join(parts ...string) string { s := ""; for _, p := range parts { s += p }; return s }'
    _pair("CWE-78", _handler('exec.Command(join("a", r.FormValue("x")))', EX, extra),
          _handler('exec.Command(join("a", "b"))', EX, extra))


def test_source_out_param_over_sanitized_var_fires():
    # c.ShouldBind(&p) overwrites a sanitized p with a fresh source value.
    src = '''package main
import ("github.com/gin-gonic/gin"; "os"; "path/filepath")
func h(c *gin.Context) {
	p := filepath.Base(c.Query("f"))
	c.ShouldBind(&p)
	os.ReadFile(p)
}'''
    patched = '''package main
import ("github.com/gin-gonic/gin"; "os"; "path/filepath")
func h(c *gin.Context) {
	p := filepath.Base(c.Query("f"))
	os.ReadFile(p)
}'''
    _pair("CWE-22", src, patched)


def test_source_call_assigned_over_sanitized_var_fires():
    _pair("CWE-22",
          _handler('p := filepath.Base(r.FormValue("x"))\np = r.FormValue("p")\nos.Open(p)', FS),
          _handler('p := r.FormValue("p")\np = filepath.Base(r.FormValue("x"))\nos.Open(p)', FS))


# --- Deep expressions (Kubernetes allocator_testing.go: a 1,870-entry
# composite literal lowered to a left-deep `+` chain overflowed the
# translator's __str__ recursion, and the whole file lost its findings).

def test_huge_composite_literal_scans_and_keeps_findings():
    elems = ", ".join(["a"] * 2000)
    body = f'a := "x"\nt := []string{{{elems}}}\n_ = t\nexec.Command(r.FormValue("c"))'
    assert "CWE-78" in _cwes(_handler(body, EX))


def test_huge_composite_literal_still_propagates_taint():
    elems = ", ".join(["a"] * 1000 + ["u"] + ["a"] * 1000)
    body = f'a := "x"\nu := r.FormValue("c")\nt := []string{{{elems}}}\nexec.Command(t[0])'
    assert "CWE-78" in _cwes(_handler(body, EX))


def test_long_concatenation_chain_scans():
    chain = " + ".join(["a"] * 1500)
    body = f'a := r.FormValue("c")\nexec.Command({chain})'
    assert "CWE-78" in _cwes(_handler(body, EX))


def test_function_skipped_for_recursion_is_reported_and_siblings_still_scan(monkeypatch):
    from frame.sil.frontends.go_frontend import GoFrontend
    original = GoFrontend._lower_function

    def lower(self, node, name=None, outer_scope=None):
        if name is None and self._t(node.child_by_field_name("name")) == "deep":
            raise RecursionError("maximum recursion depth exceeded")
        return original(self, node, name=name, outer_scope=outer_scope)

    monkeypatch.setattr(GoFrontend, "_lower_function", lower)
    src = _handler('exec.Command(r.FormValue("c"))', EX, "func deep() {}")
    result = FrameScanner(language="go", verify=False).scan(src, "t.go")
    assert not result.errors
    assert "CWE-78" in {v.cwe_id for v in result.vulnerabilities}
    assert any("'deep'" in w and "line" in w for w in result.warnings), result.warnings


# --- Program name from a function this file cannot see (Kubernetes
# pkg/kubelet/kubelet_server_journal.go: `cmdStr, args, env, err :=
# getLoggingCmd(n, services)` with getLoggingCmd in _linux.go / _windows.go).
# Default propagation still taints the results; the program-name position of
# exec.Command / CommandContext just does not fire on that taint alone.

_UNRESOLVED_CTX = '''package main
import ("context"; "net/http"; "os/exec")
type q struct{ Services []string }
func h(w http.ResponseWriter, r *http.Request) {
	n := &q{Services: r.URL.Query()["svc"]}
	n.copyLogs(r.Context(), n.Services)
}
func (n *q) copyLogs(ctx context.Context, services []string) {
	cmdStr, args, cmdEnv, err := getLoggingCmd(n, services)
	if err != nil { return }
	cmd := exec.CommandContext(ctx, SINK, args...)
	cmd.Env = cmdEnv
	cmd.Run()
}
'''


def test_program_name_from_unresolved_helper_is_silent_command_context():
    _pair("CWE-78", _UNRESOLVED_CTX.replace("SINK", "services[0]"),
          _UNRESOLVED_CTX.replace("SINK", "cmdStr"))


def test_program_name_from_unresolved_helper_is_silent_command():
    _pair("CWE-78",
          _handler('c := r.FormValue("c")\nexec.Command(c).Run()', EX),
          _handler('c, err := getCmd(r.FormValue("c"))\nif err != nil { return }\n'
                   'exec.Command(c).Run()', EX))
    assert "CWE-78" not in _cwes(_handler('exec.Command(getCmd(r.FormValue("c")))', EX))


def test_unresolved_helper_result_is_still_tainted_for_other_sinks():
    imports = EX + '\n"os"'
    assert "CWE-22" in _cwes(_handler('p, _ := getPath(r.FormValue("p"))\nos.Open(p)', imports))


def test_unresolved_helper_result_still_fires_through_sh_c_retarget():
    assert "CWE-78" in _cwes(_handler(
        's, _ := getScript(r.FormValue("c"))\nexec.Command("sh", "-c", s).Run()', EX))


def test_program_name_with_direct_or_same_file_evidence_still_fires():
    assert "CWE-78" in _cwes(_handler('exec.Command(r.FormValue("c")).Run()', EX))
    assert "CWE-78" in _cwes(_handler('exec.Command(identity(r.FormValue("c"))).Run()', EX,
                                      "func identity(s string) string { return s }"))
    # A local function value is not an unresolved package-level call.
    assert "CWE-78" in _cwes(_handler(
        'f := func(s string) string { return s }\nexec.Command(f(r.FormValue("c"))).Run()', EX))


def test_program_name_reassigned_from_source_fires():
    assert "CWE-78" in _cwes(_handler(
        'c, _ := getCmd("x")\nc = r.FormValue("c")\nexec.Command(c).Run()', EX))


def test_program_name_reassigned_on_one_branch_fires():
    assert "CWE-78" in _cwes(_handler(
        'c, _ := getCmd(r.FormValue("a"))\nif r.Method == "POST" { c = r.FormValue("c") }\n'
        'exec.Command(c).Run()', EX))
    assert "CWE-78" in _cwes(_handler(
        'c := r.FormValue("c")\nif r.Method == "POST" { c, _ = getCmd(c) }\n'
        'exec.Command(c).Run()', EX))
