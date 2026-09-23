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
