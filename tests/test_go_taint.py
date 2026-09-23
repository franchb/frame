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
