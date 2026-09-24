"""Lowering unit tests for the Go frontend (Go -> SIL)."""

from frame.sil.frontends.go_frontend import GoFrontend
from frame.sil.instructions import Call, TaintSource, Return
from frame.sil.procedure import NodeKind
from frame.sil.types import ExpBinOp, ExpConst, ExpVar


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
    fe = GoFrontend()
    p = fe.translate(src, "t.go")
    assert "go:Set.Add" in p.procedures
    adds = [n for n in _names(p.procedures["go:use"]) if n.endswith(".Add")]
    assert len(adds) == 1 and adds[0].startswith("$r_"), adds
    assert fe._site_callees[adds[0]] == "go:Set.Add"


def _prunes(proc):
    return [i for n in proc.nodes.values() for i in n.instrs if type(i).__name__ == "Prune"]


def test_named_result_shadows_package_const():
    src = '''package main
const n = 5
func f(a string) (n int) {
	n = len(a)
	if n > 3 { g() }
	return
}'''
    prunes = _prunes(_prog(src).procedures["go:f"])
    assert prunes
    for pr in prunes:
        assert isinstance(pr.condition, ExpBinOp), pr
        assert not isinstance(pr.condition.left, ExpConst), pr     # not (5 > 3)
        assert str(pr.condition.left) == "n"


def test_bare_return_returns_named_results_but_not_error():
    src = '''package main
import "net/http"
func get(r *http.Request) (s string, err error) {
	s = r.FormValue("a")
	return
}'''
    proc = _prog(src).procedures["go:get"]
    instrs = [i for n in proc.nodes.values() for i in n.instrs]
    rets = [i for i in instrs if isinstance(i, Return)]
    assert len(rets) == 1 and isinstance(rets[0].value, ExpVar)
    ret_assign = next(i for i in instrs if type(i).__name__ == "Assign"
                      and str(i.id) == str(rets[0].value.var))
    assert str(ret_assign.exp) == "s"


def test_method_value_handler_is_keyed_by_receiver_type():
    src = '''package main
import ("net/http"; "os/exec")
type Server struct{}
type Client struct{}
func (s *Server) handle(w2 Writer, req *http.Request) {}
func (c *Client) handle(req *http.Request) { exec.Command(req.URL.Path) }
func main() {
	s := &Server{}
	http.HandleFunc("/", s.handle)
}'''
    p = _prog(src)

    def sources(pname):
        return [i.var.name for n in p.procedures[pname].nodes.values() for i in n.instrs
                if isinstance(i, TaintSource)]
    assert sources("go:Server.handle") == ["req"]
    assert sources("go:Client.handle") == []


def test_method_value_with_unresolved_receiver_marks_nothing():
    src = '''package main
import "net/http"
type Server struct{}
func (s *Server) handle(req *http.Request) {}
func main() {
	http.HandleFunc("/", mk().handle)
}'''
    p = _prog(src)
    assert not any(isinstance(i, TaintSource) for n in p.procedures["go:Server.handle"].nodes.values()
                   for i in n.instrs)


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
