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
    # False: the sink sits in the THEN branch, which is dead, so it must not
    # fire. True: the mirror image on both sides -- sink in THEN fires, sink
    # in ELSE (now the dead side) does not -- so this test can't pass by
    # walking every branch regardless of the condition's value.
    sink = _call("f", "go:os.Open", _v("p"))
    assert "filesystem" not in _branch_program([_src("p")], ExpConst.boolean(False), [sink], [], OPEN)
    assert "filesystem" in _branch_program([_src("p")], ExpConst.boolean(True), [sink], [], OPEN)
    assert "filesystem" not in _branch_program([_src("p")], ExpConst.boolean(True), [], [sink], OPEN)


def test_noreturn_names_do_not_cut_go_paths():
    # "exit" and "err" are C no-return names; in Go they are ordinary
    # identifiers and must not end the path before the sink.
    instrs = [_src("p"), _call(None, "exit"), _call("f", "go:os.Open", _v("p"))]
    assert "filesystem" in _sink_types(instrs, OPEN)
