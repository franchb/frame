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
