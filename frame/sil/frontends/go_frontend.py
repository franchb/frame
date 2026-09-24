"""
Go to Frame SIL frontend.

Lowers Go (parsed by tree-sitter-go) to SIL for the shared SILTranslator. The
Go-specific parts, all syntactic (docs/superpowers/specs/2026-09-23-go-frontend-design.md):

* call resolution through a per-file import/type environment, with every
  resolved call registered under a site-unique (`$r_N.M`) or canonical
  (`go:pkg.F`) name and the program in exact-lookup mode, so no call can borrow
  another's spec;
* function literals as their own procedures (`Outer$funcN`);
* multi-value results with an untainted error slot;
* immediate / deferred / asynchronous calls kept apart, and path termination
  owned here rather than by the translator's C no-return list;
* sources rooted only in handler-shaped functions.
"""

import re
import sys
from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

try:
    import tree_sitter_go as tsgo
    from tree_sitter import Language, Parser
    TREE_SITTER_GO_AVAILABLE = True
except ImportError:
    TREE_SITTER_GO_AVAILABLE = False

from frame.sil.types import (
    Ident, PVar, Typ, Location, Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess,
)
from frame.sil.instructions import (
    Call, Assign, Prune, Return, TaintSource, TaintKind, PruneKind, Sanitize, SinkKind,
)
from frame.sil.frontends._go_guards import GuardTracker, TrustOracle
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
from frame.sil.frontends._go_env import (
    GoType, UNKNOWN, BUILTIN_TYPES, FileEnv, Scope, build_file_env,
    literal_value, params_of, statements_of, text as node_text, type_of,
)
from frame.sil.frontends._go_summaries import apply_same_file_flow, exp_vars
from frame.sil.specs.go_specs import (
    GO_SPECS, CONST_ARG0_EXEMPT, EMPTY_BUILTINS, FIELD_TYPES,
    HANDLER_REGISTRAR_FUNCS, HANDLER_REGISTRAR_METHODS, LIBRARY_PARAM_TYPES,
    MAKE_SLICE_SPEC, NON_PROPAGATING_CALLS, NON_PROPAGATING_FIELDS, NORETURN,
    OUT_PARAMS, RECEIVER_MUTATION, REQUEST_TYPE, RESPONSE_WRITER, RESULT_TYPES,
    SERVER_CONTEXT_TYPES, SHELL_COMMAND_KEYS, SHELL_FLAGS, SHELL_NAMES,
    UNRESOLVED_GUARDED_ARGS, REQUEST_DATA_TYPES, REQUEST_DATA_CALLS,
)

_EMPTY = ProcSpec(description="Go: result carries no taint")


def _package_of(path: str) -> str:
    """'net/http' for 'net/http.Request' or 'net/http.Client.Get'; '' for a
    name declared in this package ('Server')."""
    cut = path.rfind("/") + 1
    dot = path.find(".", cut)
    return path[:dot] if dot >= 0 else ""


# Imported packages some spec models: an unmodelled method on one of their
# types is still library behaviour, not a service of this program.
_MODELED_PACKAGES = frozenset(
    _package_of(k) for k in (*GO_SPECS, *FIELD_TYPES, *RESULT_TYPES, *SERVER_CONTEXT_TYPES,
                             *NON_PROPAGATING_CALLS, *OUT_PARAMS, *RECEIVER_MUTATION)) - {""}
_STRING_LITERALS = ("interpreted_string_literal", "raw_string_literal")

# Chains of an associative operator longer than this are folded as a balanced
# tree instead of left-deep. The translator walks expressions recursively
# (`__str__`, free variables) at the default recursion limit, so a 2,000-entry
# composite literal or `+` chain lowered left-deep crashed the whole file.
# Short chains keep the left-deep shape, so ordinary code lowers unchanged.
# Only associative operators are rebalanced (`+`, `*`, `&&`, `||` and the
# bitwise `|`, `&`, `^` of long flag masks); `-`, `/`, shifts and comparisons
# keep their tree.
_BALANCE_ABOVE = 64
_ASSOCIATIVE_OPS = frozenset({"+", "*", "&&", "||", "|", "&", "^"})


def _fold(op: str, exps: List[Exp]) -> Exp:
    """`e0 op e1 op ... op eN`, operand order preserved: left-deep for short
    chains, balanced (depth log2 N) for long ones."""
    if len(exps) <= _BALANCE_ABOVE:
        acc = exps[0]
        for e in exps[1:]:
            acc = ExpBinOp(op, acc, e)
        return acc
    level = list(exps)
    while len(level) > 1:
        nxt = [ExpBinOp(op, level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _same(a, b) -> bool:
    """tree-sitter returns a fresh wrapper per access, so `is` is always False;
    nodes compare equal with ==."""
    return a is not None and b is not None and a == b


class _Breakable:
    def __init__(self, break_to: Node, continue_to: Optional[Node], label: Optional[str]):
        self.break_to = break_to
        self.continue_to = continue_to      # None for switch/select
        self.label = label


class GoFrontend:
    """Translates Go source code to Frame SIL."""

    def __init__(self, specs: Optional[Dict[str, ProcSpec]] = None):
        if not TREE_SITTER_GO_AVAILABLE:
            raise ImportError("tree-sitter-go is required. "
                              "Install with: pip install tree-sitter-go")
        self.parser = Parser(Language(tsgo.language()))
        self.specs = specs or GO_SPECS
        # Set by FrameScanner in library_mode: exported functions' string /
        # []byte / io.Reader parameters are attacker-controlled.
        self.taint_exported_params = False

    # ------------------------------------------------------------------ driver
    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        self._src = source_code.encode("utf-8", errors="replace")
        self._filename = filename
        root = self.parser.parse(self._src).root_node
        self._env: FileEnv = build_file_env(root, self._src)
        self._program = Program(language="go", exact_spec_lookup=True)
        self._program.source_files.append(filename)
        self._ident_counter = 0
        self._shadow_counter = 0
        self._variant_counter = 0
        self._literal_names: Dict[int, str] = {}
        self._literal_counts: Dict[str, int] = {}
        self._site_callees: Dict[str, str] = {}
        # id(instr) -> {SIL var: sink kinds the guard tracker has Sanitize'd it
        # for on every path reaching that Call / return Assign}.
        self._guard_at: Dict[int, Dict[str, frozenset]] = {}
        self._variadic_procs: Set[str] = set()
        self._handler_nodes: Set[int] = set()
        self._handler_funcs: Set[str] = set()
        self._handler_methods: Set[Tuple[str, str]] = set()   # (receiver type, method)
        self._named_results: List[str] = []
        self._proc: Optional[Procedure] = None
        self._node: Optional[Node] = None
        self._last_call_key: Optional[str] = None
        # SIL variables whose current definition, on every path here, is the
        # result of an unresolved call (see _unresolved_only).
        self._unresolved_defs: Set[str] = set()
        # (start, end) bytes of method calls lowered by default propagation
        # on a service-like receiver (see _lower_method_call, _service_receiver).
        self._unresolved_method_calls: Set[Tuple[int, int]] = set()
        self._emitting_defers = False
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, 20000))
        try:
            self._collect_handler_registrations(root)
            self._before_lowering(root)
            self._lower_package_init(root)
            for node in root.named_children:
                if node.type in ("function_declaration", "method_declaration"):
                    try:
                        self._lower_function(node)
                    except RecursionError:
                        # Pathological nesting: skip this function, not the file.
                        fname = self._t(node.child_by_field_name("name"))
                        self._program.warnings.append(
                            f"Go frontend skipped function '{fname}' at line "
                            f"{node.start_point[0] + 1}: nesting too deep to lower")
                        continue
            self._after_lowering()
        finally:
            sys.setrecursionlimit(old_limit)
        return self._program

    # Hooks: guard facts, trusted roots and site sanitizers (_go_guards.py).
    def _before_lowering(self, root) -> None:
        self._trust = TrustOracle(root, self._src, self._env, key_of=self._call_key,
                                  is_alias=self._is_package_alias, text=self._t)
        self._guards = GuardTracker(self._src, self._trust, key_of=self._call_key,
                                    arg_nodes=self._arg_nodes, const_str=self._const_str,
                                    text=self._t, var_of=lambda n: self._sil(self._t(n)))

    def _after_lowering(self) -> None:
        apply_same_file_flow(self._program, self._site_callees, self._guard_at,
                             self._variadic_procs)

    def _record_guard_kinds(self, instr, var_names: List[str]) -> None:
        """The guard kinds holding for these variables here: the tracker's
        emitted set is restored at branches and intersected at joins, so it
        holds on every path, and the same-file summaries can use it."""
        emitted = self._guards.emitted if hasattr(self, "_guards") else {}
        kinds = {v: frozenset(emitted[v]) for v in var_names if emitted.get(v)}
        if kinds:
            self._guard_at[id(instr)] = kinds

    def _on_branch(self, cond_node, truth: bool, node: Node) -> None:
        for var, kinds in sorted(self._guards.on_branch(cond_node, truth).items()):
            node.add_instr(Sanitize(loc=self._loc(cond_node), var=PVar(var),
                                    sanitizes=[SinkKind(k) for k in sorted(kinds)],
                                    description="Go guard: " + self._t(cond_node)[:80]))

    def _on_assign(self, name: str, value_node) -> None:
        self._guards.on_assign(name, value_node)
        if value_node is not None and self._unresolved_only(value_node):
            self._unresolved_defs.add(name)
        else:
            self._unresolved_defs.discard(name)

    def _on_multi_assign(self, names: List[str], value_node) -> None:
        self._guards.on_multi_assign(names, value_node)

    def _on_function_start(self, node, receiver_name: str, param_names: Set[str]) -> None:
        self._trust.enter(node, receiver_name, param_names)

    def _on_function_end(self) -> None:
        self._trust.leave()

    def _facts_snapshot(self):
        guards = self._guards.snapshot() if hasattr(self, "_guards") else None
        return guards, frozenset(self._unresolved_defs)

    def _facts_restore(self, snap) -> None:
        guards, unresolved = snap if snap is not None else (None, frozenset())
        if hasattr(self, "_guards"):
            self._guards.restore(guards)
        self._unresolved_defs = set(unresolved)

    def _facts_join(self, snaps) -> None:
        if hasattr(self, "_guards"):
            self._guards.join([g for g, _ in snaps])
        # Unresolved-only on every incoming path, or not at all.
        self._unresolved_defs = (set(frozenset.intersection(*[u for _, u in snaps]))
                                 if snaps else set())

    def _facts_clear(self) -> None:
        # Loop heads and labels: any definition may reach, so nothing is
        # unresolved-only (the program-name sink keeps firing).
        self._unresolved_defs = set()
        if hasattr(self, "_guards"):
            self._guards.clear()

    def _adjust_site_spec(self, key: str, spec: Optional[ProcSpec], arg_nodes, arg_exps):
        spec = self._base_adjust_site_spec(key, spec, arg_nodes)
        if key in ("path/filepath.Join", "path.Join") and len(arg_nodes) == 2 \
                and self._trust.trusted(arg_nodes[0]):
            second = arg_nodes[1]
            dotdot_free = second.type == "identifier" and self._guards.implies(
                (self._t(second), "has_dotdot", "", False))
            if self._is_rooted_clean(second) or dotdot_free:
                return ProcSpec(is_sanitizer=["filesystem"], taint_propagates=[0, 1],
                                description="Go: path confined under a trusted root")
        if spec is not None and spec.is_sink in ("redirect", "ssrf") and spec.sink_args:
            idx = spec.sink_args[0]
            if idx < len(arg_nodes) and self._fixed_destination(spec.is_sink, arg_nodes[idx]):
                return replace(spec, is_sink=None, sink_args=[])
        return spec

    def _is_rooted_clean(self, node) -> bool:
        if node.type != "call_expression" or self._call_key(node) not in (
                "path/filepath.Clean", "path.Clean"):
            return False
        args = self._arg_nodes(node)
        arg = args[0] if args else None
        return (arg is not None and arg.type == "binary_expression" and self._op(arg) == "+"
                and self._const_str(arg.child_by_field_name("left")) == "/")

    def _const_prefix(self, node) -> Tuple[str, bool]:
        """(constant prefix, whole expression constant?)."""
        whole = self._const_str(node)
        if whole is not None:
            return whole, True
        if node.type == "parenthesized_expression" and node.named_children:
            return self._const_prefix(node.named_children[0])
        if node.type == "binary_expression" and self._op(node) == "+":
            left, left_full = self._const_prefix(node.child_by_field_name("left"))
            if not left_full:
                return left, False
            right, right_full = self._const_prefix(node.child_by_field_name("right"))
            return left + right, right_full
        if node.type == "call_expression" and self._call_key(node) == "fmt.Sprintf":
            args = self._arg_nodes(node)
            fmt_s = self._const_str(args[0]) if args else None
            if fmt_s is not None:
                cut = fmt_s.find("%")
                return (fmt_s, True) if cut < 0 else (fmt_s[:cut], False)
        return "", False

    def _fixed_destination(self, kind: str, node) -> bool:
        prefix, full = self._const_prefix(node)
        if full:
            return False                    # constant: carries no taint anyway
        if kind == "ssrf":
            return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+/", prefix) is not None
        return (len(prefix) >= 2 and prefix[0] == "/" and prefix[1] not in "/\\"
                and "?" in prefix)

    # ---------------------------------------------------------------- helpers
    def _t(self, node) -> str:
        return node_text(node, self._src)

    def _loc(self, node) -> Location:
        return Location(file=self._filename, line=node.start_point[0] + 1,
                        column=node.start_point[1])

    def _new_ident(self, prefix: str) -> Ident:
        self._ident_counter += 1
        return Ident(prefix, self._ident_counter)

    def _add(self, instr) -> None:
        if self._node is not None:
            self._node.add_instr(instr)

    def _new_node(self, kind: NodeKind = NodeKind.NORMAL) -> Node:
        node = self._proc.new_node(kind)
        self._proc.add_node(node)
        return node

    def _connect(self, a: Optional[Node], b: Node) -> None:
        if a is not None:
            self._proc.connect(a.id, b.id)

    def _register(self, name: str, spec: ProcSpec) -> None:
        self._program.library_specs[name] = spec

    def _variant(self, name: str) -> str:
        self._variant_counter += 1
        return f"{name}~{self._variant_counter}"

    def _opaque(self, loc: Location) -> Exp:
        """A value that is unknown but carries no taint. Not a constant, so the
        translator's constant folding cannot kill a branch that tests it."""
        ret = self._new_ident("o")
        self._add(Call(loc=loc, ret=(ret, Typ.unknown_type()),
                       func=ExpConst.string("go:opaque"), args=[]))
        self._register("go:opaque", _EMPTY)
        return ExpVar(ret)

    def _materialize(self, exp: Exp, loc: Location, prefix: str = "t") -> str:
        if isinstance(exp, ExpVar):
            return str(exp.var)
        ident = self._new_ident(prefix)
        self._add(Assign(loc=loc, id=ident, exp=exp))
        return str(ident)

    def _site_receiver(self, recv_exp: Exp, loc: Location) -> str:
        ident = self._new_ident("r")
        self._add(Assign(loc=loc, id=ident, exp=recv_exp))
        return str(ident)

    def _const_str(self, node) -> Optional[str]:
        if node is None:
            return None
        if node.type in _STRING_LITERALS:
            value = literal_value(node, self._src)
            return value if isinstance(value, str) else None
        if node.type == "identifier" and self._scope_lookup(self._t(node)) is None:
            value = self._env.consts.get(self._t(node))
            return value if isinstance(value, str) else None
        if node.type == "binary_expression" and self._op(node) == "+":
            left = self._const_str(node.child_by_field_name("left"))
            right = self._const_str(node.child_by_field_name("right"))
            return left + right if left is not None and right is not None else None
        if node.type == "parenthesized_expression" and node.named_children:
            return self._const_str(node.named_children[0])
        return None

    def _op(self, node) -> str:
        op = node.child_by_field_name("operator")
        return self._t(op) if op is not None else ""

    def _sil(self, name: str) -> str:
        """The SIL variable holding the local `name` resolves to (a shadowing
        declaration has its own); non-locals keep their name."""
        scope = getattr(self, "_scope", None)
        return scope.sil_name(name) if scope is not None else name

    def _declare(self, name: str, typ: GoType) -> str:
        """Declare a local in the current scope and return its SIL name. A
        redeclaration in the same scope (`a, err := ...; b, err := ...`) reuses
        the binding; one shadowing a local of an enclosing scope of this
        procedure gets a fresh `name#k`."""
        scope = self._scope
        if name in scope.names:
            scope.declare(name, typ)
            return scope.sil.get(name, name)
        sil = None
        if scope.shadows_local(name):
            self._shadow_counter += 1
            sil = f"{name}#{self._shadow_counter}"
        scope.declare(name, typ, sil)
        return sil or name

    def _scope_lookup(self, name: str) -> Optional[GoType]:
        scope = getattr(self, "_scope", None)
        return scope.lookup(name) if scope is not None else None

    def _is_package_alias(self, node) -> bool:
        return (node is not None and node.type == "identifier"
                and self._scope_lookup(self._t(node)) is None
                and self._env.pkg_of(self._t(node)) is not None)

    @staticmethod
    def _arg_nodes(call) -> list:
        args = call.child_by_field_name("arguments")
        if args is None:
            return []
        return [a for a in args.named_children if a.type != "comment"]

    # --------------------------------------------------------- handler shape
    def _collect_handler_registrations(self, root) -> None:
        """Route registrations name the functions that are request handlers.

        Walked in source order with a light, flow-insensitive scope per function
        (receiver, parameters, typed `var`s and `x := T{...}`-style locals) so a
        method value `s.handle` is marked by its receiver's resolved type."""
        stack = [(root, Scope())]
        while stack:
            n, scope = stack.pop()
            if n.type in ("function_declaration", "method_declaration", "func_literal"):
                scope = scope.child()
                for field in ("receiver", "parameters"):
                    for pname, ptype in params_of(n.child_by_field_name(field), self._src,
                                                  self._env.imports):
                        scope.declare(pname, ptype)
            elif n.type == "short_var_declaration":
                self._declare_prepass(scope, n.child_by_field_name("left"),
                                      n.child_by_field_name("right"))
            elif n.type == "var_spec":
                typ = type_of(n.child_by_field_name("type"), self._src, self._env.imports)
                if typ.known:
                    for name in n.children_by_field_name("name"):
                        scope.declare(self._t(name), typ)
                else:
                    self._declare_prepass(scope, None, n.child_by_field_name("value"),
                                          names=n.children_by_field_name("name"))
            stack.extend((c, scope) for c in reversed(n.named_children))
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            args = self._arg_nodes(n)
            if fn is None or fn.type != "selector_expression" or not args:
                continue
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            pkg = self._env.pkg_of(self._t(operand)) if operand is not None and operand.type == "identifier" else None
            by_func = pkg is not None and f"{pkg}.{member}" in HANDLER_REGISTRAR_FUNCS
            by_method = (pkg is None and member in HANDLER_REGISTRAR_METHODS
                         and args[0].type in _STRING_LITERALS)
            if not (by_func or by_method):
                continue
            for arg in args:
                self._mark_handler(arg, scope)

    def _declare_prepass(self, scope: Scope, left, right, names=None) -> None:
        lefts = list(names) if names is not None else (left.named_children if left is not None else [])
        rights = right.named_children if right is not None else []
        saved, self._scope = getattr(self, "_scope", None), scope
        try:
            for i, lnode in enumerate(lefts):
                typ = self._type_of(rights[i]) if len(rights) == len(lefts) else UNKNOWN
                scope.declare(self._t(lnode), typ)
        finally:
            self._scope = saved

    def _mark_handler(self, arg, scope: Scope) -> None:
        if arg.type == "func_literal":
            self._handler_nodes.add(arg.start_byte)
        elif arg.type == "identifier":
            self._handler_funcs.add(self._t(arg))
        elif arg.type == "selector_expression":
            # A method value is a handler only for its resolved receiver type:
            # an unrelated type's same-named method must not become a source.
            saved, self._scope = getattr(self, "_scope", None), scope
            try:
                recv = self._type_of(arg.child_by_field_name("operand"))
            finally:
                self._scope = saved
            if recv.known:
                self._handler_methods.add((recv.path, self._t(arg.child_by_field_name("field"))))
        elif arg.type in ("call_expression", "type_conversion_expression"):
            for inner in self._arg_nodes(arg) if arg.type == "call_expression" else arg.named_children:
                self._mark_handler(inner, scope)

    def _is_handler_shaped(self, node, receiver, params) -> bool:
        if any(t.path == RESPONSE_WRITER for _, t in params):
            return True
        if node.type == "func_literal":
            return node.start_byte in self._handler_nodes
        name = self._t(node.child_by_field_name("name"))
        if node.type == "method_declaration":
            recv_path = receiver[1].path if receiver else ""
            return name == "ServeHTTP" or (recv_path, name) in self._handler_methods
        return name in self._handler_funcs

    # ------------------------------------------------------------- procedures
    def _lower_package_init(self, root) -> None:
        """Package-level var/const values, as Assigns in a synthetic procedure,
        so the literal-secret scan and the trust oracle see them."""
        specs = [s for d in root.named_children if d.type in ("var_declaration", "const_declaration")
                 for s in d.named_children if s.type in ("var_spec", "const_spec")]
        if not specs:
            return
        proc = Procedure(name="go:$package", loc=self._loc(root))
        self._begin_proc(proc, Scope())
        for spec in specs:
            names = spec.children_by_field_name("name")
            values = spec.child_by_field_name("value")
            vals = values.named_children if values is not None else []
            for i, n in enumerate(names):
                if i < len(vals):
                    self._add(Assign(loc=self._loc(n), id=PVar(self._t(n)),
                                     exp=self._lower_expr(vals[i])))
        self._end_proc()

    def _begin_proc(self, proc: Procedure, scope: Scope) -> None:
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        self._proc, self._node, self._exit, self._scope = proc, entry, exit_node, scope
        self._defers: List[tuple] = []
        self._breakables: List[_Breakable] = []
        self._labels: Dict[str, Node] = {}
        self._gotos: List[Tuple[Node, str]] = []
        self._facts_clear()

    def _end_proc(self) -> None:
        if self._node is not None:
            self._emit_defers()
            self._connect(self._node, self._exit)
        for src_node, label in self._gotos:
            target = self._labels.get(label)
            if target is not None:
                self._proc.connect(src_node.id, target.id)
        self._program.add_procedure(self._proc)

    _STATE = ("_proc", "_node", "_exit", "_scope", "_defers", "_breakables",
              "_labels", "_gotos", "_last_call_key", "_named_results", "_result_vars")

    def _save(self):
        return {k: getattr(self, k, None) for k in self._STATE} | {"facts": self._facts_snapshot()}

    def _restore(self, saved) -> None:
        for k in self._STATE:
            setattr(self, k, saved[k])
        self._facts_restore(saved["facts"])

    def _lower_function(self, node, name: Optional[str] = None,
                        outer_scope: Optional[Scope] = None) -> str:
        is_method = node.type == "method_declaration"
        params = params_of(node.child_by_field_name("parameters"), self._src, self._env.imports)
        receiver = None
        if is_method:
            recv = params_of(node.child_by_field_name("receiver"), self._src, self._env.imports)
            receiver = recv[0] if recv else ("", UNKNOWN)
        if name is None:
            base = self._t(node.child_by_field_name("name"))
            name = f"go:{receiver[1].path}.{base}" if is_method else f"go:{base}"
        all_params = ([receiver] if receiver else []) + params
        plist = node.child_by_field_name("parameters")
        if plist is not None and plist.named_children \
                and plist.named_children[-1].type == "variadic_parameter_declaration":
            self._variadic_procs.add(name)
        results = params_of(node.child_by_field_name("result"), self._src, self._env.imports)
        proc = Procedure(
            name=name,
            params=[(PVar(n or f"$p{i}"), Typ.unknown_type()) for i, (n, _) in enumerate(all_params)],
            loc=self._loc(node), is_method=is_method,
            class_name=receiver[1].path if receiver else None)
        saved = self._save()
        self._begin_proc(proc, Scope(outer_scope or Scope(), proc_root=True))
        for pname, ptype in all_params:
            self._scope.declare(pname, ptype)
        # Named results are locals: they shadow package consts, and a bare
        # `return` returns them.
        named = [(n, t) for n, t in results if n]
        for rname, rtype in named:
            self._scope.declare(rname, rtype)
        self._result_vars = frozenset(n for n, _ in named)
        self._named_results = [
            n for i, (n, t) in enumerate(named)
            if n != "_" and t.path != "error" and not (i == len(named) - 1 and n == "err")]
        self._on_function_start(node, receiver[0] if receiver else "",
                                {n for n, _ in params if n})
        try:
            self._emit_param_sources(node, proc, receiver, params)
            self._lower_block(node.child_by_field_name("body"))
            self._end_proc()
        finally:
            # Also on a RecursionError skip, so the trust oracle's frame stack
            # and the lowering state do not leak into the next function.
            self._on_function_end()
            self._restore(saved)
        return name

    def _emit_param_sources(self, node, proc, receiver, params) -> None:
        handler = self._is_handler_shaped(node, receiver, params)
        exported = self._is_exported(node)
        for pname, ptype in ([receiver] if receiver else []) + params:
            if not pname:
                continue
            why = None
            if ptype.path in SERVER_CONTEXT_TYPES:
                why = "server request context"
            elif ptype.path == REQUEST_TYPE and handler:
                why = "handler request"
            elif (self.taint_exported_params and exported and (pname, ptype) != receiver
                  and ptype.path in LIBRARY_PARAM_TYPES):
                why = "exported library parameter"
            if why:
                self._add(TaintSource(loc=proc.loc, var=PVar(pname), kind=TaintKind.USER_INPUT,
                                      description=f"Go {why}: {pname}"))

    def _is_exported(self, node) -> bool:
        if node.type == "func_literal":
            return False
        return self._t(node.child_by_field_name("name"))[:1].isupper()

    def _lower_func_literal(self, node) -> str:
        name = self._literal_names.get(node.start_byte)
        if name is None:
            outer = self._proc.name if self._proc is not None else "go:$package"
            k = self._literal_counts.get(outer, 0) + 1
            self._literal_counts[outer] = k
            name = f"{outer}$func{k}"
            self._literal_names[node.start_byte] = name
            self._lower_function(node, name=name, outer_scope=self._scope)
        return name

    # -------------------------------------------------------------- statements
    def _lower_block(self, block) -> None:
        if block is None:
            return
        outer = self._scope
        self._scope = outer.child()
        for stmt in statements_of(block):
            self._lower_stmt(stmt)
        self._scope = outer

    def _lower_stmt(self, node, label: Optional[str] = None) -> None:
        t = node.type
        self._last_call_key = None
        if t == "expression_statement":
            if node.named_children:
                self._lower_expr(node.named_children[0])
                self._maybe_terminate()
        elif t == "short_var_declaration":
            self._lower_assign(node.child_by_field_name("left"),
                               node.child_by_field_name("right"), declare=True)
        elif t == "assignment_statement":
            op = self._op(node)
            if op in ("=", ""):
                self._lower_assign(node.child_by_field_name("left"),
                                   node.child_by_field_name("right"), declare=False)
            else:
                self._lower_compound_assign(node, op[:-1])
        elif t in ("var_declaration", "const_declaration"):
            for spec in node.named_children:
                if spec.type in ("var_spec", "const_spec"):
                    self._lower_var_spec(spec)
        elif t == "return_statement":
            self._lower_return(node)
        elif t == "if_statement":
            self._lower_if(node)
        elif t == "for_statement":
            self._lower_for(node, label)
        elif t in ("expression_switch_statement", "type_switch_statement", "select_statement"):
            self._lower_switch(node, label)
        elif t == "defer_statement":
            self._lower_defer(node)
        elif t == "go_statement":
            if node.named_children:
                self._lower_expr(node.named_children[0])   # asynchronous: never terminates
        elif t == "labeled_statement":
            self._lower_labeled(node)
        elif t in ("break_statement", "continue_statement"):
            self._lower_jump(node, t == "continue_statement")
        elif t == "goto_statement":
            lab = next((c for c in node.named_children if c.type == "label_name"), None)
            if self._node is not None and lab is not None:
                self._gotos.append((self._node, self._t(lab)))
            self._node = None
        elif t == "block":
            self._lower_block(node)
        elif t == "send_statement":
            for c in node.named_children:
                self._lower_expr(c)
        # inc/dec, empty, fallthrough (handled in switch), comments: no taint effect

    def _maybe_terminate(self) -> None:
        key = self._last_call_key
        if key in NORETURN and self._node is not None:
            if NORETURN[key]:
                self._emit_defers()
            self._connect(self._node, self._exit)
            self._node = None

    def _lower_var_spec(self, spec) -> None:
        typ = type_of(spec.child_by_field_name("type"), self._src, self._env.imports)
        names = spec.children_by_field_name("name")
        values = spec.child_by_field_name("value")
        if values is None:
            for n in names:
                if self._t(n) == "_":
                    continue
                sil = self._declare(self._t(n), typ)
                self._on_assign(sil, None)
                self._add(Assign(loc=self._loc(n), id=PVar(sil), exp=self._opaque(self._loc(n))))
            return
        self._lower_assign_lists(names, values.named_children, declare=True, declared=typ)

    def _lower_assign(self, left, right, declare: bool) -> None:
        lefts = left.named_children if left is not None else []
        rights = right.named_children if right is not None else []
        self._lower_assign_lists(lefts, rights, declare)

    def _lower_assign_lists(self, lefts, rights, declare: bool, declared: GoType = UNKNOWN) -> None:
        if len(rights) == 1 and len(lefts) > 1:
            rnode = rights[0]
            value = self._lower_expr(rnode)
            result_types = self._result_types(rnode)
            for i, lnode in enumerate(lefts):
                if self._t(lnode) == "_":
                    continue
                typ = declared if declared.known else (result_types[i] if i < len(result_types) else UNKNOWN)
                untainted = (i > 0 and rnode.type in ("index_expression", "type_assertion_expression",
                                                      "unary_expression")) \
                    or typ.path == "error" \
                    or (i == len(lefts) - 1 and self._t(lnode) == "err")
                exp = self._opaque(self._loc(lnode)) if untainted else value
                self._assign_target(lnode, exp, declare, typ, rnode if not untainted else None)
            self._on_multi_assign([self._sil(self._t(l)) if l.type == "identifier" else self._t(l)
                                   for l in lefts], rnode)
            return
        values = [self._lower_expr(r) for r in rights]      # all RHS first: a, b = b, a
        for lnode, value, rnode in zip(lefts, values, rights):
            typ = declared if declared.known else self._type_of(rnode)
            self._assign_target(lnode, value, declare, typ, rnode)

    def _assign_target(self, lnode, value: Exp, declare: bool, typ: GoType, value_node) -> None:
        loc = self._loc(lnode)
        t = lnode.type
        if t == "identifier":
            name = self._t(lnode)
            if name == "_":
                return
            name = self._declare(name, typ) if declare else self._sil(name)
            self._add(Assign(loc=loc, id=PVar(name), exp=value))
            self._on_assign(name, value_node)
        elif t in ("selector_expression", "index_expression"):
            # Field-insensitive weak update: the base object absorbs the value.
            base_node = lnode.child_by_field_name("operand")
            base = self._base_var(base_node)
            if base is not None:
                self._add(Assign(loc=loc, id=PVar(base),
                                 exp=ExpBinOp("+", ExpVar(PVar(base)), value)))
                self._on_assign(base, None)
            if t == "index_expression":
                self._lower_expr(lnode.child_by_field_name("index"))
        elif t == "unary_expression" and lnode.named_children:          # *p = v
            self._assign_target(lnode.named_children[-1], value, False, typ, value_node)
        elif t == "parenthesized_expression" and lnode.named_children:
            self._assign_target(lnode.named_children[0], value, declare, typ, value_node)

    def _base_var(self, node) -> Optional[str]:
        while node is not None and node.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression", "unary_expression"):
            node = (node.child_by_field_name("operand") if node.type != "parenthesized_expression"
                    else (node.named_children[0] if node.named_children else None))
            if node is not None and node.type == "unary_expression":
                node = node.named_children[-1] if node.named_children else None
        if node is not None and node.type == "identifier" and not self._is_package_alias(node):
            return self._sil(self._t(node))
        return None

    def _lower_compound_assign(self, node, op: str) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        lnode = left.named_children[0] if left is not None and left.named_children else None
        rnode = right.named_children[0] if right is not None and right.named_children else None
        if lnode is None or rnode is None:
            return
        value = ExpBinOp(op, self._lower_expr(lnode), self._lower_expr(rnode))
        self._assign_target(lnode, value, False, self._type_of(lnode), None)

    def _lower_return(self, node) -> None:
        loc = self._loc(node)
        values = []
        for expr_list in node.named_children:
            items = expr_list.named_children if expr_list.type == "expression_list" else [expr_list]
            values.extend(self._lower_expr(v) for v in items)
        value = None
        results = self._proc_results()
        kept = [v for i, v in enumerate(values)
                if not (i < len(results) and results[i].path == "error")]
        if not values:                      # bare return: the named results
            kept = [ExpVar(PVar(n)) for n in (self._named_results or [])]
        if kept:
            value = _fold("+", kept)
        if value is not None:
            ret_var = self._new_ident("ret")
            ret_assign = Assign(loc=loc, id=ret_var, exp=value)
            self._add(ret_assign)
            self._record_guard_kinds(ret_assign, exp_vars(value))
            value = ExpVar(ret_var)
        self._emit_defers()                 # operands first, then deferred calls
        self._add(Return(loc=loc, value=value))
        self._connect(self._node, self._exit)
        self._node = None

    def _proc_results(self) -> List[GoType]:
        name = self._proc.name[3:] if self._proc.name.startswith("go:") else ""
        if "$" in name:
            return []
        sig = self._env.funcs.get(name)
        if sig is None and "." in name:
            sig = self._env.methods.get(tuple(name.rsplit(".", 1)))
        return sig.results if sig is not None else []

    def _branch(self, before: Optional[Node], cond: Exp, true_node: Node, false_node: Node,
                loc: Location, true_kind: PruneKind, false_kind: PruneKind) -> None:
        """A clean 2-way branch in the layout SILTranslator is built for: both
        prunes in the branching node, successor 0 = true side, successor 1 =
        false side. `_branch_edge_formula` derives the per-edge feasibility
        guards (CWE-770 bound check, infeasible-path filter) and constant-folding
        edge skips from exactly this shape."""
        if before is None:
            return
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=True, kind=true_kind))
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=False, kind=false_kind))
        self._proc.connect(before.id, true_node.id)
        self._proc.connect(before.id, false_node.id)

    def _lower_if(self, node) -> None:
        outer = self._scope
        self._scope = outer.child()
        init = node.child_by_field_name("initializer")
        if init is not None:
            self._lower_stmt(init)
        cond_node = node.child_by_field_name("condition")
        # A literal bool Prune is constant-folded for Go: a (broken-parse) missing
        # condition must stay opaque.
        cond = self._lower_expr(cond_node) if cond_node is not None else self._opaque(self._loc(node))
        before = self._node
        base = self._facts_snapshot()
        loc = self._loc(node)
        then_node, else_node = self._new_node(), self._new_node()
        join = self._new_node(NodeKind.JOIN)
        self._branch(before, cond, then_node, else_node, loc, PruneKind.IF_TRUE, PruneKind.IF_FALSE)
        ends = []
        for truth, branch, bnode in ((True, node.child_by_field_name("consequence"), then_node),
                                     (False, node.child_by_field_name("alternative"), else_node)):
            self._node = bnode
            self._facts_restore(base)
            if cond_node is not None:
                self._on_branch(cond_node, truth, bnode)
            if branch is not None:
                if branch.type == "if_statement":
                    self._lower_if(branch)
                else:
                    self._lower_block(branch)
            if self._node is not None:
                self._connect(self._node, join)
                ends.append(self._facts_snapshot())
        self._facts_join(ends)
        self._node = join if join.preds else None
        self._scope = outer

    def _lower_for(self, node, label: Optional[str]) -> None:
        outer = self._scope
        self._scope = outer.child()
        loc = self._loc(node)
        body = node.child_by_field_name("body")
        clause = next((c for c in node.named_children if c.type in ("for_clause", "range_clause")), None)
        cond_node = update = None
        range_value = None
        if clause is not None and clause.type == "for_clause":
            init = clause.child_by_field_name("initializer")
            if init is not None:
                self._lower_stmt(init)
            cond_node = clause.child_by_field_name("condition")
            update = clause.child_by_field_name("update")
        elif clause is not None:
            range_value = self._lower_expr(clause.child_by_field_name("right"))
        else:
            cond_node = next((c for c in node.named_children
                              if not _same(c, body) and c.type != "comment"), None)
        self._facts_clear()
        head = self._new_node(NodeKind.LOOP_HEAD)
        self._connect(self._node, head)
        exit_node = self._new_node(NodeKind.JOIN)
        body_node = self._new_node()
        self._node = head
        if cond_node is not None:
            cond = self._lower_expr(cond_node)          # calls in the condition run in the head
            self._branch(head, cond, body_node, exit_node, loc,
                         PruneKind.LOOP_ENTER, PruneKind.LOOP_EXIT)
        else:
            self._proc.connect(head.id, body_node.id)
            if range_value is not None:                 # range may run zero times
                self._proc.connect(head.id, exit_node.id)
        cont = self._new_node() if update is not None else head
        self._breakables.append(_Breakable(exit_node, cont, label))
        self._node = body_node
        if range_value is not None:
            left = clause.child_by_field_name("left")
            declare = any(c.type == ":=" for c in clause.children)
            for lnode in (left.named_children if left is not None else []):
                self._assign_target(lnode, range_value, declare, UNKNOWN, None)
        self._lower_block(body)
        self._breakables.pop()
        if self._node is not None:
            self._connect(self._node, cont)
        if update is not None:
            self._node = cont
            self._lower_stmt(update)
            self._connect(self._node, head)
        self._facts_clear()
        self._node = exit_node if exit_node.preds else None
        self._scope = outer

    def _lower_switch(self, node, label: Optional[str]) -> None:
        """Expression cases become a chain of clean 2-way tests (the translator's
        branch layout); type-switch and select cases, which have no value
        condition, are nondeterministic successors of the test node."""
        outer = self._scope
        self._scope = outer.child()
        loc = self._loc(node)
        init = node.child_by_field_name("initializer")
        if init is not None:
            self._lower_stmt(init)
        tag_node = node.child_by_field_name("value")
        tag = self._lower_expr(tag_node) if tag_node is not None and node.type != "select_statement" else None
        alias = node.child_by_field_name("alias")
        base = self._facts_snapshot()
        exit_node = self._new_node(NodeKind.JOIN)
        cases = [c for c in node.named_children
                 if c.type in ("expression_case", "type_case", "default_case", "communication_case")]
        case_nodes = [self._new_node() for _ in cases]
        default_idx = next((i for i, c in enumerate(cases) if c.type == "default_case"), None)
        ends = []
        test = self._node
        for i, case in enumerate(cases):
            if case.type == "expression_case":
                self._node = test
                vals = case.child_by_field_name("value")
                conds = []
                for v in (vals.named_children if vals is not None else []):
                    ve = self._lower_expr(v)
                    conds.append(ExpBinOp("==", tag, ve) if tag is not None else ve)
                if not conds:
                    continue
                cond = _fold("||", conds)
                nxt = self._new_node()
                self._branch(test, cond, case_nodes[i], nxt, loc,
                             PruneKind.SWITCH_CASE, PruneKind.SWITCH_CASE)
                test = nxt if test is not None else None
            elif case.type in ("type_case", "communication_case"):
                self._connect(test, case_nodes[i])
        if default_idx is not None:
            self._connect(test, case_nodes[default_idx])
        elif node.type != "select_statement":
            self._connect(test, exit_node)
            ends.append(base)
        self._breakables.append(_Breakable(exit_node, None, label))
        for i, (case, cnode) in enumerate(zip(cases, case_nodes)):
            self._node = cnode if cnode.preds else None
            self._facts_restore(base)
            self._scope = self._scope.child()
            if case.type == "type_case" and alias is not None and alias.named_children and tag_node is not None:
                ctype = type_of(case.child_by_field_name("type"), self._src, self._env.imports)
                aname = self._t(alias.named_children[0])
                tag_exp = self._lower_expr(tag_node)
                if aname != "_":
                    aname = self._declare(aname, ctype)
                    self._add(Assign(loc=loc, id=PVar(aname), exp=tag_exp))
                    self._on_assign(aname, None)
            elif case.type == "communication_case":
                comm = case.child_by_field_name("communication")
                if comm is not None:
                    self._lower_stmt(comm)
            header = ([case.child_by_field_name("value"), case.child_by_field_name("communication")]
                      + list(case.children_by_field_name("type")))
            stmts = [s for s in statements_of(case)
                     if not any(_same(s, h) for h in header)]
            falls = bool(stmts) and stmts[-1].type == "fallthrough_statement"
            for s in stmts:
                self._lower_stmt(s)
            self._scope = self._scope.parent
            if self._node is not None:
                target = case_nodes[i + 1] if falls and i + 1 < len(case_nodes) else exit_node
                self._connect(self._node, target)
                if target is exit_node:
                    ends.append(self._facts_snapshot())
        self._breakables.pop()
        self._facts_join(ends)
        self._node = exit_node if exit_node.preds else None
        self._scope = outer

    def _lower_labeled(self, node) -> None:
        lab = node.child_by_field_name("label")
        name = self._t(lab)
        target = self._new_node()
        self._connect(self._node, target)
        self._labels[name] = target
        self._node = target
        self._facts_clear()
        inner = [c for c in node.named_children if not _same(c, lab)]
        if inner:
            self._lower_stmt(inner[0], label=name)

    def _lower_jump(self, node, is_continue: bool) -> None:
        lab = next((c for c in node.named_children if c.type == "label_name"), None)
        name = self._t(lab) if lab is not None else None
        for b in reversed(self._breakables):
            if is_continue and b.continue_to is None:
                continue
            if name is None or b.label == name:
                self._connect(self._node, b.continue_to if is_continue else b.break_to)
                break
        self._node = None

    def _lower_defer(self, node) -> None:
        call = node.named_children[0] if node.named_children else None
        if call is None or call.type != "call_expression":
            return
        loc = self._loc(node)
        fn = call.child_by_field_name("function")
        pre_recv = None
        if fn is not None and fn.type == "selector_expression" and not self._is_package_alias(
                fn.child_by_field_name("operand")):
            pre_recv = ExpVar(PVar(self._materialize(
                self._lower_expr(fn.child_by_field_name("operand")), loc, "d")))
        pre_args = [ExpVar(PVar(self._materialize(self._lower_expr(a), loc, "d")))
                    for a in self._arg_nodes(call)]
        if fn is not None and fn.type == "func_literal":
            self._lower_func_literal(fn)
        self._defers.append((call, pre_args, pre_recv))

    def _emit_defers(self) -> None:
        if self._node is None:
            return
        pending, self._defers = self._defers, []
        # The definitions reaching an exit are not those at the `defer`.
        was, self._emitting_defers = self._emitting_defers, True
        try:
            for call, pre_args, pre_recv in reversed(pending):
                self._lower_call(call, pre_args=pre_args, pre_recv=pre_recv)
        finally:
            self._emitting_defers = was
        self._defers = pending

    # ------------------------------------------------------------- expressions
    def _lower_expr(self, node) -> Exp:
        if node is None:
            return ExpConst.null()
        t = node.type
        loc = self._loc(node)
        if t in _STRING_LITERALS or t == "rune_literal":
            value = literal_value(node, self._src)
            return ExpConst.string(value if isinstance(value, str) else self._t(node))
        if t == "int_literal":
            value = literal_value(node, self._src)
            return ExpConst.integer(value) if isinstance(value, int) else self._opaque(loc)
        if t in ("float_literal", "imaginary_literal"):
            return self._opaque(loc)
        if t == "true":
            return ExpConst.boolean(True)
        if t == "false":
            return ExpConst.boolean(False)
        if t == "nil":
            return ExpConst.null()
        if t == "identifier":
            name = self._t(node)
            if self._scope_lookup(name) is None:
                if name in self._env.consts and self._env.consts[name] is not None:
                    value = self._env.consts[name]
                    return ExpConst.string(value) if isinstance(value, str) else (
                        ExpConst.integer(value) if isinstance(value, int) and not isinstance(value, bool)
                        else self._opaque(loc))
                if name in ("true", "false"):
                    return ExpConst.boolean(name == "true")
                if name in ("nil", "iota"):
                    return self._opaque(loc)
                return ExpVar(PVar(name))
            return ExpVar(PVar(self._sil(name)))
        if t == "parenthesized_expression":
            return self._lower_expr(node.named_children[0]) if node.named_children else ExpConst.null()
        if t == "call_expression":
            return self._lower_call(node)
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            field_name = self._t(node.child_by_field_name("field"))
            if self._is_package_alias(operand):
                return ExpVar(PVar(f"go:{self._env.pkg_of(self._t(operand))}.{field_name}"))
            base_type = self._type_of(operand)
            if base_type.known and f"{base_type.path}.{field_name}" in NON_PROPAGATING_FIELDS:
                return self._opaque(loc)
            return ExpFieldAccess(self._lower_expr(operand), field_name)
        if t == "index_expression":
            base = self._lower_expr(node.child_by_field_name("operand"))
            self._lower_expr(node.child_by_field_name("index"))       # side effects only
            return ExpFieldAccess(base, "[]")
        if t == "slice_expression":
            for f in ("start", "end", "capacity"):
                part = node.child_by_field_name(f)
                if part is not None:
                    self._lower_expr(part)
            return self._lower_expr(node.child_by_field_name("operand"))
        if t in ("type_assertion_expression", "type_conversion_expression"):
            return self._lower_expr(node.child_by_field_name("operand"))
        if t == "unary_expression":
            op = self._op(node)
            operand = self._lower_expr(node.child_by_field_name("operand"))
            if op in ("&", "*", "+"):
                return operand
            return ExpUnOp(op, operand)
        if t == "binary_expression":
            op = self._op(node)
            if op in _ASSOCIATIVE_OPS:
                # Walk the left spine of a same-operator chain iteratively.
                operands = [node.child_by_field_name("right")]
                left = node.child_by_field_name("left")
                while left is not None and left.type == "binary_expression" \
                        and self._op(left) == op:
                    operands.append(left.child_by_field_name("right"))
                    left = left.child_by_field_name("left")
                operands.append(left)
                operands.reverse()
                return _fold(op, [self._lower_expr(o) for o in operands])
            return ExpBinOp(op, self._lower_expr(node.child_by_field_name("left")),
                            self._lower_expr(node.child_by_field_name("right")))
        if t == "composite_literal":
            return self._lower_composite(node, loc)
        if t == "func_literal":
            return ExpConst.string(self._lower_func_literal(node))
        return self._opaque(loc)

    def _lower_composite(self, node, loc) -> Exp:
        values: List[Exp] = []
        stack = [node.child_by_field_name("body")]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            for c in n.named_children:
                if c.type == "keyed_element":
                    kids = c.named_children
                    if len(kids) >= 2:
                        stack.append(kids[-1])
                elif c.type == "literal_element":
                    stack.append(c)
                elif c.type == "literal_value":
                    stack.append(c)
                else:
                    values.append(self._lower_expr(c))
        dynamic = [v for v in values if not isinstance(v, ExpConst)]
        if not dynamic:
            return self._opaque(loc)
        return _fold("+", dynamic)

    # ------------------------------------------------------------------ calls
    def _lower_call(self, node, pre_args=None, pre_recv=None) -> Exp:
        loc = self._loc(node)
        fn = node.child_by_field_name("function")
        arg_nodes = self._arg_nodes(node)
        while fn is not None and fn.type in ("parenthesized_expression", "index_expression",
                                             "generic_type"):
            fn = (fn.child_by_field_name("operand") or fn.child_by_field_name("type")
                  or (fn.named_children[0] if fn.named_children else None))
        if fn is None:
            return self._opaque(loc)

        def args() -> List[Exp]:
            return pre_args if pre_args is not None else [self._lower_expr(a) for a in arg_nodes]

        if fn.type == "func_literal":
            name = self._lower_func_literal(fn)
            return self._emit_call(loc, name, args(), callee_proc=name)
        if fn.type == "identifier":
            name = self._t(fn)
            if self._scope_lookup(name) is None:
                if name in BUILTIN_TYPES or name in self._env.local_types:
                    return args()[0] if (arg_nodes or pre_args) else self._opaque(loc)
                if name in ("make", "append", "copy", "panic", "min", "max") or name in EMPTY_BUILTINS:
                    return self._lower_builtin(name, node, arg_nodes, args(), loc)
                if name in self._env.funcs:
                    return self._emit_call(loc, f"go:{name}", args(), callee_proc=f"go:{name}")
            return self._emit_call(loc, name, args())
        if fn.type == "selector_expression":
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            if pre_recv is None and self._is_package_alias(operand):
                pkg = self._env.pkg_of(self._t(operand))
                return self._lower_package_call(pkg, member, arg_nodes, args(), loc)
            recv_exp = pre_recv if pre_recv is not None else self._lower_expr(operand)
            return self._lower_method_call(operand, recv_exp, self._type_of(operand),
                                           member, arg_nodes, args(), loc, call_node=node)
        callee = self._lower_expr(fn)
        return self._emit_call(loc, f"{self._materialize(callee, loc)}()", args())

    def _emit_call(self, loc, name: str, arg_exps: List[Exp], spec: Optional[ProcSpec] = None,
                   callee_proc: Optional[str] = None, key: Optional[str] = None) -> Exp:
        ret = self._new_ident("c")
        call = Call(loc=loc, ret=(ret, Typ.unknown_type()), func=ExpConst.string(name),
                    args=[(a, Typ.unknown_type()) for a in arg_exps])
        self._add(call)
        names = [v for a in arg_exps for v in exp_vars(a)]
        if "." in name and not name.startswith("go:"):
            names.append(name.rsplit(".", 1)[0])
        self._record_guard_kinds(call, names)
        if spec is not None:
            self._register(name, spec)
        if callee_proc is not None:
            self._site_callees[name] = callee_proc
        self._last_call_key = key
        return ExpVar(ret)

    def _lower_builtin(self, name, node, arg_nodes, arg_exps, loc) -> Exp:
        if name == "make":
            first = arg_nodes[0] if arg_nodes else None
            type_exp = ExpConst.string(self._t(first) if first is not None else "")
            if first is not None and first.type == "slice_type":
                out = self._emit_call(loc, "go:make", [type_exp] + arg_exps[1:], spec=MAKE_SLICE_SPEC)
            else:
                out = self._emit_call(loc, "go:make$other", [type_exp] + arg_exps[1:], spec=_EMPTY)
            return out
        if name == "copy" and len(arg_nodes) >= 2:
            base = self._base_var(arg_nodes[0])
            if base is not None:
                self._add(Assign(loc=loc, id=PVar(base),
                                 exp=ExpBinOp("+", ExpVar(PVar(base)), arg_exps[1])))
            return self._opaque(loc)
        if name in EMPTY_BUILTINS or name == "panic":
            return self._emit_call(loc, f"go:{name}", arg_exps, spec=_EMPTY, key=name)
        return self._emit_call(loc, f"go:{name}", arg_exps)          # append, min, max: default

    def _lower_package_call(self, pkg: str, member: str, arg_nodes, arg_exps, loc) -> Exp:
        key = f"{pkg}.{member}"
        name = f"go:{key}"
        base = self.specs.get(key)
        spec = self._adjust_site_spec(key, base, arg_nodes, arg_exps)
        if spec is not base:
            name = self._variant(name)
        out = self._emit_call(loc, name, arg_exps, spec=spec, key=key)
        self._apply_out_params(key, arg_nodes, out, loc)
        return out

    def _lower_method_call(self, operand, recv_exp, recv_type: GoType, member, arg_nodes,
                           arg_exps, loc, call_node=None) -> Exp:
        key = f"{recv_type.path}.{member}" if recv_type.known else None
        if key is not None and key in NON_PROPAGATING_CALLS:
            self._last_call_key = key
            return self._opaque(loc)
        if key is not None and (recv_type.path, member) in self._env.methods:
            site = self._site_receiver(recv_exp, loc)
            return self._emit_call(loc, f"{site}.{member}", arg_exps,
                                   callee_proc=f"go:{key}", key=key)
        base = self.specs.get(key) if key is not None else None
        if key is not None and (base is not None or key in OUT_PARAMS or key in RECEIVER_MUTATION):
            spec = self._adjust_site_spec(key, base, arg_nodes, arg_exps)
            site = self._site_receiver(recv_exp, loc)
            out = self._emit_call(loc, f"{site}.{member}", arg_exps, spec=spec, key=key)
            self._apply_out_params(key, arg_nodes, out, loc)
            if key in RECEIVER_MUTATION:
                self._assign_target(operand, ExpBinOp("+", recv_exp, self._join(arg_exps)),
                                    False, recv_type, None)
            return out
        if (call_node is not None and self._service_receiver(operand, recv_type)
                and not self._passes_request(arg_nodes)):
            self._unresolved_method_calls.add((call_node.start_byte, call_node.end_byte))
        recv_var = self._materialize(recv_exp, loc)
        return self._emit_call(loc, f"{recv_var}.{member}", arg_exps, key=key)

    @staticmethod
    def _join(exps: List[Exp]) -> Exp:
        if not exps:
            return ExpConst.string("")
        return _fold("+", exps)

    def _apply_out_params(self, key: str, arg_nodes, out: Exp, loc) -> None:
        for idx in OUT_PARAMS.get(key, ()):
            if idx >= len(arg_nodes):
                break
            target = arg_nodes[idx]
            if target.type == "unary_expression" and target.named_children:
                target = target.named_children[-1]
            if target.type in ("identifier", "selector_expression", "index_expression"):
                self._assign_target(target, out, False, self._type_of(target), None)

    def _base_adjust_site_spec(self, key: str, spec: Optional[ProcSpec], arg_nodes):
        """Per-site spec changes that need only the call's own arguments."""
        if key in SHELL_COMMAND_KEYS and spec is not None:
            off = SHELL_COMMAND_KEYS[key]
            if (len(arg_nodes) > off + 2 and self._const_str(arg_nodes[off]) in SHELL_NAMES
                    and self._const_str(arg_nodes[off + 1]) in SHELL_FLAGS):
                return replace(spec, sink_args=[off + 2])
        if key in UNRESOLVED_GUARDED_ARGS and spec is not None:
            # Program name / redirect or SSRF destination: a value whose only
            # definition is the result of a call this file cannot see carries
            # taint only by default propagation (every input to every result).
            # That is kept for every other sink and for further propagation,
            # but is not evidence enough that the executable or the
            # destination itself is attacker-chosen.
            off = UNRESOLVED_GUARDED_ARGS[key]
            if (len(arg_nodes) > off and not self._emitting_defers
                    and self._unresolved_only(arg_nodes[off])):
                return replace(spec, is_sink=None, sink_args=[])
        if key in CONST_ARG0_EXEMPT and arg_nodes and self._const_str(arg_nodes[0]) is not None:
            return replace(spec, is_sink=None, sink_args=[]) if spec is not None else None
        return spec

    _NON_CALL_BUILTINS = frozenset({"make", "append", "copy", "panic", "min", "max"})

    def _is_unresolved_bare_call(self, node) -> bool:
        """A call `f(...)` to a bare identifier that names nothing in this
        file or the language: in practice a same-package function defined in
        another file (e.g. a platform-specific `_linux.go` / `_windows.go`
        variant), whose body and summary the per-file frontend cannot see."""
        if node is None or node.type != "call_expression":
            return False
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "identifier":
            return False
        name = self._t(fn)
        env = self._env
        return (self._scope_lookup(name) is None and name not in env.funcs
                and name not in env.local_types and name not in env.package_vars
                and name not in env.consts and name not in BUILTIN_TYPES
                and name not in self._NON_CALL_BUILTINS and name not in EMPTY_BUILTINS
                and not self._passes_request(self._arg_nodes(node)))

    def _passes_request(self, arg_nodes) -> bool:
        """Does an argument hand over the request, or bulk data of it, rather
        than one value read from it? A call that takes the request is an
        accessor in disguise (a cookie or session reader, a binder, a callback
        parser): its result is request data."""
        return any(self._is_request_data(a) for a in arg_nodes)

    def _is_request_data(self, node) -> bool:
        """The request / server context itself or a field of it (`r`, `&r`,
        `*r`, `r.Header`, `r.Body`, `c`); a value of a bulk request-data type
        (`r.URL`, `r.URL.Query()`, `q := r.URL.Query()`, a cookie); the result
        of `r.Cookies()`; or a composite literal carrying any of them
        (`Params{Req: r}`). Not a scalar accessor result (`r.FormValue(k)`,
        `q.Get(k)`) and not `r.Context()`."""
        while node is not None and node.type in ("parenthesized_expression", "unary_expression"):
            node = (node.child_by_field_name("operand") if node.type == "unary_expression"
                    else (node.named_children[0] if node.named_children else None))
        if node is None:
            return False
        if node.type == "composite_literal":
            stack = [node.child_by_field_name("body")]
            while stack:
                lit = stack.pop()
                for c in (lit.named_children if lit is not None else []):
                    if c.type in ("keyed_element", "literal_element"):
                        val = c.named_children[-1] if c.named_children else None
                        if val is not None and val.type == "literal_element" and val.named_children:
                            val = val.named_children[0]
                        if val is None:
                            continue
                        if val.type == "literal_value":
                            stack.append(val)
                        elif self._is_request_data(val):
                            return True
                    elif c.type == "literal_value":
                        stack.append(c)
                    elif c.type != "comment" and self._is_request_data(c):
                        return True
            return False
        if self._type_of(node).path in REQUEST_DATA_TYPES:
            return True
        if node.type == "call_expression":
            return self._call_key(node) in REQUEST_DATA_CALLS
        root = node
        while root is not None and root.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression"):
            root = (root.child_by_field_name("operand") if root.type != "parenthesized_expression"
                    else (root.named_children[0] if root.named_children else None))
        if root is not None and root.type == "identifier":
            typ = self._scope_lookup(self._t(root))
            return typ is not None and (typ.path == REQUEST_TYPE or typ.path in SERVER_CONTEXT_TYPES)
        return False

    def _unresolved_only(self, node) -> bool:
        """Is this value, on every path reaching here, exactly the result of an
        unresolved call -- a bare-identifier call this file cannot see, or a
        method call on a service-like receiver (_service_receiver) -- directly,
        through a field / index read of one, or through a variable whose
        current definition is one?"""
        while node is not None and node.type == "parenthesized_expression" and node.named_children:
            node = node.named_children[0]
        if node is None:
            return False
        if node.type == "identifier":
            return self._sil(self._t(node)) in self._unresolved_defs
        if node.type in ("selector_expression", "index_expression"):
            operand = node.child_by_field_name("operand")
            return not self._is_package_alias(operand) and self._unresolved_only(operand)
        if node.type == "call_expression" \
                and (node.start_byte, node.end_byte) in self._unresolved_method_calls:
            return True
        return self._is_unresolved_bare_call(node)

    def _service_receiver(self, operand, recv_type: GoType) -> bool:
        """May an unresolved method on this receiver count as unresolved-only?

        Only a receiver that looks like a service of this program, not data:
        its type is unknown, declared in this package, or imported from a
        package no spec models (not the standard library); and it is itself
        unresolved-only, or rooted at a parameter, the method receiver, a
        captured or package-level variable -- never at a local this body
        assigns (`f := form{Next: r.FormValue("n")}; f.Target()` keeps its
        taint) nor at a request / server-context value."""
        path = recv_type.path
        if path:
            if "." in path:
                pkg = _package_of(path)
                if not pkg or "." not in pkg.split("/")[0] or pkg in _MODELED_PACKAGES:
                    return False
            elif not re.fullmatch(r"[A-Za-z_]\w*", path) or path in BUILTIN_TYPES:
                return False
        if self._unresolved_only(operand):
            return True
        root = operand
        while root is not None and root.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression"):
            if root.type == "selector_expression" and self._is_package_alias(
                    root.child_by_field_name("operand")):
                return True                                 # pkg.Var: package state
            root = (root.child_by_field_name("operand") if root.type != "parenthesized_expression"
                    else (root.named_children[0] if root.named_children else None))
        if root is None or root.type != "identifier":
            return False
        name = self._t(root)
        typ = self._scope_lookup(name)
        if typ is not None and (typ.path == REQUEST_TYPE or typ.path in SERVER_CONTEXT_TYPES):
            return False
        scope = self._scope
        while scope is not None and not scope.proc_root:
            if name in scope.names:
                return False                                # a local of this body
            scope = scope.parent
        if scope is not None and name in scope.names:
            return name not in (getattr(self, "_result_vars", None) or ())
        # Captured from an enclosing function: only its parameters and
        # receiver, not a local it assigns. Not found at all: package state.
        scope = scope.parent if scope is not None else None
        while scope is not None:
            if name in scope.names:
                return scope.proc_root
            scope = scope.parent
        return True

    def _call_key(self, node) -> Optional[str]:
        """The canonical key of a call node (package function or typed method),
        resolved syntactically; None when the callee cannot be resolved."""
        if node is None or node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            return None
        operand = fn.child_by_field_name("operand")
        member = self._t(fn.child_by_field_name("field"))
        if self._is_package_alias(operand):
            return f"{self._env.pkg_of(self._t(operand))}.{member}"
        recv = self._type_of(operand)
        return f"{recv.path}.{member}" if recv.known else None

    # ------------------------------------------------------------------- types
    def _type_of(self, node) -> GoType:
        if node is None:
            return UNKNOWN
        t = node.type
        if t == "identifier":
            name = self._t(node)
            local = self._scope_lookup(name)
            if local is not None:
                return local
            return self._env.package_vars.get(name, UNKNOWN)
        if t == "parenthesized_expression" and node.named_children:
            return self._type_of(node.named_children[0])
        if t == "unary_expression":
            inner = self._type_of(node.child_by_field_name("operand"))
            return GoType(inner.path, True) if self._op(node) == "&" and inner.known else inner
        if t == "composite_literal":
            return type_of(node.child_by_field_name("type"), self._src, self._env.imports)
        if t in ("type_assertion_expression", "type_conversion_expression"):
            return type_of(node.child_by_field_name("type"), self._src, self._env.imports)
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            field_name = self._t(node.child_by_field_name("field"))
            if self._is_package_alias(operand):
                return UNKNOWN
            base = self._type_of(operand)
            if not base.known:
                return UNKNOWN
            local = self._env.struct_fields.get(base.path, {}).get(field_name)
            if local is not None:
                return local
            known = FIELD_TYPES.get(f"{base.path}.{field_name}")
            return GoType(known) if known else UNKNOWN
        if t == "call_expression":
            results = self._result_types(node)
            return results[0] if results else UNKNOWN
        return UNKNOWN

    def _result_types(self, node) -> List[GoType]:
        if node is None or node.type != "call_expression":
            return []
        fn = node.child_by_field_name("function")
        if fn is None:
            return []
        if fn.type == "identifier" and self._scope_lookup(self._t(fn)) is None:
            name = self._t(fn)
            if name in self._env.funcs:
                return self._env.funcs[name].results
            if name in BUILTIN_TYPES or name in self._env.local_types:
                return [GoType(name)]
            return []
        if fn.type == "selector_expression":
            operand = fn.child_by_field_name("operand")
            member = self._t(fn.child_by_field_name("field"))
            if self._is_package_alias(operand):
                key = f"{self._env.pkg_of(self._t(operand))}.{member}"
            else:
                recv = self._type_of(operand)
                if not recv.known:
                    return []
                sig = self._env.methods.get((recv.path, member))
                if sig is not None:
                    return sig.results
                key = f"{recv.path}.{member}"
            known = RESULT_TYPES.get(key)
            return [GoType(known, True)] if known else []
        return []
