"""Guard facts, sanitizer rules and trusted-root provenance for the Go frontend.

A guard such as `if !strings.HasPrefix(p, root+string(filepath.Separator)) { return }`
proves something about `p` on the continuation. Conditions are converted to
CNF clauses over literals (var, atom, arg, polarity); a rule is satisfied when
some clause implies each required literal (a clause implies a set of literals
when it is a subset of that set). Unrecognised conditions contribute a clause
containing an unknown literal, which implies nothing. Facts are killed when a
mentioned variable is reassigned and intersected at joins. Only complete checks
sanitize (docs/superpowers/specs/2026-09-23-go-frontend-design.md, "Guard facts").
"""

from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from frame.sil.frontends._go_env import FileEnv, literal_value
from frame.sil.specs.go_specs import NORMALIZING_KEYS, TRUSTED_PURE_CALLS

FS, REDIRECT, SSRF = "filesystem", "redirect", "ssrf"
Literal = Tuple[str, str, str, bool]          # (var, atom, arg, polarity)
Clause = FrozenSet[Literal]
_UNKNOWN: Clause = frozenset({("", "?", "", True)})
_MAX_CLAUSES = 64
_SEPARATOR_TEXTS = frozenset({
    'string(filepath.Separator)', 'string(os.PathSeparator)', '"/"'})
_URL_PARSE = frozenset({"net/url.Parse", "net/url.ParseRequestURI"})


def _strip(node):
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


# --------------------------------------------------------------------------- trust
_FUNC_TYPES = ("function_declaration", "method_declaration", "func_literal")
_TRUSTED_LITERAL_TYPES = ("slice_type", "array_type", "implicit_length_array_type", "map_type")


def _enclosing_fn(node):
    node = node.parent if node is not None else None
    while node is not None and node.type not in _FUNC_TYPES:
        node = node.parent
    return node


def _elem_expr(node):
    """The expression inside a literal_element (or the node itself)."""
    if node is not None and node.type == "literal_element" and node.named_children:
        return node.named_children[0]
    return node


class _Frame:
    __slots__ = ("key", "defs", "params", "receivers")

    def __init__(self, key, defs, params, receivers):
        self.key, self.defs, self.params, self.receivers = key, defs, params, receivers


class TrustOracle:
    """Decides syntactically whether a root / allowlist expression is trusted,
    from in-file reaching definitions (spec: "Trusted (untainted) root").

    Every collected write remembers the function it occurs in and is judged in
    that function's frame. Writes the oracle cannot see make the target
    untrusted: an address taken with `&` (an out-parameter) and a positional
    struct literal (a write to every field)."""

    def __init__(self, root, src: bytes, env: FileEnv,
                 key_of: Callable, is_alias: Callable, text: Callable):
        self.src, self.env = src, env
        self.key_of, self.is_alias, self.text = key_of, is_alias, text
        # name -> [(rhs node | None | "zero", enclosing function node | None)]
        self.pkg_assign: Dict[str, List] = {}
        self.field_assign: Dict[str, List] = {}      # "*": a write to any field
        self.escaped_names: Set[str] = set()
        self.escaped_fields: Set[str] = set()
        self.frames: List[_Frame] = []
        self._frame_cache: Dict[Tuple[int, int], _Frame] = {}
        self._collect(root)

    # ---- collection
    def _record_target(self, lnode, rnode, fn) -> None:
        lnode = _strip(lnode)
        if lnode is None:
            return
        node = lnode
        while node is not None and node.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression", "unary_expression"):
            if node.type == "selector_expression":
                self.field_assign.setdefault(
                    self.text(node.child_by_field_name("field")), []).append((rnode, fn))
            node = (node.child_by_field_name("operand") if node.type != "parenthesized_expression"
                    else (node.named_children[0] if node.named_children else None))
        if node is not None and node.type == "identifier":
            name = self.text(node)
            if name in self.env.package_vars:
                # `v = x`, `v[k] = x` and `v.f = x` all change what v holds.
                self.pkg_assign.setdefault(name, []).append((rnode, fn))

    def _record_escape(self, operand) -> None:
        node = _strip(operand)
        if node is None or node.type == "composite_literal":
            return
        while node is not None and node.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression"):
            if node.type == "selector_expression":
                self.escaped_fields.add(self.text(node.child_by_field_name("field")))
            node = (node.child_by_field_name("operand") if node.type != "parenthesized_expression"
                    else (node.named_children[0] if node.named_children else None))
        if node is not None and node.type == "identifier":
            self.escaped_names.add(self.text(node))

    def _record_positional(self, lit, fn) -> None:
        type_node = lit.child_by_field_name("type")
        body = lit.child_by_field_name("body")
        if type_node is None or body is None or type_node.type in _TRUSTED_LITERAL_TYPES:
            return
        elems = [_elem_expr(e) for e in body.named_children
                 if e.type not in ("keyed_element", "comment")]
        if not elems:
            return
        if type_node.type == "type_identifier" and self.text(type_node) not in self.env.struct_fields:
            return                                  # a local non-struct type
        fields = (list(self.env.struct_fields[self.text(type_node)])
                  if type_node.type == "type_identifier" else ["*"])
        for f in fields:
            for e in elems:
                self.field_assign.setdefault(f, []).append((e, fn))

    def _collect(self, root) -> None:
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type in ("assignment_statement", "short_var_declaration"):
                lefts = n.child_by_field_name("left")
                rights = n.child_by_field_name("right")
                ls = lefts.named_children if lefts is not None else []
                rs = rights.named_children if rights is not None else []
                fn = _enclosing_fn(n)
                for i, l in enumerate(ls):
                    self._record_target(l, rs[i] if len(rs) == len(ls) else None, fn)
            elif n.type == "unary_expression":
                op = n.child_by_field_name("operator")
                if op is not None and self.text(op) == "&":
                    self._record_escape(n.child_by_field_name("operand"))
            elif n.type == "composite_literal":
                self._record_positional(n, _enclosing_fn(n))
            elif n.type == "keyed_element":
                kids = n.named_children
                if len(kids) >= 2:
                    key = _strip(_elem_expr(kids[0]))
                    if key is not None and key.type in ("identifier", "field_identifier"):
                        self.field_assign.setdefault(self.text(key), []).append(
                            (_elem_expr(kids[-1]), _enclosing_fn(n)))
            elif n.type == "var_spec" and n.parent is not None and n.parent.type == "var_declaration" \
                    and n.parent.parent is not None and n.parent.parent.type == "source_file":
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    self.pkg_assign.setdefault(self.text(name), []).append(
                        (vals[i] if i < len(vals) else "zero", None))

    # ---- frames
    def _param_names(self, plist) -> Set[str]:
        out: Set[str] = set()
        for p in (plist.named_children if plist is not None else []):
            for name in p.children_by_field_name("name"):
                out.add(self.text(name))
        return out

    def _own_defs(self, fn_node) -> Dict[str, List]:
        defs: Dict[str, List] = {}
        body = fn_node.child_by_field_name("body")
        stack = [body] if body is not None else []
        while stack:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type in ("assignment_statement", "short_var_declaration"):
                lefts = n.child_by_field_name("left")
                rights = n.child_by_field_name("right")
                ls = lefts.named_children if lefts is not None else []
                rs = rights.named_children if rights is not None else []
                for i, l in enumerate(ls):
                    rhs = rs[i] if len(rs) == len(ls) else None
                    base = _strip(l)
                    while base is not None and base.type in ("selector_expression", "index_expression",
                                                             "unary_expression"):
                        base = _strip(base.child_by_field_name("operand"))
                    if base is not None and base.type == "identifier":
                        defs.setdefault(self.text(base), []).append(rhs)
            elif n.type in ("var_spec", "const_spec"):
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    defs.setdefault(self.text(name), []).append(vals[i] if i < len(vals) else "zero")
            elif n.type == "range_clause":
                left = n.child_by_field_name("left")
                for l in (left.named_children if left is not None else []):
                    defs.setdefault(self.text(l), []).append(None)
        return defs

    def _frame_for(self, fn_node) -> _Frame:
        """The frame of a function, merged with every enclosing function's (a
        closure sees its outer locals and parameters)."""
        if fn_node is None:
            return _Frame(None, {}, set(), set())
        key = (fn_node.start_byte, fn_node.end_byte)
        cached = self._frame_cache.get(key)
        if cached is not None:
            return cached
        defs: Dict[str, List] = {}
        params: Set[str] = set()
        receivers: Set[str] = set()
        node = fn_node
        while node is not None:
            for name, rhs in self._own_defs(node).items():
                defs.setdefault(name, []).extend(rhs)
            params |= self._param_names(node.child_by_field_name("parameters"))
            if node.type == "method_declaration":
                receivers |= self._param_names(node.child_by_field_name("receiver"))
            node = _enclosing_fn(node)
        frame = _Frame(key, defs, params, receivers)
        self._frame_cache[key] = frame
        return frame

    def enter(self, fn_node, receiver: str, params: Set[str]) -> None:
        base = self._frame_for(fn_node)
        self.frames.append(_Frame(base.key, base.defs, base.params | set(params),
                                  base.receivers | ({receiver} if receiver else set())))

    def leave(self) -> None:
        if self.frames:
            self.frames.pop()

    # ---- queries
    def trusted(self, node, checked: Optional[str] = None, _seen: Optional[Set] = None) -> bool:
        node = _strip(node)
        if node is None:
            return False
        seen = _seen if _seen is not None else set()
        t = node.type
        if t in ("interpreted_string_literal", "raw_string_literal", "int_literal", "rune_literal",
                 "true", "false"):
            return True
        if t == "binary_expression":
            return (self.trusted(node.child_by_field_name("left"), checked, seen)
                    and self.trusted(node.child_by_field_name("right"), checked, seen))
        if t == "identifier":
            return self._trusted_name(self.text(node), checked, seen)
        if t == "selector_expression":
            return self._trusted_field_path(node, checked, seen)
        if t == "composite_literal":
            type_node = node.child_by_field_name("type")
            return (type_node is not None and type_node.type in _TRUSTED_LITERAL_TYPES
                    and self._trusted_elements(node.child_by_field_name("body"), checked, seen))
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            args = [a for a in (args_node.named_children if args_node is not None else [])]
            if fn is not None and fn.type == "identifier" and self.text(fn) == "string":
                return len(args) == 1 and (self.text(args[0]) in (
                    "filepath.Separator", "os.PathSeparator") or self.trusted(args[0], checked, seen))
            key = self.key_of(node)
            return key in TRUSTED_PURE_CALLS and all(self.trusted(a, checked, seen) for a in args)
        return False

    def _trusted_elements(self, body, checked, seen) -> bool:
        """Every key and value of a slice / array / map literal is trusted."""
        if body is None:
            return False
        for e in body.named_children:
            if e.type == "comment":
                continue
            parts = e.named_children if e.type == "keyed_element" else [e]
            for part in parts:
                inner = _elem_expr(part)
                if inner is not None and inner.type == "literal_value":
                    if not self._trusted_elements(inner, checked, seen):
                        return False
                elif not self.trusted(inner, checked, seen):
                    return False
        return True

    def _trusted_name(self, name: str, checked, seen) -> bool:
        if name == checked or name in self.escaped_names:
            return False
        if self.frames:
            frame = self.frames[-1]
            if name in frame.params or name in frame.receivers:
                return False
            if name in frame.defs:
                return self._all_trusted(("local", frame.key, name),
                                         [(r, frame) for r in frame.defs[name]], checked, seen)
        if name in self.env.consts:
            return True
        if name in self.env.package_vars:
            return self._all_trusted(("pkg", name), self.pkg_assign.get(name, []), checked, seen)
        return False

    def _trusted_field_path(self, node, checked, seen) -> bool:
        operand = node.child_by_field_name("operand")
        field_name = self.text(node.child_by_field_name("field"))
        if self.is_alias(operand):
            return field_name in ("Separator", "PathSeparator")
        fields = [field_name]
        base = _strip(operand)
        while base is not None and base.type == "selector_expression":
            fields.append(self.text(base.child_by_field_name("field")))
            base = _strip(base.child_by_field_name("operand"))
        if base is None or base.type != "identifier":
            return False
        base_name = self.text(base)
        if base_name == checked or base_name in self.escaped_names:
            return False
        if any(f in self.escaped_fields for f in fields):
            return False
        frame = self.frames[-1] if self.frames else None
        base_ok = (frame is not None and base_name in frame.receivers) or (
            base_name in self.env.package_vars and self._trusted_name(base_name, checked, seen)) or (
            frame is not None and base_name in frame.defs
            and self._trusted_name(base_name, checked, seen))
        if not base_ok:
            return False
        writes = self.field_assign.get("*", [])
        return all(self._all_trusted(("field", f), self.field_assign.get(f, []) + writes, checked, seen)
                   for f in fields)

    def _all_trusted(self, key, entries, checked, seen) -> bool:
        """entries: (rhs, where) with `where` a _Frame (same frame), a function
        node (judged in that function's frame) or None (package level)."""
        if key in seen:
            return False
        seen = seen | {key}
        for rhs, where in entries:
            if rhs == "zero":
                continue
            if rhs is None:
                return False
            frame = where if isinstance(where, _Frame) else self._frame_for(where)
            self.frames.append(frame)
            try:
                ok = self.trusted(rhs, checked, seen)
            finally:
                self.frames.pop()
            if not ok:
                return False
        return True


# --------------------------------------------------------------------------- guards
class _GuardCounter:
    n = 0          # unique Rel-call instance ids (never reset: ids only need to differ)


class GuardTracker:
    def __init__(self, src: bytes, trust: TrustOracle, key_of: Callable,
                 arg_nodes: Callable, const_str: Callable, text: Callable):
        self.src, self.trust = src, trust
        self.key_of, self.arg_nodes, self.const_str, self.text = key_of, arg_nodes, const_str, text
        self.clear()

    # ---- state
    def clear(self) -> None:
        self.clauses: FrozenSet[Clause] = frozenset()
        self.emitted: Dict[str, FrozenSet[str]] = {}
        self.normalized: FrozenSet[str] = frozenset()
        self.url_src: Dict[str, str] = {}
        self.url_err: Dict[str, str] = {}
        # A filepath.Rel call instance: rel var -> (trusted root text | None, p, id);
        # err var -> (p, id). Rel literals carry the instance id, so the err,
        # `..` and root parts of the rule must all come from one call.
        self.rel_src: Dict[str, Tuple[Optional[str], str, str]] = {}
        self.rel_err: Dict[str, Tuple[str, str]] = {}

    def snapshot(self):
        return (self.clauses, dict(self.emitted), self.normalized, dict(self.url_src),
                dict(self.url_err), dict(self.rel_src), dict(self.rel_err))

    def restore(self, snap) -> None:
        if snap is None:
            self.clear()
            return
        (self.clauses, emitted, self.normalized, url_src, url_err, rel_src, rel_err) = snap
        self.emitted, self.url_src, self.url_err = dict(emitted), dict(url_src), dict(url_err)
        self.rel_src, self.rel_err = dict(rel_src), dict(rel_err)

    def join(self, snaps: list) -> None:
        live = [s for s in snaps if s is not None]
        if not live:
            self.clear()
            return
        first = live[0]
        clauses = first[0]
        normalized = first[2]
        emitted = dict(first[1])
        for s in live[1:]:
            clauses &= s[0]
            normalized &= s[2]
            emitted = {k: v & s[1][k] for k, v in emitted.items() if k in s[1]}
        maps = []
        for idx in (3, 4, 5, 6):
            merged = dict(first[idx])
            for s in live[1:]:
                merged = {k: v for k, v in merged.items() if s[idx].get(k) == v}
            maps.append(merged)
        self.clauses, self.emitted, self.normalized = clauses, emitted, normalized
        self.url_src, self.url_err, self.rel_src, self.rel_err = maps

    def kill(self, var: str) -> None:
        self.clauses = frozenset(c for c in self.clauses if all(l[0] != var for l in c))
        self.emitted.pop(var, None)
        self.normalized = self.normalized - {var}
        for m in (self.url_src, self.url_err):
            for k in [k for k, v in m.items() if k == var or v == var]:
                del m[k]
        for k in [k for k, (p, _) in self.rel_err.items() if k == var or p == var]:
            del self.rel_err[k]
        for k in [k for k, (_, p, _) in self.rel_src.items() if k == var or p == var]:
            del self.rel_src[k]

    # ---- assignments
    def on_assign(self, name: str, value_node) -> None:
        self.kill(name)
        value_node = _strip(value_node)
        if value_node is not None and value_node.type == "call_expression" \
                and self.key_of(value_node) in NORMALIZING_KEYS:
            self.normalized = self.normalized | {name}

    def on_multi_assign(self, names: List[str], value_node) -> None:
        value_node = _strip(value_node)
        if value_node is None or value_node.type != "call_expression" or len(names) < 2:
            return
        key = self.key_of(value_node)
        args = self.arg_nodes(value_node)
        first, err = names[0], names[1]
        if key in NORMALIZING_KEYS and first != "_":
            self.normalized = self.normalized | {first}
        if key in _URL_PARSE and args and _strip(args[0]).type == "identifier":
            s = self.text(_strip(args[0]))
            if first != "_":
                self.url_src[first] = s
            if err != "_":
                self.url_err[err] = s
        if key == "path/filepath.Rel" and len(args) == 2 and _strip(args[1]).type == "identifier":
            p = self.text(_strip(args[1]))
            root = self.text(args[0]) if self.trust.trusted(args[0], checked=p) else None
            _GuardCounter.n += 1
            inst = f"rel#{_GuardCounter.n}"
            if first != "_":
                self.rel_src[first] = (root, p, inst)
            if err != "_":
                self.rel_err[err] = (p, inst)

    # ---- conditions
    def on_branch(self, cond_node, truth: bool) -> Dict[str, Set[str]]:
        added = frozenset(c for c in self._cnf(cond_node, truth) if c != _UNKNOWN)
        self.clauses = self.clauses | added
        out: Dict[str, Set[str]] = {}
        for var in {l[0] for c in self.clauses for l in c if l[0]}:
            new = self.sanitized_kinds(var) - set(self.emitted.get(var, frozenset()))
            if new:
                out[var] = new
                self.emitted[var] = frozenset(set(self.emitted.get(var, frozenset())) | new)
        return out

    def implies(self, *lits: Literal) -> bool:
        allowed = frozenset(lits)
        return any(c <= allowed for c in self.clauses)

    def _cnf(self, node, truth: bool) -> List[Clause]:
        node = _strip(node)
        if node is None:
            return [_UNKNOWN]
        if node.type == "unary_expression" and self._op(node) == "!":
            return self._cnf(node.child_by_field_name("operand"), not truth)
        if node.type == "binary_expression" and self._op(node) in ("&&", "||"):
            left = self._cnf(node.child_by_field_name("left"), truth)
            right = self._cnf(node.child_by_field_name("right"), truth)
            conjunctive = (self._op(node) == "&&") == truth
            if conjunctive:
                return left + right
            product = [a | b for a in left for b in right]
            return product if len(product) <= _MAX_CLAUSES else [_UNKNOWN]
        return self._atom(node, truth)

    def _op(self, node) -> str:
        op = node.child_by_field_name("operator")
        return self.text(op) if op is not None else ""

    def _var(self, node) -> Optional[str]:
        node = _strip(node)
        return self.text(node) if node is not None and node.type == "identifier" else None

    def _url_vars(self, u: str) -> List[str]:
        return [u] + ([self.url_src[u]] if u in self.url_src else [])

    def _host_var(self, node) -> Optional[str]:
        """`u.Host` or `u.Hostname()` where u came from url.Parse."""
        node = _strip(node)
        if node is None:
            return None
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "selector_expression" \
                    and self.text(fn.child_by_field_name("field")) == "Hostname":
                return self._var(fn.child_by_field_name("operand"))
        if node.type == "selector_expression" and self.text(node.child_by_field_name("field")) == "Host":
            return self._var(node.child_by_field_name("operand"))
        return None

    def _clauses(self, vars_: List[str], atom: str, arg: str, pol: bool) -> List[Clause]:
        return [frozenset({(v, atom, arg, pol)}) for v in vars_]

    def _atom(self, node, truth: bool) -> List[Clause]:
        t = node.type
        if t == "call_expression":
            return self._call_atom(node, truth)
        if t == "binary_expression" and self._op(node) in ("==", "!="):
            return self._compare_atom(node, truth)
        if t == "index_expression":
            host_u = self._host_var(node.child_by_field_name("index"))
            if host_u and self.trust.trusted(node.child_by_field_name("operand")):
                return self._clauses(self._url_vars(host_u), "host_allowed", "", truth)
        return [_UNKNOWN]

    def _call_atom(self, node, truth: bool) -> List[Clause]:
        key = self.key_of(node)
        args = self.arg_nodes(node)
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "selector_expression" \
                and self.text(fn.child_by_field_name("field")) == "IsAbs":
            u = self._var(fn.child_by_field_name("operand"))
            if u in self.url_src:
                return self._clauses(self._url_vars(u), "url_abs", "", truth)
        v0 = self._var(args[0]) if args else None
        if key == "path/filepath.IsLocal" and v0:
            return self._clauses([v0], "is_local", "", truth)
        if key == "strings.HasPrefix" and v0 and len(args) == 2:
            return self._prefix_atom(v0, args[1], truth)
        if key in ("strings.Contains", "strings.ContainsAny", "strings.ContainsRune") and v0 and len(args) == 2:
            needle = self.const_str(args[1])
            if needle is None and _strip(args[1]).type == "rune_literal":
                needle = literal_value(_strip(args[1]), self.src)
            if needle is None:
                return [_UNKNOWN]
            atoms = []
            if key == "strings.Contains" and needle == "..":
                atoms.append("has_dotdot")
            # Contains / ContainsRune test for the whole needle: only a lone
            # backslash proves there is no backslash anywhere. ContainsAny
            # tests each character of the set.
            if (needle == "\\") if key != "strings.ContainsAny" else ("\\" in needle):
                atoms.append("has_bs")
            if key == "strings.ContainsAny" and {"\t", "\n", "\r"} <= set(needle):
                atoms.append("has_ctrl")
            if not atoms:
                return [_UNKNOWN]
            if truth:
                return [frozenset((v0, a, "", True) for a in atoms)]
            return [frozenset({(v0, a, "", False)}) for a in atoms]
        if key == "strings.ContainsFunc" and v0 and len(args) == 2 \
                and self.text(args[1]) == "unicode.IsControl":
            return self._clauses([v0], "has_ctrl", "", truth)
        if key == "slices.Contains" and len(args) == 2:
            host_u = self._host_var(args[1])
            if host_u and self.trust.trusted(args[0]):
                return self._clauses(self._url_vars(host_u), "host_allowed", "", truth)
        return [_UNKNOWN]

    def _prefix_atom(self, v: str, prefix_node, truth: bool) -> List[Clause]:
        const = self.const_str(prefix_node)
        if v in self.rel_src:                       # HasPrefix(rel, "..") / (rel, ".."+sep)
            _, p, inst = self.rel_src[v]
            if const == "..":
                return self._clauses([p], "rel_prefix", inst + "|..", truth)
            node = _strip(prefix_node)
            if node is not None and node.type == "binary_expression" and self._op(node) == "+" \
                    and self.const_str(node.child_by_field_name("left")) == ".." \
                    and self.text(node.child_by_field_name("right")) in _SEPARATOR_TEXTS:
                return self._clauses([p], "rel_prefix", inst + "|..sep", truth)
            return [_UNKNOWN]
        if const in ("/", "//", "/\\"):
            return self._clauses([v], "prefix", const, truth)
        node = _strip(prefix_node)
        if node is not None and node.type == "binary_expression" and self._op(node) == "+":
            root = node.child_by_field_name("left")
            sep = node.child_by_field_name("right")
            if self.text(sep) in _SEPARATOR_TEXTS and self.trust.trusted(root, checked=v):
                return self._clauses([v], "prefix_sep", self.text(root), truth)
        return [_UNKNOWN]

    def _compare_atom(self, node, truth: bool) -> List[Clause]:
        left = _strip(node.child_by_field_name("left"))
        right = _strip(node.child_by_field_name("right"))
        equal = (self._op(node) == "==") == truth          # does equality hold?
        for a, b in ((left, right), (right, left)):
            av = self._var(a)
            if b is not None and b.type == "nil" and av:
                if av in self.url_err:
                    return self._clauses([self.url_err[av]], "url_err", "", not equal)
                if av in self.rel_err:
                    p, inst = self.rel_err[av]
                    return self._clauses([p], "rel_err", inst, not equal)
            host_u = self._host_var(a)
            if host_u:
                c = self.const_str(b)
                if c == "" and a.type == "selector_expression":
                    return self._clauses(self._url_vars(host_u), "url_host_nonempty", "", not equal)
                if c and self.trust.trusted(b):
                    return self._clauses(self._url_vars(host_u), "host_allowed", "", equal)
            if av in self.rel_src and self.const_str(b) == "..":
                _, p, inst = self.rel_src[av]
                return self._clauses([p], "rel_eq_dotdot", inst, equal)
            if av and b is not None and self.trust.trusted(b, checked=av):
                return self._clauses([av], "eq_root", self.text(b), equal)
        return [_UNKNOWN]

    # ---- rules
    def sanitized_kinds(self, v: str) -> Set[str]:
        imp = self.implies
        kinds: Set[str] = set()
        if v in self.normalized:
            roots = {l[2] for c in self.clauses for l in c
                     if l[0] == v and l[1] in ("eq_root", "prefix_sep") and l[3]}
            if any(imp((v, "eq_root", r, True), (v, "prefix_sep", r, True)) for r in roots):
                kinds.add(FS)
            for root, p, inst in self.rel_src.values():
                if p == v and root is not None and imp((v, "rel_err", inst, False)) and (
                        imp((v, "rel_prefix", inst + "|..", False))
                        or (imp((v, "rel_prefix", inst + "|..sep", False))
                            and imp((v, "rel_eq_dotdot", inst, False)))):
                    kinds.add(FS)
        if imp((v, "is_local", "", True)):
            kinds.add(FS)
        no_bs = imp((v, "has_bs", "", False))
        no_ctrl = imp((v, "has_ctrl", "", False)) or imp((v, "url_err", "", False))
        if imp((v, "prefix", "/", True)) and imp((v, "prefix", "//", False)) and no_bs and no_ctrl:
            kinds.add(REDIRECT)
        if (imp((v, "url_err", "", False)) and imp((v, "url_abs", "", False))
                and imp((v, "url_host_nonempty", "", False)) and no_bs):
            kinds.add(REDIRECT)
        if imp((v, "host_allowed", "", True)):
            kinds |= {REDIRECT, SSRF}
        return kinds
