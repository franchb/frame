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
class TrustOracle:
    """Decides syntactically whether a root / allowlist expression is trusted,
    from in-file reaching definitions (spec: "Trusted (untainted) root")."""

    def __init__(self, root, src: bytes, env: FileEnv,
                 key_of: Callable, is_alias: Callable, text: Callable):
        self.src, self.env = src, env
        self.key_of, self.is_alias, self.text = key_of, is_alias, text
        self.pkg_assign: Dict[str, List] = {}
        self.field_assign: Dict[str, List] = {}
        self.frames: List[Tuple[Dict[str, List], Set[str], str]] = []
        self._collect(root)

    def _record_target(self, lnode, rnode) -> None:
        lnode = _strip(lnode)
        if lnode is None:
            return
        if lnode.type == "identifier":
            name = self.text(lnode)
            if name in self.env.package_vars:
                self.pkg_assign.setdefault(name, []).append(rnode)
        elif lnode.type in ("selector_expression", "index_expression"):
            node = lnode
            while node is not None and node.type in ("selector_expression", "index_expression"):
                if node.type == "selector_expression":
                    self.field_assign.setdefault(
                        self.text(node.child_by_field_name("field")), []).append(rnode)
                node = node.child_by_field_name("operand")

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
                for i, l in enumerate(ls):
                    self._record_target(l, rs[i] if len(rs) == len(ls) else None)
            elif n.type == "keyed_element":
                kids = n.named_children
                if len(kids) >= 2:
                    key = _strip(kids[0].named_children[0] if kids[0].type == "literal_element"
                                 and kids[0].named_children else kids[0])
                    if key is not None and key.type in ("identifier", "field_identifier"):
                        value = kids[-1].named_children[0] if kids[-1].type == "literal_element" \
                            and kids[-1].named_children else kids[-1]
                        self.field_assign.setdefault(self.text(key), []).append(value)
            elif n.type == "var_spec" and n.parent is not None and n.parent.type == "var_declaration" \
                    and n.parent.parent is not None and n.parent.parent.type == "source_file":
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    self.pkg_assign.setdefault(self.text(name), []).append(
                        vals[i] if i < len(vals) else "zero")

    def enter(self, fn_node, receiver: str, params: Set[str]) -> None:
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
                    if l.type == "identifier":
                        defs.setdefault(self.text(l), []).append(
                            rs[i] if len(rs) == len(ls) else None)
            elif n.type in ("var_spec", "const_spec"):
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    defs.setdefault(self.text(name), []).append(vals[i] if i < len(vals) else "zero")
            elif n.type == "range_clause":
                left = n.child_by_field_name("left")
                for l in (left.named_children if left is not None else []):
                    defs.setdefault(self.text(l), []).append(None)
        self.frames.append((defs, set(params), receiver))

    def leave(self) -> None:
        if self.frames:
            self.frames.pop()

    def trusted(self, node, checked: Optional[str] = None, _seen: Optional[Set] = None) -> bool:
        node = _strip(node)
        if node is None:
            return False
        seen = _seen if _seen is not None else set()
        t = node.type
        if t in ("interpreted_string_literal", "raw_string_literal", "int_literal", "rune_literal"):
            return True
        if t == "binary_expression":
            return (self.trusted(node.child_by_field_name("left"), checked, seen)
                    and self.trusted(node.child_by_field_name("right"), checked, seen))
        if t == "identifier":
            return self._trusted_name(self.text(node), checked, seen)
        if t == "selector_expression":
            return self._trusted_field_path(node, checked, seen)
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

    def _trusted_name(self, name: str, checked, seen) -> bool:
        if name == checked:
            return False
        if self.frames:
            defs, params, receiver = self.frames[-1]
            if name in params or name == receiver:
                return False
            if name in defs:
                return self._all_trusted(("local", name), defs[name], checked, seen)
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
        if base_name == checked:
            return False
        receiver = self.frames[-1][2] if self.frames else ""
        base_ok = base_name == receiver or (
            base_name in self.env.package_vars and self._trusted_name(base_name, checked, seen)) or (
            bool(self.frames) and base_name in self.frames[-1][0]
            and self._trusted_name(base_name, checked, seen))
        if not base_ok:
            return False
        return all(self._all_trusted(("field", f), self.field_assign.get(f, []), checked, seen)
                   for f in fields)

    def _all_trusted(self, key, rhs_nodes, checked, seen) -> bool:
        if key in seen:
            return False
        seen = seen | {key}
        for rhs in rhs_nodes:
            if rhs == "zero":
                continue
            if rhs is None or not self.trusted(rhs, checked, seen):
                return False
        return True


# --------------------------------------------------------------------------- guards
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
        self.rel_src: Dict[str, Tuple[Optional[str], str]] = {}
        self.rel_err: Dict[str, str] = {}

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
        for m in (self.url_src, self.url_err, self.rel_err):
            for k in [k for k, v in m.items() if k == var or v == var]:
                del m[k]
        for k in [k for k, (_, p) in self.rel_src.items() if k == var or p == var]:
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
            if first != "_":
                self.rel_src[first] = (root, p)
            if err != "_":
                self.rel_err[err] = p

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
            if "\\" in needle:
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
            p = self.rel_src[v][1]
            if const == "..":
                return self._clauses([p], "rel_prefix", "..", truth)
            node = _strip(prefix_node)
            if node is not None and node.type == "binary_expression" and self._op(node) == "+" \
                    and self.const_str(node.child_by_field_name("left")) == ".." \
                    and self.text(node.child_by_field_name("right")) in _SEPARATOR_TEXTS:
                return self._clauses([p], "rel_prefix", "..sep", truth)
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
                    return self._clauses([self.rel_err[av]], "rel_err", "", not equal)
            host_u = self._host_var(a)
            if host_u:
                c = self.const_str(b)
                if c == "" and a.type == "selector_expression":
                    return self._clauses(self._url_vars(host_u), "url_host_nonempty", "", not equal)
                if c and self.trust.trusted(b):
                    return self._clauses(self._url_vars(host_u), "host_allowed", "", equal)
            if av in self.rel_src and self.const_str(b) == "..":
                return self._clauses([self.rel_src[av][1]], "rel_eq_dotdot", "", equal)
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
            rel_ok = any(p == v and root is not None for (root, p) in self.rel_src.values())
            if rel_ok and imp((v, "rel_err", "", False)) and (
                    imp((v, "rel_prefix", "..", False))
                    or (imp((v, "rel_prefix", "..sep", False)) and imp((v, "rel_eq_dotdot", "", False)))):
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
