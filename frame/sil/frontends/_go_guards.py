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
# Calls that only read a container argument, so passing it is not an escape.
_READ_ONLY_CALLS = frozenset({
    "slices.Contains", "slices.Index", "slices.ContainsFunc", "slices.IndexFunc",
    "maps.Keys", "maps.Values"})


def _enclosing_fn(node):
    node = node.parent if node is not None else None
    while node is not None and node.type not in _FUNC_TYPES:
        node = node.parent
    return node


def _assigns_existing(node) -> bool:
    """A range_clause / receive_statement whose targets are assigned with `=`
    (not declared with `:=`)."""
    return node.child_by_field_name("left") is not None and any(
        not c.is_named and c.type == "=" for c in node.children)


def _elem_expr(node):
    """The expression inside a literal_element (or the node itself)."""
    if node is not None and node.type == "literal_element" and node.named_children:
        return node.named_children[0]
    return node


class _Frame:
    __slots__ = ("key", "defs", "params", "receivers", "node")

    def __init__(self, key, defs, params, receivers, node=None):
        self.key, self.defs, self.params, self.receivers = key, defs, params, receivers
        self.node = node


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
        self.root = root
        self._reads_only_cache: Dict[Tuple, bool] = {}
        self.frames: List[_Frame] = []
        self._frame_cache: Dict[Tuple[int, int], _Frame] = {}
        self._collect(root)

    # ---- collection
    def _record_target(self, lnode, rnode, fn) -> None:
        lnode = _strip(lnode)
        if lnode is None:
            return
        # `m[k] = v` writes both k and v into m: every index on the path is a
        # written value too.
        written = [rnode]
        fields: List[str] = []
        node = lnode
        while node is not None and node.type in ("selector_expression", "index_expression",
                                                 "parenthesized_expression", "unary_expression"):
            if node.type == "selector_expression":
                fields.append(self.text(node.child_by_field_name("field")))
            elif node.type == "index_expression":
                written.append(node.child_by_field_name("index"))
            node = (node.child_by_field_name("operand") if node.type != "parenthesized_expression"
                    else (node.named_children[0] if node.named_children else None))
        for f in fields:
            self.field_assign.setdefault(f, []).extend((w, fn) for w in written)
        if node is not None and node.type == "identifier":
            name = self.text(node)
            if name in self.env.package_vars:
                # `v = x`, `v[k] = x` and `v.f = x` all change what v holds.
                self.pkg_assign.setdefault(name, []).extend((w, fn) for w in written)

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

    def _struct_fields_of(self, type_node) -> Optional[List[str]]:
        """Field names of a same-file struct type (through `*T`); ["*"] for a
        qualified or generic type; None for anything else."""
        if type_node is not None and type_node.type == "pointer_type" and type_node.named_children:
            type_node = type_node.named_children[0]
        if type_node is None:
            return None
        if type_node.type == "type_identifier":
            name = self.text(type_node)
            return list(self.env.struct_fields[name]) if name in self.env.struct_fields else None
        if type_node.type in ("qualified_type", "generic_type"):
            return ["*"]
        return None

    def _record_struct_body(self, fields: List[str], body, fn) -> None:
        elems = [_elem_expr(e) for e in body.named_children
                 if e.type not in ("keyed_element", "comment")]
        for f in fields:
            for e in elems:
                self.field_assign.setdefault(f, []).append((e, fn))

    def _record_elided(self, type_node, body, fn) -> None:
        """Elements of a slice / array / map literal whose type is elided
        (`[]S{{x}}`, `map[string]*S{"a": {x}}`) are literals of the element type."""
        if type_node is None or body is None:
            return
        if type_node.type in ("slice_type", "array_type", "implicit_length_array_type"):
            elem_type = type_node.child_by_field_name("element")
        elif type_node.type == "map_type":
            elem_type = type_node.child_by_field_name("value")
        else:
            return
        for e in body.named_children:
            value = e.named_children[-1] if e.type == "keyed_element" and e.named_children else e
            inner = _elem_expr(value)
            if inner is None or inner.type != "literal_value":
                continue
            fields = self._struct_fields_of(elem_type)
            if fields is not None:
                self._record_struct_body(fields, inner, fn)
            else:
                self._record_elided(elem_type, inner, fn)

    def _record_positional(self, lit, fn) -> None:
        type_node = lit.child_by_field_name("type")
        body = lit.child_by_field_name("body")
        if type_node is None or body is None:
            return
        if type_node.type in _TRUSTED_LITERAL_TYPES:
            self._record_elided(type_node, body, fn)
            return
        fields = self._struct_fields_of(type_node)
        if fields is not None:
            self._record_struct_body(fields, body, fn)

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
            elif n.type in ("range_clause", "receive_statement") and _assigns_existing(n):
                # `for k, t = range xs` / `case t = <-ch:` store into existing
                # targets; the stored value is not tracked, so it is unknown.
                lefts = n.child_by_field_name("left")
                fn = _enclosing_fn(n)
                for l in (lefts.named_children if lefts is not None else []):
                    self._record_target(l, None, fn)
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
                    indexes = []
                    while base is not None and base.type in ("selector_expression", "index_expression",
                                                             "unary_expression"):
                        if base.type == "index_expression":
                            indexes.append(base.child_by_field_name("index"))
                        base = _strip(base.child_by_field_name("operand"))
                    if base is not None and base.type == "identifier":
                        # `m[k] = v` writes k as well as v into m.
                        defs.setdefault(self.text(base), []).extend([rhs] + indexes)
            elif n.type in ("var_spec", "const_spec"):
                values = n.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, name in enumerate(n.children_by_field_name("name")):
                    defs.setdefault(self.text(name), []).append(vals[i] if i < len(vals) else "zero")
            elif n.type in ("range_clause", "receive_statement"):
                left = n.child_by_field_name("left")
                for l in (left.named_children if left is not None else []):
                    base = _strip(l)
                    while base is not None and base.type in ("selector_expression",
                                                             "index_expression", "unary_expression"):
                        base = _strip(base.child_by_field_name("operand"))
                    if base is not None and base.type == "identifier":
                        defs.setdefault(self.text(base), []).append(None)
        return defs

    def _frame_for(self, fn_node) -> _Frame:
        """The frame of a function, merged with every enclosing function's (a
        closure sees its outer locals and parameters)."""
        if fn_node is None:
            return _Frame(None, {}, set(), set(), None)
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
        frame = _Frame(key, defs, params, receivers, fn_node)
        self._frame_cache[key] = frame
        return frame

    def enter(self, fn_node, receiver: str, params: Set[str]) -> None:
        base = self._frame_for(fn_node)
        self.frames.append(_Frame(base.key, base.defs, base.params | set(params),
                                  base.receivers | ({receiver} if receiver else set()), base.node))

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

    def _is_container(self, name: str, frame) -> bool:
        """Is `name` a map / slice / array (a reference a callee can write into)?"""
        typ = self.env.package_vars.get(name)
        if typ is not None and typ.path.startswith(("[", "map[")):
            return True
        rhs_nodes = list(frame.defs.get(name, [])) if frame is not None and name in frame.defs \
            else [r for r, _ in self.pkg_assign.get(name, [])]
        for rhs in rhs_nodes:
            node = _strip(rhs) if rhs not in (None, "zero") else None
            if node is None:
                continue
            if node.type == "composite_literal":
                t = node.child_by_field_name("type")
                if t is not None and t.type in _TRUSTED_LITERAL_TYPES:
                    return True
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "identifier" and self.text(fn) in ("make", "append"):
                    return True
        return False

    # ---- allowlist containers: a positive list of permitted uses
    def _reads_only(self, name: str, frame) -> bool:
        """A map / slice allowlist is trusted only if every occurrence of its
        name in its scope is a permitted read: its own declaration, an index
        read, `range`, an argument to a read-only helper or to unshadowed
        `len` / `cap`, or `delete(m, k)`. Anything else (assignment, alias,
        other call argument, slicing, `...`, `&`, method call, index write)
        could let a value the oracle cannot see into it."""
        local = frame is not None and name in frame.defs
        if local:
            scope = frame.node
            while scope is not None and _enclosing_fn(scope) is not None:
                scope = _enclosing_fn(scope)       # the outermost enclosing function
        else:
            scope = self.root
        if scope is None:
            return False
        key = (scope.start_byte, scope.end_byte, name, local)
        cached = self._reads_only_cache.get(key)
        if cached is not None:
            return cached
        ok = True
        stack = [scope]
        while stack and ok:
            n = stack.pop()
            stack.extend(n.named_children)
            if n.type != "identifier" or self.text(n) != name:
                continue
            if not local and self._resolves_locally(n, name):
                continue                            # a different, shadowing local
            ok = self._permitted_use(n, name)
        self._reads_only_cache[key] = ok
        return ok

    def _declares(self, stmt, name: str) -> bool:
        """Does statement `stmt` declare `name` in its enclosing block?"""
        t = stmt.type
        if t == "short_var_declaration":
            left = stmt.child_by_field_name("left")
            return any(c.type == "identifier" and self.text(c) == name
                       for c in (left.named_children if left is not None else []))
        if t in ("var_declaration", "const_declaration"):
            specs = [c for c in stmt.named_children if c.type in ("var_spec", "const_spec")]
            for group in [c for c in stmt.named_children if c.type in ("var_spec_list", "const_spec_list")]:
                specs.extend(c for c in group.named_children if c.type in ("var_spec", "const_spec"))
            return any(self.text(nm) == name for sp in specs for nm in sp.children_by_field_name("name"))
        if t == "for_clause":
            return any(self._declares(c, name) for c in stmt.named_children)
        if t == "range_clause":                      # `for k, v := range x`
            left = stmt.child_by_field_name("left")
            declares = any(c.type == ":=" for c in stmt.children)
            return declares and left is not None and any(
                self.text(c) == name for c in left.named_children)
        return False

    def _resolves_locally(self, occ, name: str) -> bool:
        """Is this occurrence of `name` bound by a local declaration (a
        parameter, receiver, named result or a declaration in an enclosing
        block that precedes it) rather than the package-level one?"""
        decl = occ.parent
        if decl is not None and decl.type == "expression_list" and decl.parent is not None \
                and decl == decl.parent.child_by_field_name("left") and (
                    decl.parent.type == "short_var_declaration"
                    or (decl.parent.type == "range_clause"
                        and any(c.type == ":=" for c in decl.parent.children))):
            return True                             # the declaring occurrence itself
        if decl is not None and decl.type in ("var_spec", "const_spec") \
                and _enclosing_fn(decl) is not None:
            return True
        child, node = occ, occ.parent
        while node is not None and node.type != "source_file":
            if node.type in _FUNC_TYPES:
                names = set()
                for field in ("parameters", "receiver", "result"):
                    names |= self._param_names(node.child_by_field_name(field))
                if name in names:
                    return True
            elif node.type in ("if_statement", "for_statement", "expression_switch_statement",
                               "type_switch_statement"):
                for c in node.named_children:
                    if c.end_byte <= occ.start_byte or c.type in ("for_clause", "range_clause"):
                        if c.start_byte < child.start_byte and self._declares(c, name):
                            return True
                if node.type == "type_switch_statement":
                    alias = node.child_by_field_name("alias")
                    if alias is not None and any(self.text(a) == name for a in
                                                 (alias.named_children or [alias])):
                        return True
            else:
                for c in node.named_children:
                    if c.end_byte <= occ.start_byte and self._declares(c, name):
                        return True
            child, node = node, node.parent
        return False

    def _builtin(self, fn, names) -> bool:
        return (fn is not None and fn.type == "identifier" and self.text(fn) in names
                and self.text(fn) not in self.env.funcs and self.text(fn) not in self.env.package_vars
                and not self._resolves_locally(fn, self.text(fn)))

    def _permitted_use(self, occ, name: str) -> bool:
        node, parent = occ, occ.parent
        while parent is not None and parent.type == "parenthesized_expression":
            node, parent = parent, parent.parent
        if parent is None:
            return False
        pt = parent.type
        # its own declaration (the value is judged through its definitions)
        if pt == "var_spec" and any(n == occ for n in parent.children_by_field_name("name")):
            return True
        if pt == "expression_list" and parent.parent is not None \
                and parent.parent.type == "short_var_declaration" \
                and parent == parent.parent.child_by_field_name("left"):
            return True
        # index read, not written and not addressed
        if pt == "index_expression" and parent.child_by_field_name("operand") == node:
            up, above = parent, parent.parent
            while above is not None and above.type == "parenthesized_expression":
                up, above = above, above.parent
            if above is not None and above.type == "expression_list" and above.parent is not None \
                    and above.parent.type == "assignment_statement" \
                    and above == above.parent.child_by_field_name("left"):
                return False
            if above is not None and above.type == "expression_list" and above.parent is not None \
                    and above.parent.type in ("range_clause", "receive_statement") \
                    and above == above.parent.child_by_field_name("left"):
                return False
            if above is not None and above.type in ("inc_statement", "dec_statement"):
                return False
            if above is not None and above.type == "unary_expression":
                op = above.child_by_field_name("operator")
                if op is not None and self.text(op) == "&":
                    return False
            return True
        if pt == "range_clause" and parent.child_by_field_name("right") == node:
            return True
        if pt == "argument_list" and parent.parent is not None \
                and parent.parent.type == "call_expression":
            call = parent.parent
            fn = call.child_by_field_name("function")
            args = [a for a in parent.named_children if a.type != "comment"]
            if self.key_of(call) in _READ_ONLY_CALLS:
                return True
            if self._builtin(fn, ("len", "cap")):
                return True
            if self._builtin(fn, ("delete",)) and args and args[0] == node:
                return True
        return False

    def _trusted_name(self, name: str, checked, seen) -> bool:
        if name == checked or name in self.escaped_names:
            return False
        frame = self.frames[-1] if self.frames else None
        if self._is_container(name, frame) and not self._reads_only(name, frame):
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
def _src_name(var: str) -> str:
    """The source identifier of a SIL variable (`p#3` -> `p`); the trust
    oracle is name-based."""
    return var.split("#", 1)[0]


class _GuardCounter:
    n = 0          # unique Rel-call instance ids (never reset: ids only need to differ)


class GuardTracker:
    def __init__(self, src: bytes, trust: TrustOracle, key_of: Callable,
                 arg_nodes: Callable, const_str: Callable, text: Callable,
                 var_of: Optional[Callable] = None):
        self.src, self.trust = src, trust
        self.key_of, self.arg_nodes, self.const_str, self.text = key_of, arg_nodes, const_str, text
        # Facts are keyed by the SIL variable an identifier resolves to, so a
        # shadowing declaration's facts never reach the outer binding.
        self.var_of = var_of or text
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
            s = self.var_of(_strip(args[0]))
            if first != "_":
                self.url_src[first] = s
            if err != "_":
                self.url_err[err] = s
        if key == "path/filepath.Rel" and len(args) == 2 and _strip(args[1]).type == "identifier":
            p = self.var_of(_strip(args[1]))
            root = self.text(args[0]) if self.trust.trusted(args[0], checked=_src_name(p)) else None
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
        return self.var_of(node) if node is not None and node.type == "identifier" else None

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
            if self.text(sep) in _SEPARATOR_TEXTS and self.trust.trusted(root, checked=_src_name(v)):
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
            if av and b is not None and self.trust.trusted(b, checked=_src_name(av)):
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
        # `///evil.example` parses with an empty Host and IsAbs false, so the
        # url.Parse rule also needs the `//` prefix rejected.
        if (imp((v, "url_err", "", False)) and imp((v, "url_abs", "", False))
                and imp((v, "url_host_nonempty", "", False)) and no_bs
                and imp((v, "prefix", "//", False))):
            kinds.add(REDIRECT)
        if imp((v, "host_allowed", "", True)):
            kinds |= {REDIRECT, SSRF}
        return kinds
