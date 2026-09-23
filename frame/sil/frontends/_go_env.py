"""Per-file import and syntactic type environment for the Go frontend.

Go writes parameter, receiver, field and most variable types in source, so a
single parse yields package-qualified names without a Go toolchain:
`osexec.Command` resolves to `os/exec.Command` through the import table, and
`db.Query` resolves to `database/sql.DB.Query` because `db` was declared
`*sql.DB`. Everything here is syntactic. An unknown type is UNKNOWN, never a
guess, because a wrong guess becomes a wrong spec and a false finding.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

BUILTIN_TYPES = frozenset({
    "bool", "byte", "complex64", "complex128", "error", "float32", "float64",
    "int", "int8", "int16", "int32", "int64", "rune", "string",
    "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any",
})

# Import paths whose package name is not their last path element.
_PACKAGE_NAMES = {
    "github.com/cyphar/filepath-securejoin": "securejoin",
    "gopkg.in/yaml.v2": "yaml",
    "gopkg.in/yaml.v3": "yaml",
}

_VERSION_SUFFIX = re.compile(r"/v\d+$")


def canonical_pkg(path: str) -> str:
    """Drop a major-version suffix: github.com/labstack/echo/v4 -> .../echo."""
    return _VERSION_SUFFIX.sub("", path)


def default_package_name(path: str) -> str:
    if path in _PACKAGE_NAMES:
        return _PACKAGE_NAMES[path]
    return canonical_pkg(path).rsplit("/", 1)[-1]


@dataclass(frozen=True)
class GoType:
    """A syntactic type. `path` is canonical: 'net/http.Request' for an imported
    named type, 'Server' for a type declared in this file, 'string' for a
    builtin, source text for composite types ('[]byte'), '' when unknown."""
    path: str = ""
    pointer: bool = False

    @property
    def known(self) -> bool:
        return bool(self.path)


UNKNOWN = GoType("")


@dataclass
class FuncSig:
    name: str                                   # "F", or "Server.H" for a method
    params: List[Tuple[str, GoType]]            # (name, type); "" if unnamed
    results: List[GoType]
    receiver: Optional[Tuple[str, GoType]] = None
    exported: bool = False


@dataclass
class FileEnv:
    package: str = ""
    imports: Dict[str, str] = field(default_factory=dict)        # local name -> path
    struct_fields: Dict[str, Dict[str, GoType]] = field(default_factory=dict)
    package_vars: Dict[str, GoType] = field(default_factory=dict)
    consts: Dict[str, object] = field(default_factory=dict)      # name -> literal or None
    funcs: Dict[str, FuncSig] = field(default_factory=dict)
    methods: Dict[Tuple[str, str], FuncSig] = field(default_factory=dict)
    local_types: Set[str] = field(default_factory=set)

    def pkg_of(self, alias: str) -> Optional[str]:
        path = self.imports.get(alias)
        return canonical_pkg(path) if path else None


def text(node, src: bytes) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def statements_of(block) -> list:
    """The statements of a block or case body. tree-sitter-go 0.25 wraps them
    in a `statement_list`; older grammars do not."""
    out = []
    if block is None:
        return out
    for child in block.named_children:
        if child.type == "statement_list":
            out.extend(child.named_children)
        else:
            out.append(child)
    return out


def literal_value(node, src: bytes):
    """The Python value of a literal node, or None if it is not a literal."""
    if node is None:
        return None
    t = node.type
    raw = text(node, src)
    if t == "interpreted_string_literal":
        body = raw[1:-1]
        try:
            return body.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return body
    if t == "raw_string_literal":
        return raw[1:-1]
    if t == "rune_literal":
        body = raw[1:-1]                    # '\\' is one backslash, as in a string
        try:
            return body.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return body
    if t == "int_literal":
        try:
            return int(raw.replace("_", ""), 0)
        except ValueError:
            return None
    if t == "true":
        return True
    if t == "false":
        return False
    return None


def type_of(node, src: bytes, imports: Dict[str, str]) -> GoType:
    if node is None:
        return UNKNOWN
    t = node.type
    if t == "pointer_type":
        inner = type_of(node.named_children[0], src, imports) if node.named_children else UNKNOWN
        return GoType(inner.path, True) if inner.known else UNKNOWN
    if t == "qualified_type":
        pkg = node.child_by_field_name("package")
        name = node.child_by_field_name("name")
        path = imports.get(text(pkg, src))
        if path is None or name is None:
            return UNKNOWN
        return GoType(f"{canonical_pkg(path)}.{text(name, src)}")
    if t == "type_identifier":
        return GoType(text(node, src))
    if t == "generic_type":
        base = node.child_by_field_name("type")
        if base is None and node.named_children:
            base = node.named_children[0]
        return type_of(base, src, imports)
    if t == "parenthesized_type":
        return type_of(node.named_children[0], src, imports) if node.named_children else UNKNOWN
    if t in ("slice_type", "array_type", "map_type", "channel_type",
             "function_type", "struct_type", "interface_type"):
        return GoType(text(node, src))
    return UNKNOWN


def params_of(plist, src: bytes, imports: Dict[str, str]) -> List[Tuple[str, GoType]]:
    out: List[Tuple[str, GoType]] = []
    if plist is None:
        return out
    for p in plist.named_children:
        if p.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        typ = type_of(p.child_by_field_name("type"), src, imports)
        if p.type == "variadic_parameter_declaration":
            typ = GoType(f"[]{typ.path}") if typ.known else UNKNOWN
        names = p.children_by_field_name("name")
        if names:
            out.extend((text(n, src), typ) for n in names)
        else:
            out.append(("", typ))
    return out


def _descendants(node, node_type: str):
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == node_type:
            yield n
            continue
        stack.extend(reversed(n.named_children))


def _struct_fields(struct_node, src, imports) -> Dict[str, GoType]:
    fields: Dict[str, GoType] = {}
    for decl in _descendants(struct_node, "field_declaration"):
        typ = type_of(decl.child_by_field_name("type"), src, imports)
        names = decl.children_by_field_name("name")
        if names:
            for n in names:
                fields[text(n, src)] = typ
        elif typ.known:                       # embedded field: named by its type
            fields[typ.path.rsplit(".", 1)[-1]] = typ
    return fields


def _sig(node, src, imports, receiver) -> FuncSig:
    base = text(node.child_by_field_name("name"), src)
    params = params_of(node.child_by_field_name("parameters"), src, imports)
    result = node.child_by_field_name("result")
    if result is None:
        results: List[GoType] = []
    elif result.type == "parameter_list":
        results = [t for _, t in params_of(result, src, imports)]
    else:
        results = [type_of(result, src, imports)]
    name = f"{receiver[1].path}.{base}" if receiver else base
    return FuncSig(name=name, params=params, results=results, receiver=receiver,
                   exported=base[:1].isupper())


def build_file_env(root, src: bytes) -> FileEnv:
    env = FileEnv()
    for node in root.named_children:
        if node.type == "package_clause" and node.named_children:
            env.package = text(node.named_children[0], src)
        elif node.type == "import_declaration":
            for spec in _descendants(node, "import_spec"):
                path_node = spec.child_by_field_name("path")
                if path_node is None:
                    continue
                path = text(path_node, src).strip('"`')
                name_node = spec.child_by_field_name("name")
                if name_node is None:
                    env.imports[default_package_name(path)] = path
                elif name_node.type == "package_identifier":
                    env.imports[text(name_node, src)] = path
                # "_" and "." imports bind no usable name.
    for node in root.named_children:
        t = node.type
        if t == "type_declaration":
            for spec in node.named_children:
                if spec.type not in ("type_spec", "type_alias"):
                    continue
                name = text(spec.child_by_field_name("name"), src)
                env.local_types.add(name)
                body = spec.child_by_field_name("type")
                if body is not None and body.type == "struct_type":
                    env.struct_fields[name] = _struct_fields(body, src, env.imports)
        elif t == "var_declaration":
            for spec in _descendants(node, "var_spec"):
                typ = type_of(spec.child_by_field_name("type"), src, env.imports)
                for n in spec.children_by_field_name("name"):
                    env.package_vars[text(n, src)] = typ
        elif t == "const_declaration":
            for spec in _descendants(node, "const_spec"):
                values = spec.child_by_field_name("value")
                vals = values.named_children if values is not None else []
                for i, n in enumerate(spec.children_by_field_name("name")):
                    env.consts[text(n, src)] = literal_value(vals[i], src) if i < len(vals) else None
        elif t == "function_declaration":
            sig = _sig(node, src, env.imports, receiver=None)
            env.funcs[sig.name] = sig
        elif t == "method_declaration":
            recv = params_of(node.child_by_field_name("receiver"), src, env.imports)
            if not recv or not recv[0][1].known:
                continue
            sig = _sig(node, src, env.imports, receiver=recv[0])
            env.methods[(recv[0][1].path, sig.name.split(".", 1)[1])] = sig
    return env


class Scope:
    """Lexical scope for locals. A name declared in any enclosing function
    scope shadows package-level names and import aliases."""

    def __init__(self, parent: Optional["Scope"] = None):
        self.parent = parent
        self.names: Dict[str, GoType] = {}

    def declare(self, name: str, typ: GoType = UNKNOWN) -> None:
        if name and name != "_":
            self.names[name] = typ

    def lookup(self, name: str) -> Optional[GoType]:
        scope = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None

    def child(self) -> "Scope":
        return Scope(self)
