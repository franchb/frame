"""The Go frontend's per-file import and type environment."""

import tree_sitter_go as tsgo
from tree_sitter import Language, Parser

from frame.sil.frontends._go_env import (
    GoType, UNKNOWN, Scope, build_file_env, canonical_pkg, default_package_name,
)

_PARSER = Parser(Language(tsgo.language()))


def _env(src: str):
    data = src.encode()
    return build_file_env(_PARSER.parse(data).root_node, data)


SRC = '''package main

import (
	"database/sql"
	"net/http"
	osexec "os/exec"
	_ "embed"
	. "strings"
	"github.com/labstack/echo/v4"
	"github.com/cyphar/filepath-securejoin"
)

const apiKey = "k-123"
const limit = 10
var root = "/srv"
var db *sql.DB

type Server struct {
	root string
	db   *sql.DB
}

type Set[T any] struct{ items []T }

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) (string, error) { return "", nil }
func (s *Set[T]) Add(x T) {}
func helper(xs ...string) int { return 0 }
func Exported(p string) {}
'''


def test_imports_default_alias_and_versions():
    env = _env(SRC)
    assert env.imports["sql"] == "database/sql"
    assert env.imports["http"] == "net/http"
    assert env.imports["osexec"] == "os/exec"
    assert env.imports["echo"] == "github.com/labstack/echo/v4"
    assert env.imports["securejoin"] == "github.com/cyphar/filepath-securejoin"
    assert "_" not in env.imports and "." not in env.imports
    assert env.pkg_of("echo") == "github.com/labstack/echo"


def test_canonical_and_default_names():
    assert canonical_pkg("github.com/go-chi/chi/v5") == "github.com/go-chi/chi"
    assert default_package_name("gopkg.in/yaml.v3") == "yaml"
    assert default_package_name("os/exec") == "exec"


def test_package_level_declarations():
    env = _env(SRC)
    assert env.consts["apiKey"] == "k-123"
    assert env.consts["limit"] == 10
    assert env.package_vars["db"] == GoType("database/sql.DB", True)
    assert env.struct_fields["Server"]["db"] == GoType("database/sql.DB", True)
    assert env.struct_fields["Server"]["root"] == GoType("string")
    assert "Server" in env.local_types and "Set" in env.local_types


def test_signatures_and_methods():
    env = _env(SRC)
    sig = env.methods[("Server", "Handle")]
    assert sig.name == "Server.Handle"
    assert sig.receiver == ("s", GoType("Server", True))
    assert [t for _, t in sig.params] == [GoType("net/http.ResponseWriter"),
                                          GoType("net/http.Request", True)]
    assert sig.results == [GoType("string"), GoType("error")]
    assert ("Set", "Add") in env.methods          # generic receiver
    assert env.funcs["helper"].params == [("xs", GoType("[]string"))]
    assert env.funcs["Exported"].exported and not env.funcs["helper"].exported


def test_scope_shadowing():
    outer = Scope()
    outer.declare("x", GoType("string"))
    inner = outer.child()
    assert inner.lookup("x") == GoType("string")
    inner.declare("x", GoType("int"))
    assert inner.lookup("x") == GoType("int")
    assert outer.lookup("x") == GoType("string")
    assert inner.lookup("nope") is None
    inner.declare("_", GoType("int"))
    assert inner.lookup("_") is None


def test_unknown_type_is_unknown():
    assert not UNKNOWN.known
