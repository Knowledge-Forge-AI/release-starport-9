from __future__ import annotations

import ast
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
import sys
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
SRC = REPOSITORY / "src" / "rs9"
sys.path.insert(0, str(REPOSITORY / "src"))

ENTRYPOINT_MODULES = frozenset({
    "nebular080_universal_consumer",
    "nebular080_universal_fetch",
    "nebular080_universal_history",
    "nebular080_universal_launcher",
    "nebular080_universal_missing",
    "nebular080_universal_profile",
    "nebular080_universal_publication",
    "nebular080_universal_workflow",
    "tf_pypi_nebular080_universal",
    "wheel_nebular080_universal",
})
OFF_ROUTE_CALLS = frozenset({
    "rs9.nebular080_release.validate_nebular080_release_admission",
    "rs9.nebular080_system_wheel._system_wheel",
    "rs9.nebular080_system_webkit.check_missing_runtime",
    "rs9.nebular080_system_webkit.validate_missing_runtime",
    "rs9.nebular080_consumer_core.consume_nebular_candidate",
    "rs9.nebular080_consumer_core._nebular_profile_contract",
})
ROOT_PACKAGE_METADATA = frozenset({
    "__cached__",
    "__file__",
    "__loader__",
    "__name__",
    "__package__",
    "__path__",
    "__spec__",
})


def _expression_parts(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        base = _expression_parts(node.value)
        return (*base, node.attr) if base else ()
    return ()


def _import_module_path(
    node: ast.ImportFrom,
    current_module: str,
    *,
    package_init: bool = False,
) -> str | None:
    if node.level == 0:
        return node.module
    if node.level != 1:
        raise AssertionError(
            f"Unsupported relative import level {node.level} in rs9.{current_module}"
        )
    if package_init:
        package_parts = ["rs9", *(() if current_module == "__init__" else current_module.split("."))]
    else:
        module_parts = [] if current_module == "__init__" else current_module.split(".")
        package_parts = ["rs9", *module_parts[:-1]]
    prefix = ".".join(package_parts)
    return prefix if node.module is None else f"{prefix}.{node.module}"


def _import_bindings(
    nodes: Iterable[ast.AST],
    *,
    current_module: str,
    package_init: bool = False,
) -> dict[str, str]:
    """Return Python's bindings for imports whose target is inside ``rs9``."""
    bindings: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                if not (item.name == "rs9" or item.name.startswith("rs9.")):
                    continue
                if item.asname:
                    bindings[item.asname] = item.name
                else:
                    # ``import rs9.x`` binds ``rs9``, not ``x``.
                    bindings[item.name.split(".", 1)[0]] = item.name.split(".", 1)[0]
        elif isinstance(node, ast.ImportFrom):
            module_path = _import_module_path(
                node,
                current_module,
                package_init=package_init,
            )
            if module_path is None:
                continue
            if not (module_path == "rs9" or module_path.startswith("rs9.")):
                continue
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                bindings[local] = f"{module_path}.{item.name}"
    return bindings


def _import_bound_names(nodes: Iterable[ast.AST]) -> set[str]:
    """Return all names bound by imports, including non-rs9 shadowing imports."""
    bound: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                bound.add(item.asname or item.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for item in node.names:
                bound.add("*" if item.name == "*" else (item.asname or item.name))
    return bound


@dataclass(frozen=True)
class _Scope:
    aliases: dict[str, str]
    shadowed: frozenset[str]
    class_parent: _Scope | None = None


class _TreeSet(dict[str, ast.Module]):
    def __init__(
        self,
        values: Mapping[str, ast.Module] | None = None,
        *,
        package_initializers: Iterable[str] = (),
    ) -> None:
        super().__init__(values or {})
        self.package_initializers = frozenset(package_initializers)


class _DirectBindingCollector(ast.NodeVisitor):
    """Collect bindings/imports owned by one lexical scope, not child scopes."""

    def __init__(self, parameters: Iterable[str] = ()) -> None:
        self.imports: list[ast.AST] = []
        self.bound: set[str] = set(parameters)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bound.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bound.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bound.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.append(node)
        self.bound.update(item.asname or item.name.split(".", 1)[0] for item in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append(node)
        if node.module == "__future__":
            return
        self.bound.update("*" if item.name == "*" else (item.asname or item.name)
                         for item in node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.add(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)


def _argument_names(arguments: ast.arguments) -> set[str]:
    values = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        values.append(arguments.vararg)
    if arguments.kwarg is not None:
        values.append(arguments.kwarg)
    return {argument.arg for argument in values}


def _scope_for_body(
    body: Iterable[ast.stmt],
    parent: _Scope,
    *,
    current_module: str,
    parameters: Iterable[str] = (),
    class_scope: bool = False,
    package_init: bool = False,
) -> _Scope:
    collector = _DirectBindingCollector(parameters)
    for statement in body:
        collector.visit(statement)
    if package_init and any(
        isinstance(node, ast.ImportFrom) and node.level > 0
        for node in collector.imports
    ):
        raise AssertionError(
            f"Relative import below module level in package initializer rs9.{current_module}"
        )
    local_aliases = _import_bindings(collector.imports, current_module=current_module)
    aliases = dict(parent.aliases)
    aliases.update(local_aliases)
    if "*" in collector.bound:
        raise AssertionError(f"Wildcard import prevents closed route analysis in rs9.{current_module}")
    shadowed = (set(parent.shadowed) - set(local_aliases)) | (
        collector.bound - set(local_aliases)
    )
    class_parent = (parent.class_parent or parent) if class_scope else None
    return _Scope(aliases, frozenset(shadowed), class_parent)


class _FunctionReferenceVisitor:
    """Collect loads from a top-level function and all ordinary nested scopes."""

    def __init__(
        self,
        current_module: str,
        module_scope: _Scope,
        *,
        package_init: bool = False,
    ) -> None:
        self.current_module = current_module
        self.module_scope = module_scope
        self.package_init = package_init
        self.references: list[tuple[ast.AST, _Scope]] = []

    def collect(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.AST, _Scope]]:
        self._visit_function(root, self.module_scope)
        return self.references

    def collect_module(self, tree: ast.Module) -> list[tuple[ast.AST, _Scope]]:
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._visit_header(statement, self.module_scope)
            else:
                self._walk(statement, self.module_scope)
        return self.references

    def _visit_header(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: _Scope,
    ) -> None:
        for expression in node.decorator_list:
            self._walk(expression, scope)
        if node.returns is not None:
            self._walk(node.returns, scope)
        arguments = node.args
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
            if argument.annotation is not None:
                self._walk(argument.annotation, scope)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self._walk(arguments.vararg.annotation, scope)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self._walk(arguments.kwarg.annotation, scope)
        for default in (*arguments.defaults, *arguments.kw_defaults):
            if default is not None:
                self._walk(default, scope)

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent: _Scope,
    ) -> None:
        self._visit_header(node, parent)
        scope = _scope_for_body(
            node.body,
            parent.class_parent or parent,
            current_module=self.current_module,
            parameters=_argument_names(node.args),
            package_init=self.package_init,
        )
        for statement in node.body:
            self._walk(statement, scope)

    def _visit_class_method(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        class_scope: _Scope,
        parent_scope: _Scope,
    ) -> None:
        # A method's header executes in the class body, but its body resolves
        # bare names through the enclosing function/module, not class locals.
        self._visit_header(node, class_scope)
        scope = _scope_for_body(
            node.body,
            parent_scope,
            current_module=self.current_module,
            parameters=_argument_names(node.args),
            package_init=self.package_init,
        )
        for statement in node.body:
            self._walk(statement, scope)

    def _visit_class(self, node: ast.ClassDef, parent: _Scope) -> None:
        for expression in (*node.decorator_list, *node.bases):
            self._walk(expression, parent)
        for keyword in node.keywords:
            self._walk(keyword.value, parent)
        body_parent = parent.class_parent or parent
        scope = _scope_for_body(
            node.body,
            body_parent,
            current_module=self.current_module,
            class_scope=True,
            package_init=self.package_init,
        )
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._visit_class_method(statement, scope, body_parent)
            else:
                self._walk(statement, scope)

    def _visit_lambda(self, node: ast.Lambda, parent: _Scope) -> None:
        arguments = node.args
        for default in (*arguments.defaults, *arguments.kw_defaults):
            if default is not None:
                self._walk(default, parent)
        scope = _scope_for_body(
            (),
            parent.class_parent or parent,
            current_module=self.current_module,
            parameters=_argument_names(arguments),
            package_init=self.package_init,
        )
        self._walk(node.body, scope)

    def _target_names(self, target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names: set[str] = set()
            for element in target.elts:
                names.update(self._target_names(element))
            return names
        if isinstance(target, ast.Starred):
            return self._target_names(target.value)
        return set()

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        parent: _Scope,
    ) -> None:
        scope = parent
        for generator in node.generators:
            self._walk(generator.iter, scope)
            names = self._target_names(generator.target)
            body_parent = scope.class_parent or scope
            scope = _Scope(
                dict(body_parent.aliases),
                frozenset(set(body_parent.shadowed) | names),
                body_parent.class_parent,
            )
            for condition in generator.ifs:
                self._walk(condition, scope)
        if isinstance(node, ast.DictComp):
            self._walk(node.key, scope)
            self._walk(node.value, scope)
        else:
            self._walk(node.elt, scope)

    def _walk(self, node: ast.AST, scope: _Scope) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(node, scope)
            return
        if isinstance(node, ast.ClassDef):
            self._visit_class(node, scope)
            return
        if isinstance(node, ast.Lambda):
            self._visit_lambda(node, scope)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._visit_comprehension(node, scope)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                self.references.append((node, scope))
            return
        if isinstance(node, ast.Attribute):
            if isinstance(node.ctx, ast.Load):
                self.references.append((node, scope))
            self._walk(node.value, scope)
            return
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope)


def _module_aliases(
    tree: ast.Module,
    *,
    current_module: str,
    package_init: bool = False,
) -> dict[str, str]:
    collector = _ModuleImportCollector()
    for statement in tree.body:
        collector.visit(statement)
    return _import_bindings(
        collector.imports,
        current_module=current_module,
        package_init=package_init,
    )


def _module_bound_names(tree: ast.Module) -> set[str]:
    collector = _ModuleImportCollector()
    for statement in tree.body:
        collector.visit(statement)
    return _import_bound_names(collector.imports)


class _ModuleImportCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[ast.AST] = []

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.append(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _function_index(
    trees: Mapping[str, ast.Module],
) -> dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    index: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for module, tree in trees.items():
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index[f"rs9.{module}.{node.name}"] = (module, node)
    return index


def _assert_no_conditional_top_level_functions(trees: Mapping[str, ast.Module]) -> None:
    class _ConditionalDefinitionChecker(ast.NodeVisitor):
        def __init__(self, module: str) -> None:
            self.module = module

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            raise AssertionError(
                f"Unindexed module-level nested function {self.module}.{node.name}"
            )

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            raise AssertionError(
                f"Unindexed module-level nested function {self.module}.{node.name}"
            )

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    for module, tree in trees.items():
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            _ConditionalDefinitionChecker(module).visit(statement)


def _chase_reexports(
    target: str,
    module_aliases: Mapping[str, Mapping[str, str]],
) -> str:
    def aliases_for(module: str) -> Mapping[str, str]:
        if module == "rs9":
            return module_aliases.get("__init__", {})
        aliases = module_aliases.get(module)
        if aliases is None and module.startswith("rs9."):
            aliases = module_aliases.get(module[4:])
        return aliases or {}

    seen: set[str] = set()
    while target not in seen:
        seen.add(target)
        parts = target.split(".")
        replacement = None
        for split in range(len(parts) - 1, 0, -1):
            module = ".".join(parts[:split])
            symbol = parts[split]
            replacement = aliases_for(module).get(symbol)
            if replacement is not None:
                tail = parts[split + 1:]
                if tail:
                    replacement = ".".join((replacement, *tail))
                break
        if replacement is None:
            break
        target = replacement
    return target


def _resolve_reference(
    reference: ast.AST,
    scope: _Scope,
    *,
    module: str,
    names_by_module: Mapping[str, set[str]],
    module_aliases: Mapping[str, Mapping[str, str]],
    functions: Mapping[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    module_nodes: Mapping[str, str],
) -> str | None:
    parts = _expression_parts(reference)
    if not parts or (parts[0] in scope.shadowed and parts[0] not in scope.aliases):
        return None
    target_root = scope.aliases.get(parts[0])
    if target_root is None and parts[0] in names_by_module.get(module, set()):
        target_root = f"rs9.{module}.{parts[0]}"
    if target_root is None:
        return None
    target = _chase_reexports(".".join((target_root, *parts[1:])), module_aliases)
    if target in functions or target in OFF_ROUTE_CALLS:
        return target
    target_parts = target.split(".")
    if len(target_parts) >= 2 and target_parts[0] == "rs9" and target_parts[1] in ROOT_PACKAGE_METADATA:
        return None
    for split in range(len(target_parts) - 1, 0, -1):
        module_name = ".".join(target_parts[:split])
        if split == 1 and len(target_parts) != 2:
            continue
        module_key = "__init__" if module_name == "rs9" else module_name.removeprefix("rs9.")
        node = module_nodes.get(module_key)
        if node is not None:
            return node
    if target.startswith("rs9.") and len(target_parts) >= 3:
        raise AssertionError(f"Unindexed rs9 module target prevents closed analysis: {target}")
    return None


def _function_graph(
    trees: Mapping[str, ast.Module],
    *,
    require_contract: bool = False,
) -> dict[str, frozenset[str]]:
    """Index load references between top-level functions and forbidden leaves."""
    if require_contract:
        _assert_no_conditional_top_level_functions(trees)
    functions = _function_index(trees)
    if require_contract:
        missing = sorted(OFF_ROUTE_CALLS - set(functions))
        if missing:
            raise AssertionError(f"Forbidden route leaves are not indexed: {missing}")
    names_by_module: dict[str, set[str]] = {}
    for qualified, (module, _node) in functions.items():
        names_by_module.setdefault(module, set()).add(qualified.rsplit(".", 1)[1])

    package_initializers = getattr(trees, "package_initializers", frozenset())
    module_aliases = {
        module: _module_aliases(
            tree,
            current_module=module,
            package_init=module in package_initializers,
        )
        for module, tree in trees.items()
    }
    module_bound_names = {module: _module_bound_names(tree) for module, tree in trees.items()}
    module_nodes = {module: f"rs9.{module}.<module>" for module in trees}
    edges: dict[str, set[str]] = {
        **{qualified: set() for qualified in functions},
        **{node: set() for node in module_nodes.values()},
    }
    module_scopes: dict[str, _Scope] = {}
    for module in trees:
        if "*" in module_bound_names[module]:
            raise AssertionError(f"Wildcard import prevents closed route analysis in rs9.{module}")
        module_scopes[module] = _Scope(
            dict(module_aliases[module]),
            frozenset(module_bound_names[module] - set(module_aliases[module])),
        )

    for module, tree in trees.items():
        module_visitor = _FunctionReferenceVisitor(
            module,
            module_scopes[module],
            package_init=module in package_initializers,
        )
        module_references = module_visitor.collect_module(tree)
        module_targets = {
            target for reference, scope in module_references
            if (target := _resolve_reference(
                reference,
                scope,
                module=module,
                names_by_module=names_by_module,
                module_aliases=module_aliases,
                functions=functions,
                module_nodes=module_nodes,
            )) is not None
        }
        pseudo_node = module_nodes[module]
        edges[pseudo_node].update(module_targets)
        for qualified in functions:
            function_module = functions[qualified][0]
            if function_module == module:
                edges[qualified].update(module_targets)

    for qualified, (module, function) in functions.items():
        visitor = _FunctionReferenceVisitor(
            module,
            module_scopes[module],
            package_init=module in package_initializers,
        )
        for reference, scope in visitor.collect(function):
            target = _resolve_reference(
                reference,
                scope,
                module=module,
                names_by_module=names_by_module,
                module_aliases=module_aliases,
                functions=functions,
                module_nodes=module_nodes,
            )
            if target is not None:
                edges[qualified].add(target)
    return {qualified: frozenset(targets) for qualified, targets in edges.items()}


def _find_path(
    graph: Mapping[str, frozenset[str]],
    starts: Iterable[str],
    target: str,
) -> tuple[str, ...] | None:
    queue = deque((start, (start,)) for start in sorted(starts))
    seen = set(starts)
    while queue:
        current, path = queue.popleft()
        for successor in sorted(graph.get(current, ())):
            next_path = (*path, successor)
            if successor == target:
                return next_path
            if successor in graph and successor not in seen:
                seen.add(successor)
                queue.append((successor, next_path))
    return None


def _entrypoint_functions(graph: Mapping[str, frozenset[str]]) -> tuple[str, ...]:
    return tuple(sorted(
        qualified for qualified in graph
        if not qualified.endswith(".<module>")
        and qualified.split(".", 2)[1] in ENTRYPOINT_MODULES
    ))


def _actual_trees() -> dict[str, ast.Module]:
    def module_name(path: Path) -> str:
        parts = list(path.relative_to(SRC).with_suffix("").parts)
        if parts[-1] == "__init__":
            return ".".join(parts[:-1]) or "__init__"
        return ".".join(parts)

    trees = _TreeSet({
        module_name(path): ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for path in sorted(SRC.rglob("*.py"))
    })
    init_modules = {
        module_name(path)
        for path in SRC.rglob("__init__.py")
    }
    trees.package_initializers = frozenset(init_modules)
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for module in init_modules
        for node in trees[module].body
    ):
        raise AssertionError("rs9 package __init__ files must not define top-level functions")
    return trees


class Nebular080TransitiveRouteGuardTests(unittest.TestCase):
    def test_entrypoints_have_no_transitive_off_route_reachability(self) -> None:
        graph = _function_graph(_actual_trees(), require_contract=True)
        starts = _entrypoint_functions(graph)
        self.assertEqual(
            {qualified.split(".", 2)[1] for qualified in starts},
            ENTRYPOINT_MODULES,
        )
        self.assertTrue(OFF_ROUTE_CALLS <= set(graph))
        violations = []
        for forbidden in sorted(OFF_ROUTE_CALLS):
            path = _find_path(graph, starts, forbidden)
            if path is not None:
                violations.append(" -> ".join(path))
        self.assertEqual(violations, [])

    def test_nested_function_class_and_lambda_loads_are_attributed(self) -> None:
        trees = {
            "synthetic_nested": ast.parse(
                "from rs9 import nebular080_consumer_core as core\n"
                "from rs9 import nebular080_system_wheel as wheel\n"
                "from rs9 import nebular080_release as release\n"
                "def entry():\n"
                "    def stage():\n"
                "        return core._nebular_profile_contract\n"
                "    return stage\n"
                "def class_entry():\n"
                "    class Stage:\n"
                "        def method(self):\n"
                "            return wheel._system_wheel\n"
                "    return Stage\n"
                "def lambda_entry():\n"
                "    callback = lambda: release.validate_nebular080_release_admission\n"
                "    return callback\n"
            )
        }
        graph = _function_graph(trees)
        cases = (
            ("entry", "rs9.nebular080_consumer_core._nebular_profile_contract"),
            ("class_entry", "rs9.nebular080_system_wheel._system_wheel"),
            ("lambda_entry", "rs9.nebular080_release.validate_nebular080_release_admission"),
        )
        for name, target in cases:
            self.assertEqual(
                _find_path(graph, (f"rs9.synthetic_nested.{name}",), target),
                (f"rs9.synthetic_nested.{name}", target),
            )

    def test_class_method_uses_parent_scope_for_bare_same_module_delegation(self) -> None:
        trees = {
            "synthetic_class_parent": ast.parse(
                "from rs9 import nebular080_consumer_core as core\n"
                "def helper():\n"
                "    return core._nebular_profile_contract\n"
                "def entry():\n"
                "    class Pipeline:\n"
                "        def helper(self):\n"
                "            return helper()\n"
                "    return Pipeline\n"
            )
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_consumer_core._nebular_profile_contract"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_class_parent.entry",), target),
            (
                "rs9.synthetic_class_parent.entry",
                "rs9.synthetic_class_parent.helper",
                target,
            ),
        )

    def test_class_lambda_and_comprehension_bodies_use_class_parent_scope(self) -> None:
        trees = {
            "synthetic_class_expression": ast.parse(
                "from rs9 import nebular080_consumer_core as core\n"
                "def helper():\n"
                "    return core._nebular_profile_contract\n"
                "def lambda_entry():\n"
                "    class Pipeline:\n"
                "        helper = staticmethod(lambda: helper())\n"
                "    return Pipeline\n"
                "def comprehension_entry(items):\n"
                "    class Pipeline:\n"
                "        helper = staticmethod(lambda: None)\n"
                "        values = [helper() for item in items]\n"
                "    return Pipeline\n"
            )
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_consumer_core._nebular_profile_contract"
        for name in ("lambda_entry", "comprehension_entry"):
            self.assertEqual(
                _find_path(graph, (f"rs9.synthetic_class_expression.{name}",), target),
                (
                    f"rs9.synthetic_class_expression.{name}",
                    "rs9.synthetic_class_expression.helper",
                    target,
                ),
            )

    def test_class_nested_and_non_direct_definitions_use_class_parent_scope(self) -> None:
        trees = {
            "synthetic_class_nested": ast.parse(
                "from rs9 import nebular080_consumer_core as core\n"
                "def helper():\n"
                "    return core._nebular_profile_contract\n"
                "def entry():\n"
                "    class Outer:\n"
                "        class Inner:\n"
                "            def run(self):\n"
                "                return helper()\n"
                "        if True:\n"
                "            def guarded(self):\n"
                "                return helper()\n"
                "    return Outer\n"
            )
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_consumer_core._nebular_profile_contract"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_class_nested.entry",), target),
            (
                "rs9.synthetic_class_nested.entry",
                "rs9.synthetic_class_nested.helper",
                target,
            ),
        )

    def test_relative_import_resolves_to_forbidden_leaf(self) -> None:
        trees = {
            "nebular080_release": ast.parse(
                "def validate_nebular080_release_admission():\n"
                "    return None\n"
            ),
            "synthetic_relative": ast.parse(
                "from .nebular080_release import validate_nebular080_release_admission\n"
                "def entry():\n"
                "    validate_nebular080_release_admission()\n"
            ),
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_release.validate_nebular080_release_admission"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_relative.entry",), target),
            ("rs9.synthetic_relative.entry", target),
        )

    def test_reexport_alias_chasing_resolves_to_forbidden_leaf(self) -> None:
        trees = {
            "nebular080_system_wheel": ast.parse(
                "def _system_wheel():\n"
                "    return None\n"
            ),
            "synthetic_facade": ast.parse(
                "from .nebular080_system_wheel import _system_wheel as exported\n"
            ),
            "synthetic_reexport_entry": ast.parse(
                "from rs9.synthetic_facade import exported\n"
                "def entry():\n"
                "    exported()\n"
            ),
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_system_wheel._system_wheel"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_reexport_entry.entry",), target),
            ("rs9.synthetic_reexport_entry.entry", target),
        )

    def test_root_package_reexport_resolves_to_forbidden_leaf(self) -> None:
        trees = _TreeSet({
            "__init__": ast.parse(
                "from .nebular080_release import validate_nebular080_release_admission\n"
            ),
            "nebular080_release": ast.parse(
                "def validate_nebular080_release_admission():\n"
                "    return None\n"
            ),
            "synthetic_root_entry": ast.parse(
                "from rs9 import validate_nebular080_release_admission\n"
                "def entry():\n"
                "    validate_nebular080_release_admission()\n"
            ),
        }, package_initializers={"__init__"})
        graph = _function_graph(trees)
        target = "rs9.nebular080_release.validate_nebular080_release_admission"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_root_entry.entry",), target),
            ("rs9.synthetic_root_entry.entry", target),
        )

    def test_reexported_module_object_tail_resolves_to_forbidden_leaf(self) -> None:
        trees = {
            "nebular080_consumer_core": ast.parse(
                "def _nebular_profile_contract():\n"
                "    return None\n"
            ),
            "synthetic_facade": ast.parse(
                "from . import nebular080_consumer_core as core\n"
            ),
            "synthetic_module_entry": ast.parse(
                "from rs9.synthetic_facade import core\n"
                "def entry():\n"
                "    return core._nebular_profile_contract()\n"
            ),
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_consumer_core._nebular_profile_contract"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_module_entry.entry",), target),
            ("rs9.synthetic_module_entry.entry", target),
        )

    def test_module_level_dispatch_load_is_conservatively_attached(self) -> None:
        trees = {
            "nebular080_system_wheel": ast.parse(
                "def _system_wheel():\n"
                "    return None\n"
            ),
            "synthetic_dispatch": ast.parse(
                "import rs9.nebular080_system_wheel\n"
                "HANDLER = rs9.nebular080_system_wheel._system_wheel\n"
                "def entry():\n"
                "    return HANDLER()\n"
            ),
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_system_wheel._system_wheel"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_dispatch.entry",), target),
            ("rs9.synthetic_dispatch.entry", target),
        )

    def test_cross_module_constant_and_class_dispatch_use_module_pseudonode(self) -> None:
        trees = {
            "nebular080_system_webkit": ast.parse(
                "def check_missing_runtime():\n"
                "    return None\n"
            ),
            "synthetic_provider": ast.parse(
                "from rs9 import nebular080_system_webkit as webkit\n"
                "_RUNNER = webkit.check_missing_runtime\n"
                "class Runner:\n"
                "    def run(self):\n"
                "        return webkit.check_missing_runtime()\n"
            ),
            "synthetic_cross_module_entry": ast.parse(
                "from rs9.synthetic_provider import _RUNNER, Runner\n"
                "def entry():\n"
                "    return _RUNNER(), Runner().run()\n"
            ),
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_system_webkit.check_missing_runtime"
        pseudo = "rs9.synthetic_provider.<module>"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_cross_module_entry.entry",), target),
            ("rs9.synthetic_cross_module_entry.entry", pseudo, target),
        )

    def test_subpackage_initializer_relative_reexport_is_resolved(self) -> None:
        trees = _TreeSet({
            "nebular080_system_wheel": ast.parse(
                "def _system_wheel():\n"
                "    return None\n"
            ),
            "sub": ast.parse("from .impl import exported\n"),
            "sub.impl": ast.parse(
                "from rs9.nebular080_system_wheel import _system_wheel as exported\n"
            ),
            "synthetic_subpackage_entry": ast.parse(
                "from rs9.sub import exported\n"
                "def entry():\n"
                "    return exported()\n"
            ),
        }, package_initializers={"sub"})
        graph = _function_graph(trees)
        target = "rs9.nebular080_system_wheel._system_wheel"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_subpackage_entry.entry",), target),
            ("rs9.synthetic_subpackage_entry.entry", target),
        )

    def test_subpackage_initializer_local_relative_import_fails_closed(self) -> None:
        trees = _TreeSet({
            "__init__": ast.parse(""),
            "sub": ast.parse(
                "class Runner:\n"
                "    def run(self):\n"
                "        from .impl import exported\n"
                "        return exported()\n"
            ),
            "sub.impl": ast.parse("def exported():\n    return None\n"),
            "synthetic_initializer_entry": ast.parse(
                "from rs9.sub import Runner\n"
                "def entry():\n"
                "    return Runner().run()\n"
            ),
        }, package_initializers={"__init__", "sub"})
        with self.assertRaisesRegex(AssertionError, "Relative import below module level"):
            _function_graph(trees)

    def test_unknown_non_root_module_reference_does_not_attach_root_pseudonode(self) -> None:
        trees = _TreeSet({
            "__init__": ast.parse(""),
            "synthetic_unknown_module": ast.parse(
                "import rs9.unknown_module as unknown\n"
                "def entry():\n"
                "    return unknown.symbol()\n"
            ),
        }, package_initializers={"__init__"})
        with self.assertRaisesRegex(AssertionError, "Unindexed rs9 module target"):
            _function_graph(trees)

    def test_comprehension_target_does_not_suppress_same_module_reference(self) -> None:
        trees = {
            "synthetic_comprehension": ast.parse(
                "def helper():\n"
                "    return None\n"
                "def entry(items):\n"
                "    values = [helper for helper in items]\n"
                "    return helper()\n"
            )
        }
        graph = _function_graph(trees)
        self.assertEqual(
            _find_path(
                graph,
                ("rs9.synthetic_comprehension.entry",),
                "rs9.synthetic_comprehension.helper",
            ),
            ("rs9.synthetic_comprehension.entry", "rs9.synthetic_comprehension.helper"),
        )

    def test_synthetic_two_hop_forbidden_load_is_detected(self) -> None:
        trees = {
            "synthetic": ast.parse(
                "import rs9.nebular080_system_wheel\n"
                "def entry():\n"
                "    helper()\n"
                "def helper():\n"
                "    rs9.nebular080_system_wheel._system_wheel\n"
            )
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_system_wheel._system_wheel"
        path = _find_path(graph, ("rs9.synthetic.entry",), target)
        self.assertEqual(path, ("rs9.synthetic.entry", "rs9.synthetic.helper", target))

    def test_function_local_alias_and_shadowing_are_scoped(self) -> None:
        trees = {
            "synthetic_scope": ast.parse(
                "import rs9.nebular080_system_wheel\n"
                "def local_alias():\n"
                "    from rs9 import nebular080_consumer_core as core\n"
                "    core._nebular_profile_contract\n"
                "def shadowed_alias():\n"
                "    core = object()\n"
                "    core._nebular_profile_contract\n"
            )
        }
        graph = _function_graph(trees)
        target = "rs9.nebular080_consumer_core._nebular_profile_contract"
        self.assertEqual(
            _find_path(graph, ("rs9.synthetic_scope.local_alias",), target),
            ("rs9.synthetic_scope.local_alias", target),
        )
        self.assertIsNone(_find_path(graph, ("rs9.synthetic_scope.shadowed_alias",), target))

    def test_real_qualification_crosses_consumer_into_installed_helper(self) -> None:
        graph = _function_graph(_actual_trees())
        start = "rs9.tf_pypi_nebular080_universal.qualify_native"
        consumer = "rs9.nebular080_universal_consumer.consume_universal_wheel"
        target = "rs9.nebular080_consumer_core._nebular_installed_consumer"
        path = _find_path(graph, (start,), target)
        self.assertEqual(path, (start, consumer, target))


if __name__ == "__main__":
    unittest.main()
