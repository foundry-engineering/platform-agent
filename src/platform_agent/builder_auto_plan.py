"""Deterministic import planning over an explicitly approved source manifest.

Parsing never imports project code, walks directories, executes tools, calls a
model or issues authority. Independent checks and scope remain operator input.
"""
from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.source_context import MAX_CONTEXT_BYTES, ScopedSourceContext, SourceSnapshot, source_path
from tree_sitter import Language, Node, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from .builder_work_units import BuilderWorkUnit, unit_definitions, validate_work_units
from .engineering_builder_authority import TenantBuilderAuthority

_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")
_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AutoPlanSpecification:
    source_paths: tuple[str, ...]
    file_checks: tuple[tuple[str, tuple[str, ...]], ...]
    max_files_per_unit: int
    max_rounds_per_unit: int
    module_aliases: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (not isinstance(self.source_paths, tuple) or not 1 <= len(self.source_paths) <= 48
                or len(set(self.source_paths)) != len(self.source_paths)):
            raise BuilderBoundaryError("automatic planning requires a bounded unique source manifest")
        for path in self.source_paths:
            source_path(path)
        if any(PurePosixPath(a) in PurePosixPath(b).parents for a in self.source_paths
               for b in self.source_paths if a != b):
            raise BuilderBoundaryError("automatic source paths cannot alias directories")
        if (not isinstance(self.file_checks, tuple) or len(self.file_checks) != len(self.source_paths)
                or {path for path, _ in self.file_checks} != set(self.source_paths)):
            raise BuilderBoundaryError("each automatic source requires independent check ownership")
        for _, checks in self.file_checks:
            if (not isinstance(checks, tuple) or not 1 <= len(checks) <= 12
                    or len(set(checks)) != len(checks)
                    or any(not isinstance(c, str) or not _ID.fullmatch(c) for c in checks)):
                raise BuilderBoundaryError("automatic planning requires explicit trusted check IDs")
        if (type(self.max_files_per_unit) is not int or not 1 <= self.max_files_per_unit <= 8
                or type(self.max_rounds_per_unit) is not int or not 1 <= self.max_rounds_per_unit <= 6):
            raise BuilderBoundaryError("automatic work-unit limits exceed the Builder boundary")
        if (not isinstance(self.module_aliases, tuple)
                or len(self.module_aliases) > 16 or len(dict(self.module_aliases)) != len(self.module_aliases)):
            raise BuilderBoundaryError("bounded explicit module aliases required")
        for alias, target in self.module_aliases:
            if (not isinstance(alias, str) or not re.fullmatch(r"[@A-Za-z][@A-Za-z0-9_/-]{0,63}/", alias)
                    or ".." in alias or not isinstance(target, str) or not target.endswith("/")):
                raise BuilderBoundaryError("module aliases must use canonical directory prefixes")
            source_path(target + "placeholder.ts")

    @classmethod
    def from_payload(cls, value: object) -> AutoPlanSpecification:
        keys = {"schemaVersion", "sourcePaths", "fileChecks", "maxFilesPerUnit", "maxRoundsPerUnit", "moduleAliases"}
        if (not isinstance(value, dict) or set(value) != keys
                or value["schemaVersion"] != "foundry.builder-auto-plan.v1"
                or not isinstance(value["sourcePaths"], list)
                or not isinstance(value["fileChecks"], dict) or not isinstance(value["moduleAliases"], dict)
                or any(not isinstance(checks, list) for checks in value["fileChecks"].values())):
            raise BuilderBoundaryError("exact automatic Builder planning profile required")
        return cls(tuple(value["sourcePaths"]),
            tuple((path, tuple(checks)) for path, checks in sorted(value["fileChecks"].items())),
            value["maxFilesPerUnit"], value["maxRoundsPerUnit"],
            tuple(sorted(value["moduleAliases"].items())))


def _snapshots(workspace: Path, paths: tuple[str, ...]) -> tuple[SourceSnapshot, ...]:
    items = tuple(ScopedSourceContext(workspace, (path,)).snapshot()[0] for path in paths)
    if sum(len((item.content or "").encode()) + len(item.path.encode()) for item in items) > 192 * 1024:
        raise BuilderBoundaryError("automatic planning exceeds the aggregate source byte limit")
    return items


def _python_edges(path: str, content: str, paths: frozenset[str]) -> set[str]:
    # Both repository-root imports and the conventional src-layout are indexed.
    modules: dict[str, set[str]] = {}
    for candidate in paths:
        if not candidate.endswith(".py"):
            continue
        module = candidate[:-3].replace("/", ".")
        if module.endswith(".__init__"):
            module = module[:-9]
        for name in {module, module.removeprefix("src.")}:
            modules.setdefault(name, set()).add(candidate)
    edges: set[str] = set()
    def resolve(name: str, *, required: bool = False) -> bool:
        matches = modules.get(name, set())
        if len(matches) > 1:
            raise BuilderBoundaryError("ambiguous approved Python module")
        if matches:
            edges.update(matches)
            # Package initialization is also an import dependency.
            pieces = name.split(".")
            for i in range(1, len(pieces)):
                parents = modules.get(".".join(pieces[:i]), set())
                if len(parents) > 1:
                    raise BuilderBoundaryError("ambiguous approved Python package")
                edges.update(parents)
        elif required:
            raise BuilderBoundaryError("local Python import is outside the approved source manifest")
        return bool(matches)
    try:
        tree = ast.parse(content, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        raise BuilderBoundaryError("automatic planning requires parseable Python sources") from None
    package = path[:-3].replace("/", ".").split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
            isinstance(node.func, ast.Name) and node.func.id in {"__import__", "import_module"}
            or isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
        ):
            raise BuilderBoundaryError("dynamic Python imports require explicit work-unit planning")
        if isinstance(node, ast.Import):
            for alias in node.names:
                resolve(alias.name, required=alias.name.startswith("src."))
        elif isinstance(node, ast.ImportFrom):
            if node.level > len(package):
                raise BuilderBoundaryError("Python relative import escapes its package")
            prefix = package[:len(package) - node.level + 1] if node.level else []
            base = ".".join((*prefix, *((node.module or "").split(".") if node.module else [])))
            base_found = resolve(base) if base else False
            children_found = False
            for alias in node.names:
                if alias.name != "*":
                    child_found = resolve(".".join(filter(None, (base, alias.name))))
                    children_found = children_found or child_found
                    if node.level and not node.module and not (base_found or child_found):
                        raise BuilderBoundaryError("relative Python import is outside approved scope")
            if (node.level or base.startswith("src.")) and not (base_found or children_found):
                raise BuilderBoundaryError("local Python import is outside the approved source manifest")
    return edges - {path}


def _javascript_edges(path: str, content: str, paths: frozenset[str],
                      aliases: tuple[tuple[str, str], ...]) -> set[str]:
    suffix = PurePosixPath(path).suffix
    grammar = (tree_sitter_typescript.language_tsx() if suffix == ".tsx" else
        tree_sitter_typescript.language_typescript() if suffix in {".ts", ".mts", ".cts"} else
        tree_sitter_javascript.language())
    data = content.encode()
    tree = Parser(Language(grammar)).parse(data)
    if tree.root_node.has_error:
        raise BuilderBoundaryError("automatic planning requires parseable JavaScript/TypeScript sources")
    imports: set[str] = set()
    def literal(node: Node | None) -> str:
        if node is None or node.type != "string":
            raise BuilderBoundaryError("nonliteral JavaScript imports require explicit work-unit planning")
        raw = data[node.start_byte:node.end_byte].decode()
        if len(raw) < 2 or "\\" in raw or raw[0] not in {"'", '\"'} or raw[-1] != raw[0]:
            raise BuilderBoundaryError("escaped JavaScript imports require explicit work-unit planning")
        return raw[1:-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in {"import_statement", "export_statement", "import_require_clause"}:
            source = node.child_by_field_name("source")
            if source is not None:
                imports.add(literal(source))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            function_name = data[function.start_byte:function.end_byte] if function is not None else b""
            if function_name in {b"require", b"import", b"require.resolve"}:
                args = node.child_by_field_name("arguments")
                arguments = tuple(n for n in args.named_children if n.type != "comment") if args else ()
                if len(arguments) != 1:
                    raise BuilderBoundaryError("dynamic JavaScript dependencies require explicit work units")
                imports.add(literal(arguments[0]))
        stack.extend(node.named_children)
    edges: set[str] = set()
    for name in sorted(imports):
        local: str | None = None
        if name.startswith("."):
            local = posixpath.normpath(posixpath.join(posixpath.dirname(path), name))
        elif name.startswith("/"):
            raise BuilderBoundaryError("absolute JavaScript imports are outside the approved manifest")
        else:
            matches = [(alias, target) for alias, target in aliases if name.startswith(alias)]
            if matches:
                alias, target = max(matches, key=lambda pair: len(pair[0]))
                local = target + name[len(alias):]
        if local is None:
            continue  # External packages confer no repository read or execution authority.
        source_path(local if PurePosixPath(local).suffix else local + ".ts")
        candidates = {local, *(local + ext for ext in _EXTENSIONS),
            *(local + "/index" + ext for ext in _EXTENSIONS)} & paths
        if local.endswith((".js", ".jsx")):
            candidates.update({local.rsplit(".", 1)[0] + ext for ext in (".ts", ".tsx")} & paths)
        if len(candidates) != 1:
            raise BuilderBoundaryError("local JavaScript import is missing or ambiguous in approved scope")
        edges.update(candidates)
    return edges - {path}


@dataclass(frozen=True, slots=True)
class AutomaticWorkPlan:
    specification: AutoPlanSpecification
    units: tuple[BuilderWorkUnit, ...]
    source_digests: tuple[tuple[str, str | None], ...]
    dependencies: tuple[tuple[str, tuple[str, ...]], ...]

    def evidence(self) -> dict[str, Any]:
        value: dict[str, Any] = {"schema_version": "foundry.builder-auto-plan-evidence.v1",
            "algorithm": "approved-static-imports.v1", "sources": dict(self.source_digests),
            "dependencies": dict(self.dependencies), "work_units": unit_definitions(self.units),
            "file_checks": dict(self.specification.file_checks),
            "module_aliases": dict(self.specification.module_aliases),
            "max_files_per_unit": self.specification.max_files_per_unit,
            "max_rounds_per_unit": self.specification.max_rounds_per_unit}
        return {**value, "plan_sha256": _digest(value)}

    def require_current(self, authority: TenantBuilderAuthority, workspace: Path) -> None:
        authority.checkpoint()
        authority.require_source_paths(self.specification.source_paths)
        current = _snapshots(workspace, tuple(path for path, _ in self.source_digests))
        if tuple((item.path, item.sha256) for item in current) != self.source_digests:
            raise BuilderBoundaryError("automatic plan source changed; fresh planning required")
        authority.checkpoint()


def compile_automatic_plan(*, specification: AutoPlanSpecification,
                           authority: TenantBuilderAuthority, workspace: Path) -> AutomaticWorkPlan:
    authority.checkpoint()
    paths = tuple(sorted(specification.source_paths))
    specification = replace(specification, source_paths=paths,
        file_checks=tuple(sorted(specification.file_checks)), module_aliases=tuple(sorted(specification.module_aliases)))
    authority.require_source_paths(paths)  # Verify authorization BEFORE any source read.
    sources = _snapshots(workspace, paths)
    dependencies: dict[str, set[str]] = {path: set() for path in paths}
    parsed = 0
    for item in sources:
        if item.content is None:
            raise BuilderBoundaryError("automatic import planning requires existing source files")
        if item.path.endswith(".py"):
            dependencies[item.path] = _python_edges(item.path, item.content, frozenset(paths))
            parsed += 1
        elif PurePosixPath(item.path).suffix in _EXTENSIONS:
            dependencies[item.path] = _javascript_edges(item.path, item.content, frozenset(paths), specification.module_aliases)
            parsed += 1
    if not parsed:
        raise BuilderBoundaryError("automatic planning requires Python, JavaScript or TypeScript source")
    # Shared checks and import cycles are atomic; no partial component may pass
    # a check that assumes another uncompleted component has already been built.
    owner = {path: path for path in paths}
    def find(path: str) -> str:
        while owner[path] != path:
            path = owner[path]
        return path
    def merge(a: str, b: str) -> None:
        left, right = sorted((find(a), find(b)))
        owner[right] = left
    checks = dict(specification.file_checks)
    for a in paths:
        for b in paths:
            if set(checks[a]) & set(checks[b]):
                merge(a, b)
    # At most 48 nodes: closure is small and deterministic, including cycles
    # introduced by merging shared-check owners.
    while True:
        groups = {find(path) for path in paths}
        graph = {group: {find(dep) for path in paths if find(path) == group
            for dep in dependencies[path] if find(dep) != group} for group in groups}
        reach = {group: set(edges) for group, edges in graph.items()}
        for _ in groups:
            for group in sorted(groups):
                reach[group].update(dep for parent in tuple(reach[group]) for dep in reach[parent])
        cycles = [(a, b) for a in sorted(groups) for b in sorted(groups) if a < b
                  and b in reach[a] and a in reach[b]]
        if not cycles:
            break
        for a, b in cycles:
            merge(a, b)
    ordered: list[str] = []
    while len(ordered) < len(graph):
        ready = sorted(group for group, deps in graph.items() if group not in ordered and deps <= set(ordered))
        if not ready:
            raise BuilderBoundaryError("automatic component graph cannot be scheduled")
        ordered.append(ready[0])
    contents = {item.path: item.content or "" for item in sources}
    def fits(outputs: set[str]) -> bool:
        context = outputs | {dep for path in outputs for dep in dependencies[path]}
        return (len(outputs) <= specification.max_files_per_unit and len(context) <= 16
            and len({check for path in outputs for check in checks[path]}) <= 12
            and sum(len(contents[path].encode()) + len(path.encode()) for path in context) <= MAX_CONTEXT_BYTES)
    batches: list[set[str]] = []
    for group in ordered:
        component = {path for path in paths if find(path) == group}
        if not fits(component):
            raise BuilderBoundaryError("atomic import/check component exceeds work-unit limits")
        if batches and fits(batches[-1] | component):
            batches[-1].update(component)
        else:
            batches.append(component)
    ids = ["auto_" + _digest(sorted(batch))[:20] for batch in batches]
    producers = {path: ids[i] for i, batch in enumerate(batches) for path in batch}
    units = tuple(BuilderWorkUnit(ids[i],
        "Apply the approved root objective only to these outputs; preserve verified dependency interfaces.",
        tuple(sorted(batch | {dep for path in batch for dep in dependencies[path]})), tuple(sorted(batch)),
        tuple(sorted({producers[dep] for path in batch for dep in dependencies[path]} - {ids[i]})),
        specification.max_rounds_per_unit, tuple(sorted({check for path in batch for check in checks[path]})))
        for i, batch in enumerate(batches))
    validate_work_units(authority.task, paths, units, authority.policy_ref)
    plan = AutomaticWorkPlan(specification, units, tuple((item.path, item.sha256) for item in sources),
        tuple((path, tuple(sorted(dependencies[path]))) for path in paths))
    plan.require_current(authority, workspace)
    return plan
