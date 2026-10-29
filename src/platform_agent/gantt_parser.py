from __future__ import annotations

import hashlib
import json
import posixpath
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from xml.etree import ElementTree

from platform_agent.plan_source import PlanSourceError, inspect_plan_source

_PARSE_REPORT_SCHEMA: Final[str] = "foundry.gantt-parse-report.v1"
_PLAN_GRAPH_VERSION: Final[str] = "plangraph.v1"
_GANTT_SHEET: Final[str] = "Gantt"

_REQUIRED_HEADERS: Final[tuple[str, ...]] = (
    "Track",
    "Workstream",
    "Deliverable",
    "Owner Repo(s)",
    "Status",
    "Notes / Acceptance",
)
_OPTIONAL_DEPENDENCIES_HEADER: Final[str] = "Dependencies"

_MAIN_NS: Final[str] = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS: Final[str] = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_REL_NS: Final[str] = "http://schemas.openxmlformats.org/package/2006/relationships"

_MAX_ZIP_ENTRIES: Final[int] = 2048
_MAX_ZIP_UNCOMPRESSED_BYTES: Final[int] = 128 * 1024 * 1024
_MAX_XML_BYTES: Final[int] = 32 * 1024 * 1024
_MAX_ROWS: Final[int] = 10000
_MAX_CELLS: Final[int] = 250000

_CELL_REF = re.compile(r"^([A-Z]+)([1-9][0-9]*)$")
_DEPENDENCY_TOKEN = re.compile(r"^row:([1-9][0-9]*)$")


class GanttParseError(ValueError):
    """Raised when an XLSX Gantt cannot be interpreted deterministically."""


@dataclass(frozen=True, slots=True)
class ParseReport:
    schema: str
    source_sha256: str
    source_size_bytes: int
    sheet: str
    title: str
    header_row: int
    task_rows: tuple[int, ...]
    section_rows: tuple[int, ...]
    dependencies_column_present: bool
    dependency_syntax: str | None
    candidate_sha256: str
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
            "sheet": self.sheet,
            "title": self.title,
            "header_row": self.header_row,
            "task_rows": list(self.task_rows),
            "section_rows": list(self.section_rows),
            "dependencies_column_present": self.dependencies_column_present,
            "dependency_syntax": self.dependency_syntax,
            "candidate_sha256": self.candidate_sha256,
            "warnings": list(self.warnings),
        }

    def to_canonical_json(self) -> str:
        return _canonical_json(self.as_dict())


@dataclass(frozen=True, slots=True)
class ParsedPlan:
    plan: dict[str, object]
    report: ParseReport

    def plan_json(self) -> str:
        return _canonical_json(self.plan)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, value: str, *, length: int = 32) -> str:
    return f"{prefix}{_sha256_text(value)[:length]}"


def _normalize_text(value: str) -> str:
    return " ".join(value.replace("\r\n", "\n").replace("\r", "\n").split())


def _column_number(reference: str) -> int:
    match = _CELL_REF.match(reference)
    if match is None:
        raise GanttParseError(f"invalid cell reference: {reference}")

    result = 0
    for char in match.group(1):
        result = result * 26 + (ord(char) - ord("A") + 1)
    return result


def _safe_member_name(name: str) -> None:
    if "\\" in name:
        raise GanttParseError(f"unsafe XLSX member path: {name}")
    if name.startswith("/"):
        raise GanttParseError(f"unsafe XLSX member path: {name}")

    normalized = posixpath.normpath(name)
    if normalized == ".." or normalized.startswith("../"):
        raise GanttParseError(f"unsafe XLSX member path: {name}")


def _audit_archive(archive: zipfile.ZipFile) -> None:
    infos = archive.infolist()
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise GanttParseError(
            f"XLSX contains too many archive entries: {len(infos)} > {_MAX_ZIP_ENTRIES}"
        )

    total = 0
    for info in infos:
        _safe_member_name(info.filename)
        total += info.file_size
        if total > _MAX_ZIP_UNCOMPRESSED_BYTES:
            raise GanttParseError(
                "XLSX uncompressed content exceeds deterministic safety limit"
            )


def _read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    _safe_member_name(name)
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise GanttParseError(f"required XLSX member missing: {name}") from exc

    if info.file_size > _MAX_XML_BYTES:
        raise GanttParseError(f"XLSX XML member exceeds safety limit: {name}")

    return archive.read(info)


def _xml_root(archive: zipfile.ZipFile, name: str) -> ElementTree.Element:
    payload = _read_member(archive, name)
    try:
        return ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise GanttParseError(f"invalid XML in XLSX member: {name}") from exc


def _shared_strings(archive: zipfile.ZipFile) -> tuple[str, ...]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return ()

    root = _xml_root(archive, "xl/sharedStrings.xml")
    values: list[str] = []
    for item in root.findall(f"{{{_MAIN_NS}}}si"):
        values.append(
            "".join(node.text or "" for node in item.iter(f"{{{_MAIN_NS}}}t"))
        )
    return tuple(values)


def _sheet_member(archive: zipfile.ZipFile, sheet_name: str) -> str:
    workbook = _xml_root(archive, "xl/workbook.xml")
    relationship_id: str | None = None

    for sheet in workbook.findall(f".//{{{_MAIN_NS}}}sheet"):
        if sheet.get("name") == sheet_name:
            relationship_id = sheet.get(f"{{{_REL_NS}}}id")
            break

    if relationship_id is None:
        raise GanttParseError(f"required sheet not found: {sheet_name}")

    rels = _xml_root(archive, "xl/_rels/workbook.xml.rels")
    target: str | None = None
    for relation in rels.findall(f"{{{_PACKAGE_REL_NS}}}Relationship"):
        if relation.get("Id") == relationship_id:
            target = relation.get("Target")
            break

    if not target:
        raise GanttParseError(f"worksheet relationship missing for: {sheet_name}")

    if target.startswith("/"):
        member = target.lstrip("/")
    else:
        member = posixpath.normpath(posixpath.join("xl", target))

    _safe_member_name(member)
    if not member.startswith("xl/"):
        raise GanttParseError("worksheet relationship escapes xl/ namespace")
    return member


def _cell_text(cell: ElementTree.Element, shared_strings: tuple[str, ...]) -> str:
    if cell.find(f"{{{_MAIN_NS}}}f") is not None:
        raise GanttParseError(
            f"formula cells are not accepted in deterministic Gantt parsing: {cell.get('r')}"
        )

    cell_type = cell.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.iter(f"{{{_MAIN_NS}}}t"))

    value = cell.find(f"{{{_MAIN_NS}}}v")
    raw = "" if value is None or value.text is None else value.text

    if cell_type == "s":
        try:
            return shared_strings[int(raw)]
        except (ValueError, IndexError) as exc:
            raise GanttParseError(f"invalid shared-string index at {cell.get('r')}") from exc

    if cell_type in (None, "str", "n"):
        return raw

    if cell_type == "b":
        if raw not in {"0", "1"}:
            raise GanttParseError(f"invalid boolean cell at {cell.get('r')}")
        return "TRUE" if raw == "1" else "FALSE"

    raise GanttParseError(f"unsupported cell type {cell_type!r} at {cell.get('r')}")


def _rows(
    archive: zipfile.ZipFile,
    sheet_member: str,
    shared_strings: tuple[str, ...],
) -> dict[int, dict[int, str]]:
    root = _xml_root(archive, sheet_member)
    result: dict[int, dict[int, str]] = {}
    cell_count = 0

    for row in root.findall(f".//{{{_MAIN_NS}}}sheetData/{{{_MAIN_NS}}}row"):
        row_raw = row.get("r")
        if row_raw is None:
            raise GanttParseError("worksheet row without row number")

        row_number = int(row_raw)
        if row_number > _MAX_ROWS:
            raise GanttParseError(f"worksheet row exceeds supported limit: {row_number}")

        values: dict[int, str] = {}
        for cell in row.findall(f"{{{_MAIN_NS}}}c"):
            cell_count += 1
            if cell_count > _MAX_CELLS:
                raise GanttParseError("worksheet exceeds supported cell limit")

            reference = cell.get("r")
            if reference is None:
                raise GanttParseError(f"cell without reference in row {row_number}")

            values[_column_number(reference)] = _cell_text(cell, shared_strings)
        result[row_number] = values

    return result


def _find_header_row(rows: dict[int, dict[int, str]]) -> tuple[int, dict[str, int]]:
    for row_number in sorted(rows):
        values = rows[row_number]
        normalized = {
            _normalize_text(value): column
            for column, value in values.items()
            if _normalize_text(value)
        }

        if all(header in normalized for header in _REQUIRED_HEADERS):
            columns = {header: normalized[header] for header in _REQUIRED_HEADERS}
            if _OPTIONAL_DEPENDENCIES_HEADER in normalized:
                columns[_OPTIONAL_DEPENDENCIES_HEADER] = normalized[
                    _OPTIONAL_DEPENDENCIES_HEADER
                ]
            return row_number, columns

    expected = ", ".join(_REQUIRED_HEADERS)
    raise GanttParseError(f"Gantt header row not found; expected exact headers: {expected}")


def _row_value(values: dict[int, str], columns: dict[str, int], header: str) -> str:
    return _normalize_text(values.get(columns[header], ""))


def _task_identity(
    *,
    source_sha256: str,
    row_number: int,
    track: str,
    workstream: str,
    deliverable: str,
    owner: str,
    acceptance: str,
) -> str:
    material = "\x1f".join(
        (
            source_sha256,
            _GANTT_SHEET,
            str(row_number),
            track,
            workstream,
            deliverable,
            owner,
            acceptance,
        )
    )
    return _stable_id("tsk_", material)


def _parse_dependency_rows(raw: str, *, row_number: int) -> tuple[int, ...]:
    if not raw:
        return ()

    dependencies: list[int] = []
    for token in raw.split(";"):
        normalized = token.strip()
        match = _DEPENDENCY_TOKEN.match(normalized)
        if match is None:
            raise GanttParseError(
                f"row {row_number} has invalid dependency token {normalized!r}; "
                "expected semicolon-separated row:<number> references"
            )
        dependencies.append(int(match.group(1)))

    if len(dependencies) != len(set(dependencies)):
        raise GanttParseError(f"row {row_number} contains duplicate dependencies")
    return tuple(dependencies)


def _assert_acyclic(tasks: list[dict[str, object]]) -> None:
    dependencies: dict[str, tuple[str, ...]] = {}
    for task in tasks:
        task_id = str(task["task_id"])
        deps = task["dependencies"]
        if not isinstance(deps, list):
            raise GanttParseError(f"internal dependency shape error for {task_id}")
        dependencies[task_id] = tuple(str(dep) for dep in deps)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visited:
            return
        if task_id in visiting:
            raise GanttParseError(f"dependency cycle detected at {task_id}")

        visiting.add(task_id)
        for dependency in dependencies.get(task_id, ()):
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in dependencies:
        visit(task_id)


def parse_gantt_workbook(
    source: str | Path,
    *,
    policy_id: str,
    policy_sha256: str,
    jurisdiction: str,
    policy_constraints: tuple[str, ...] = (),
) -> ParsedPlan:
    """Parse an approved Foundry Gantt workbook into a PlanGraph v1 candidate.

    Dependencies are never inferred from row order. If a Dependencies column is
    absent, every task receives an empty dependency list and the parse report
    records that fact. If present, only semicolon-separated row:<number>
    references are accepted.
    """
    try:
        fingerprint = inspect_plan_source(source)
    except PlanSourceError as exc:
        raise GanttParseError(str(exc)) from exc

    path = Path(source)

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise GanttParseError("plan source is not a valid XLSX ZIP container") from exc

    with archive:
        _audit_archive(archive)
        shared_strings = _shared_strings(archive)
        sheet_member = _sheet_member(archive, _GANTT_SHEET)
        rows = _rows(archive, sheet_member, shared_strings)

    title = _normalize_text(rows.get(1, {}).get(1, ""))
    if not title:
        raise GanttParseError("Gantt title is missing from A1")

    header_row, columns = _find_header_row(rows)
    dependencies_column_present = _OPTIONAL_DEPENDENCIES_HEADER in columns

    raw_tasks: list[dict[str, object]] = []
    section_rows: list[int] = []
    task_rows: list[int] = []
    row_to_task_id: dict[int, str] = {}
    raw_dependency_rows: dict[int, tuple[int, ...]] = {}

    for row_number in sorted(rows):
        if row_number <= header_row:
            continue

        values = rows[row_number]
        core = {header: _row_value(values, columns, header) for header in _REQUIRED_HEADERS}

        nonempty_core = [header for header, value in core.items() if value]
        if not nonempty_core:
            continue

        if (
            core["Track"]
            and not core["Workstream"]
            and not core["Deliverable"]
            and not core["Owner Repo(s)"]
            and not core["Status"]
            and not core["Notes / Acceptance"]
        ):
            section_rows.append(row_number)
            continue

        missing = [header for header, value in core.items() if not value]
        if missing:
            raise GanttParseError(
                f"row {row_number} is ambiguous; missing required cells: {', '.join(missing)}"
            )

        task_id = _task_identity(
            source_sha256=fingerprint.sha256,
            row_number=row_number,
            track=core["Track"],
            workstream=core["Workstream"],
            deliverable=core["Deliverable"],
            owner=core["Owner Repo(s)"],
            acceptance=core["Notes / Acceptance"],
        )
        gate_id = _stable_id(
            "gate_",
            f"{task_id}\x1f{core['Notes / Acceptance']}",
            length=24,
        )

        dependency_raw = ""
        if dependencies_column_present:
            dependency_raw = _normalize_text(
                values.get(columns[_OPTIONAL_DEPENDENCIES_HEADER], "")
            )
        dependency_rows = _parse_dependency_rows(dependency_raw, row_number=row_number)

        task: dict[str, object] = {
            "task_id": task_id,
            "title": core["Workstream"],
            "description": (
                f"Track: {core['Track']}. Roadmap status: {core['Status']}. "
                f"Deliverable: {core['Deliverable']}"
            ),
            "dependencies": [],
            "routing": {
                "owner": core["Owner Repo(s)"],
                "required_capabilities": [],
            },
            "target": None,
            "preconditions": [],
            "acceptance_gates": [
                {
                    "gate_id": gate_id,
                    "kind": "custom",
                    "criteria": core["Notes / Acceptance"],
                    "evidence_requirements": ["task acceptance evidence"],
                }
            ],
            "inputs": [f"xlsx:{_GANTT_SHEET}!row:{row_number}"],
            "deliverables": [core["Deliverable"]],
            "evidence_refs": [],
        }

        raw_tasks.append(task)
        task_rows.append(row_number)
        row_to_task_id[row_number] = task_id
        raw_dependency_rows[row_number] = dependency_rows

    if not raw_tasks:
        raise GanttParseError("Gantt contains no deterministic task rows")

    for row_number, task in zip(task_rows, raw_tasks, strict=True):
        resolved: list[str] = []
        for dependency_row in raw_dependency_rows[row_number]:
            if dependency_row == row_number:
                raise GanttParseError(f"row {row_number} depends on itself")
            try:
                resolved.append(row_to_task_id[dependency_row])
            except KeyError as exc:
                raise GanttParseError(
                    f"row {row_number} references non-task dependency row {dependency_row}"
                ) from exc
        task["dependencies"] = resolved

    _assert_acyclic(raw_tasks)

    policy_ref: dict[str, object] = {
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,
        "jurisdiction": jurisdiction,
        "constraints": list(policy_constraints),
    }
    plan_id = _stable_id(
        "pln_",
        f"{fingerprint.sha256}\x1f{_GANTT_SHEET}\x1f{header_row}",
    )
    plan: dict[str, object] = {
        "schema_version": _PLAN_GRAPH_VERSION,
        "plan_id": plan_id,
        "title": title,
        "source": {
            "kind": "xlsx",
            "sha256": fingerprint.sha256,
            "ref": path.name,
        },
        "policy_ref": policy_ref,
        "tasks": raw_tasks,
    }

    candidate_sha256 = hashlib.sha256(_canonical_json(plan).encode("utf-8")).hexdigest()

    warnings: list[str] = []
    if not dependencies_column_present:
        warnings.append("Dependencies column absent; parser emitted no inferred dependencies.")

    report = ParseReport(
        schema=_PARSE_REPORT_SCHEMA,
        source_sha256=fingerprint.sha256,
        source_size_bytes=fingerprint.size_bytes,
        sheet=_GANTT_SHEET,
        title=title,
        header_row=header_row,
        task_rows=tuple(task_rows),
        section_rows=tuple(section_rows),
        dependencies_column_present=dependencies_column_present,
        dependency_syntax=(
            "semicolon-separated row:<number> references"
            if dependencies_column_present
            else None
        ),
        candidate_sha256=candidate_sha256,
        warnings=tuple(warnings),
    )
    return ParsedPlan(plan=plan, report=report)
