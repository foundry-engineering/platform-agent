from __future__ import annotations

import zipfile
from html import escape
from pathlib import Path

import pytest

from platform_agent.gantt_parser import GanttParseError, parse_gantt_workbook

POLICY_SHA = "b" * 64


def _cell(reference: str, value: str) -> str:
    return f'<c r="{reference}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'


def _write_workbook(
    path: Path,
    *,
    dependencies: bool = False,
    dependency_value: str = "",
    ambiguous: bool = False,
    formula: bool = False,
) -> None:
    headers = [
        "Track",
        "Workstream",
        "Deliverable",
        "Owner Repo(s)",
        "Status",
        "Notes / Acceptance",
    ]
    if dependencies:
        headers.append("Dependencies")

    header_cells = "".join(
        _cell(f"{chr(ord('A') + index)}4", value)
        for index, value in enumerate(headers)
    )

    first_task = [
        "P2 Plan Execution",
        "Plan ingestion contract",
        "PlanGraph v1 contract",
        "agent-protocol",
        "Open",
        "Schema validates deterministically",
    ]
    second_task = [
        "P2 Plan Execution",
        "Gantt parser",
        "Convert workbook to PlanGraph",
        "platform-agent",
        "Open",
        "Same workbook yields same plan",
    ]

    if ambiguous:
        second_task[3] = ""

    first_cells = "".join(
        _cell(f"{chr(ord('A') + index)}5", value)
        for index, value in enumerate(first_task)
    )
    second_cells = "".join(
        _cell(f"{chr(ord('A') + index)}6", value)
        for index, value in enumerate(second_task)
        if value
    )

    if dependencies:
        second_cells += _cell("G6", dependency_value)

    if formula:
        second_cells = second_cells.replace(
            _cell("C6", second_task[2]),
            '<c r="C6"><f>A1</f><v>1</v></c>',
        )

    worksheet = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        f'<row r="1">{_cell("A1", "Foundry Test Roadmap")}</row>'
        f'<row r="4">{header_cells}</row>'
        f'<row r="5">{first_cells}</row>'
        f'<row r="6">{second_cells}</row>'
        f'<row r="7">{_cell("A7", "Section marker")}</row>'
        "</sheetData>"
        "</worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Gantt" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)


def _parse(path: Path):
    return parse_gantt_workbook(
        path,
        policy_id="pol_foundry_default",
        policy_sha256=POLICY_SHA,
        jurisdiction="global",
    )


def test_parser_is_deterministic_and_skips_section_row(tmp_path: Path) -> None:
    workbook = tmp_path / "roadmap.xlsx"
    _write_workbook(workbook)

    first = _parse(workbook)
    second = _parse(workbook)

    assert first.plan_json() == second.plan_json()
    assert first.report.candidate_sha256 == second.report.candidate_sha256
    assert first.report.task_rows == (5, 6)
    assert first.report.section_rows == (7,)
    assert first.report.dependencies_column_present is False
    assert first.plan["tasks"][0]["dependencies"] == []
    assert first.plan["tasks"][1]["dependencies"] == []


def test_explicit_row_dependency_resolves_to_stable_task_id(tmp_path: Path) -> None:
    workbook = tmp_path / "roadmap.xlsx"
    _write_workbook(workbook, dependencies=True, dependency_value="row:5")

    parsed = _parse(workbook)
    tasks = parsed.plan["tasks"]

    assert parsed.report.dependencies_column_present is True
    assert tasks[1]["dependencies"] == [tasks[0]["task_id"]]


def test_invalid_dependency_syntax_is_rejected(tmp_path: Path) -> None:
    workbook = tmp_path / "roadmap.xlsx"
    _write_workbook(workbook, dependencies=True, dependency_value="5")

    with pytest.raises(GanttParseError, match="invalid dependency token"):
        _parse(workbook)


def test_ambiguous_task_row_is_rejected(tmp_path: Path) -> None:
    workbook = tmp_path / "roadmap.xlsx"
    _write_workbook(workbook, ambiguous=True)

    with pytest.raises(GanttParseError, match="ambiguous"):
        _parse(workbook)


def test_formula_in_source_cells_is_rejected(tmp_path: Path) -> None:
    workbook = tmp_path / "roadmap.xlsx"
    _write_workbook(workbook, formula=True)

    with pytest.raises(GanttParseError, match="formula cells are not accepted"):
        _parse(workbook)
