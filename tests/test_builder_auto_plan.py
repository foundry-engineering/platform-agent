"""Static planning with actual parser grammars, real scoped reads and grant checks."""
from dataclasses import replace
import json
import zipfile

import pytest
from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.source_context import SourceContextError

from builder_runtime_fixture import Harness
from platform_agent.builder_auto_plan import AutoPlanSpecification, compile_automatic_plan


def specification(files, *, size=1, rounds=1, checks=None, aliases=()):
    return AutoPlanSpecification(tuple(files), tuple((p, tuple(checks[p]) if checks else
        ('check_' + str(i),)) for i, p in enumerate(sorted(files))), size, rounds, aliases)


def seed(h, files):
    for path, content in files.items():
        target = h.workspace / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def plan(h, spec):
    return compile_automatic_plan(specification=spec, authority=h.authority(), workspace=h.workspace)


def test_python_imports_derive_deterministic_units_context_and_order(tmp_path):
    h = Harness(tmp_path)
    files = {'src/orders.py': 'from pricing import total\ndef invoice(): return total()\n',
        'src/pricing.py': 'def total(): return 0\n'}
    seed(h, files)
    spec = specification(files)
    result = plan(h, spec)
    assert [u.output_paths for u in result.units] == [('src/pricing.py',), ('src/orders.py',)]
    assert result.units[1].dependencies == (result.units[0].unit_id,)
    assert result.units[1].source_paths == tuple(sorted(files))
    assert result == plan(h, replace(spec, source_paths=tuple(reversed(spec.source_paths))))
    evidence = result.evidence()
    assert evidence['dependencies']['src/orders.py'] == ('src/pricing.py',)
    assert len(evidence['plan_sha256']) == 64
    assert h.runner.requests == []
    result.require_current(h.authority(), h.workspace)
    (h.workspace / 'src/pricing.py').write_text('def total(): return 1\n')
    with pytest.raises(BuilderBoundaryError, match='source changed'):
        result.require_current(h.authority(), h.workspace)
    with pytest.raises(BuilderBoundaryError, match='source changed'):
        h.runtime(source_paths=tuple(sorted(files)), work_units=result.units, automatic_plan=result,
            unit_verifiers={u.unit_id: h.verifier for u in result.units})
    assert h.runner.requests == []


@pytest.mark.parametrize('shared', [False, True])
def test_cycles_and_shared_check_owners_are_atomic(tmp_path, shared):
    h = Harness(tmp_path)
    files = {'src/a.py': 'from b import x\nx=1\n', 'src/b.py': 'x=2\n' if shared else 'from a import x\nx=2\n'}
    seed(h, files)
    checks = {p: ['shared-check'] for p in files} if shared else None
    with pytest.raises(BuilderBoundaryError, match='atomic'):
        plan(h, specification(files, checks=checks))
    result = plan(h, specification(files, size=2, checks=checks))
    assert len(result.units) == 1 and result.units[0].output_paths == tuple(sorted(files))


def test_check_merges_that_introduce_cycles_are_recomputed(tmp_path):
    h = Harness(tmp_path)
    files = {'src/a.py': 'from b import x\n', 'src/b.py': 'from c import x\n', 'src/c.py': 'x=1\n'}
    seed(h, files)
    checks = {'src/a.py': ['ac-check'], 'src/b.py': ['b-check'], 'src/c.py': ['ac-check']}
    result = plan(h, specification(files, size=3, checks=checks))
    assert len(result.units) == 1 and len(result.units[0].output_paths) == 3


@pytest.mark.parametrize('ext', ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'mts', 'cts'])
def test_real_javascript_grammars_resolve_static_exports_aliases_and_literal_calls(tmp_path, ext):
    h = Harness(tmp_path)
    files = {f'src/app.{ext}': "// import './absent'\nconst ignored = \"require('./absent')\";\n"
        "import {x} from '@/base';\nexport {x as y} from './other';\n"
        "const z=require('./third');const later=import('./third');\n",
        'src/base.ts': 'export const x=1;\n', 'src/other.js': 'export const x=2;\n',
        'src/third.js': 'module.exports=3;\n'}
    seed(h, files)
    h.task = replace(h.task, max_rounds=6)
    result = plan(h, specification(files, aliases=(('@/', 'src/'),)))
    assert dict(result.dependencies)[f'src/app.{ext}'] == ('src/base.ts', 'src/other.js', 'src/third.js')
    unit = next(u for u in result.units if f'src/app.{ext}' in u.output_paths)
    assert set(unit.source_paths) == set(files) and len(unit.dependencies) == 3


@pytest.mark.parametrize('content', ["import('./missing')", "require(name)", "import(name)",
    "import x from './missing'", "import x from '../outside'", "import x from '/absolute'", "function {"])
def test_unsupported_or_cross_scope_javascript_is_rejected_before_model(tmp_path, content):
    h = Harness(tmp_path)
    seed(h, {'src/app.ts': content})
    with pytest.raises((BuilderBoundaryError, SourceContextError)):
        plan(h, specification(['src/app.ts']))
    assert not h.runner.requests


@pytest.mark.parametrize('content', ['from .missing import x', '__import__("x")',
    'import importlib\nimportlib.import_module("x")', 'def broken('])
def test_unsupported_python_dependencies_require_explicit_plan(tmp_path, content):
    h = Harness(tmp_path)
    seed(h, {'src/app.py': content})
    with pytest.raises(BuilderBoundaryError):
        plan(h, specification(['src/app.py']))
    assert not h.runner.requests


def test_symlinks_unknown_scope_absent_sources_and_aggregate_limits_never_dispatch(tmp_path):
    h = Harness(tmp_path)
    seed(h, {'src/app.py': 'x=1\n'})
    with pytest.raises(BuilderBoundaryError, match='source'):
        plan(h, specification(['src/missing.py']))
    with pytest.raises((BuilderBoundaryError, SourceContextError)):
        plan(h, specification(['tests/test_app.py']))
    (h.workspace / 'src/link.py').symlink_to(h.workspace / 'src/app.py')
    with pytest.raises(SourceContextError):
        plan(h, specification(['src/link.py']))
    files = {f'src/file{i}.py': '#' + 'a'*28000 for i in range(8)}
    seed(h, files)
    with pytest.raises(BuilderBoundaryError, match='aggregate'):
        plan(h, specification(files))
    assert not h.runner.requests


def test_context_and_original_call_budget_are_never_expanded(tmp_path):
    h = Harness(tmp_path)
    files = {'src/a.py': '#'+'a'*17000+'\n', 'src/b.py': 'import a\n#'+'b'*17000+'\n'}
    seed(h, files)
    with pytest.raises(BuilderBoundaryError, match='atomic'):
        plan(h, specification(files))
    files = {f'src/file{i}.py': 'x=1\n' for i in range(4)}
    seed(h, files)
    with pytest.raises(BuilderBoundaryError, match='total model-call'):
        plan(h, specification(files))
    assert len(plan(h, specification(files, size=2)).units) == 2


def test_automatic_runtime_seals_generated_plan_with_final_zip(tmp_path):
    h = Harness(tmp_path)
    seed(h, {'src/app.py': 'def main():\n    return 0\n'})
    result = plan(h, specification(['src/app.py'], rounds=3))
    delivered = h.runtime(work_units=result.units, automatic_plan=result,
        unit_verifiers={result.units[0].unit_id: h.verifier}).run()
    assert delivered.execution.status == 'verified'
    data = h.artifacts.read_bytes(h.authority().context, repository_id=h.repo, artifact_id=delivered.artifact.artifact_id)
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        manifest = json.loads(archive.read('builder-result.json'))
    assert manifest['schema_version'] == 'foundry.builder-delivery.v3'
    assert manifest['automatic_plan'] == json.loads(json.dumps(result.evidence()))
    assert len(h.runner.requests) == 2


def test_strict_auto_profile_rejects_missing_checks_bad_aliases_and_booleans():
    valid = {'schemaVersion': 'foundry.builder-auto-plan.v1', 'sourcePaths': ['src/app.py'],
        'fileChecks': {'src/app.py': ['python-check']}, 'maxFilesPerUnit': 1,
        'maxRoundsPerUnit': 2, 'moduleAliases': {}}
    assert AutoPlanSpecification.from_payload(valid).source_paths == ('src/app.py',)
    for bad in ({'extra': 1}, {'fileChecks': {}}, {'maxFilesPerUnit': True},
        {'moduleAliases': {'@/': '../'}}, {'moduleAliases': {'../': 'src/'}}):
        with pytest.raises((BuilderBoundaryError, SourceContextError)):
            AutoPlanSpecification.from_payload({**valid, **bad})


def test_python_relative_namespace_and_package_initializers_are_context(tmp_path):
    h = Harness(tmp_path)
    h.task = replace(h.task, max_rounds=6)
    files = {'src/pkg/__init__.py': 'NAME="pkg"\n', 'src/pkg/base.py': 'x=1\n',
        'src/pkg/app.py': 'from .base import x\nfrom . import base\n'}
    seed(h, files)
    result = plan(h, specification(files))
    assert dict(result.dependencies)['src/pkg/app.py'] == ('src/pkg/__init__.py', 'src/pkg/base.py')


def test_typescript_import_assignment_uses_the_nested_source_field(tmp_path):
    h = Harness(tmp_path)
    files = {'src/app.ts': 'import x = require("./base");', 'src/base.ts': 'export const x=1;'}
    seed(h, files)
    assert dict(plan(h, specification(files)).dependencies)['src/app.ts'] == ('src/base.ts',)
