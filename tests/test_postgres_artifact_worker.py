"""Native PostgreSQL acceptance; explicit isolated database required."""
from __future__ import annotations

import os
import re
import hashlib
import json
from threading import Thread
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

if os.environ.get("FOUNDRY_PLATFORM_PG_TEST") != "1":
    pytest.skip("native PostgreSQL acceptance is explicitly enabled in CI", allow_module_level=True)

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from foundry_runner.economic_gate import EconomicAccessDenied, EconomicGate
from foundry_runner.postgres_economic_store import PostgresEconomicReservationStore
from foundry_runner.execution_provider import HttpExecutionProvider, LocalExecutionProvider
from foundry_runner.http_transport import HttpResponse
from foundry_runner.network_egress import EgressPolicy
from platform_agent.artifact_worker_runtime import build_core_artifact_worker
from platform_agent.core_execution_authorizer import CoreExecutionAuthorizationError
from platform_agent.core_work_authority_issuer import ArtifactWorkPolicy
from platform_agent.postgres_artifact_budget import ArtifactBudgetRegistrationError, PostgresArtifactBudgetRegistrar
from test_core_execution_authorizer import Harness
from worker_counterparties import Counterparties
from public_quality import CASE_IDS
from public_repairs import REPAIR_IDS


@pytest.fixture
def database():
    dsn = os.environ["FOUNDRY_PLATFORM_TEST_DATABASE_URL"]
    name = conninfo_to_dict(dsn).get("dbname", "")
    if not re.search(r"(^|[-_])(test|ci)([-_]|$)", name, re.IGNORECASE):
        raise RuntimeError("explicit isolated test/ci database required")
    schema = "platform_worker_" + uuid4().hex
    def connect():
        return psycopg.connect(dsn, connect_timeout=5,
            options=f"-c search_path={schema},pg_catalog -c statement_timeout=10000 -c lock_timeout=5000")
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            root = Path(os.environ["FOUNDRY_RUNNER_SOURCE_ROOT"])
            with connect() as db:
                db.execute((root / "docs/postgres-economic-store-v1.sql").read_text())
                db.execute((root / "docs/postgres-paid-concurrency-lease-v1.sql").read_text())
                db.execute((root / "docs/postgres-waw-replay-store-v1.sql").read_text())
                db.execute((root / "docs/postgres-spend-reconciliation-v1.sql").read_text())
                db.execute((root / "docs/postgres-economic-breach-v1.sql").read_text())
            yield connect
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def prepare(h, connect):
    # The operator grants roots. The issuer must neither invent nor enlarge them.
    h.now = datetime.now(UTC).replace(microsecond=0)
    with connect() as db:
        for kind, identity in (("platform", "platform"), ("tenant", h.config.tenant_id),
                               ("license", "license_worker-acceptance"), ("agent", h.config.canonical_agent_id)):
            db.execute("INSERT INTO foundry_budget_scope(scope_type,scope_id,max_total_cost_microusd,"
                "max_paid_invocations,max_input_tokens,max_output_tokens,effective_from,expires_at) "
                "VALUES(%s,%s,1000000,10,1000000,1000000,%s,%s)",
                (kind, identity, h.now - timedelta(hours=1), h.now + timedelta(hours=1)))
    h.registrar = PostgresArtifactBudgetRegistrar(connection_factory=connect, tenant_id=h.config.tenant_id,
        license_id="license_worker-acceptance", agent_id=h.config.canonical_agent_id)
    h.authorizer = h.reopen()


def authorize(h):
    admitted = h.authorizer.admit(h.job)
    return h.authorizer.authorize(h.job, admitted=admitted, request=h.request(admitted))


def test_concrete_issuer_registers_and_consumes_all_six_durable_budgets(database, tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    prepare(h, database)
    result = authorize(h)
    gate = EconomicGate(reservation_store=PostgresEconomicReservationStore(connection_factory=database))
    args = dict(envelope=result.cost_envelope, tenant_context=result.witness["tenant_context"],
        run_id=result.witness["run_id"], task_id=result.witness["task_id"], agent_id=result.witness["agent_id"],
        reservation=result.reservation, now=h.now, operation=lambda: "admitted")
    assert gate.invoke(**args) == "admitted"
    with pytest.raises(EconomicAccessDenied):
        gate.invoke(**args)
    with database() as db:
        rows = db.execute("SELECT scope_type,reserved_total_microusd,reserved_paid_invocations "
                          "FROM foundry_budget_scope ORDER BY scope_type").fetchall()
        assert len(rows) == 6 and all(row[1:] == (500000, 1) for row in rows)


def test_missing_operator_budget_fails_without_creating_leaf_authority(database, tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    prepare(h, database)
    with database() as db:
        db.execute("DELETE FROM foundry_budget_scope WHERE scope_type='license'")
    with pytest.raises(CoreExecutionAuthorizationError, match="authorization failed closed"):
        authorize(h)
    with database() as db:
        assert db.execute("SELECT count(*) FROM foundry_budget_scope WHERE scope_type IN ('run','task')").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM foundry_cost_envelope_state").fetchone() == (0,)
    assert len(h.calls) == 2


def test_conflicting_leaf_rolls_back_without_resetting_prior_consumption(database, tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    prepare(h, database)
    result = authorize(h)
    envelope = result.cost_envelope
    with database() as db:
        db.execute("UPDATE foundry_budget_scope SET reserved_paid_invocations=1 WHERE scope_type='run'")
        db.execute("UPDATE foundry_budget_scope SET max_total_cost_microusd=1 WHERE scope_type='task'")
    with pytest.raises(ArtifactBudgetRegistrationError):
        h.registrar.register(envelope)
    with database() as db:
        assert db.execute("SELECT reserved_paid_invocations FROM foundry_budget_scope WHERE scope_type='run'").fetchone() == (1,)
        assert db.execute("SELECT max_total_cost_microusd FROM foundry_budget_scope WHERE scope_type='task'").fetchone() == (1,)


def test_actual_worker_composes_signed_issuers_postgres_gates_settlement_and_private_candidate(database, tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    prepare(h, database)
    peers = Counterparties(h)
    monkeypatch.setattr("foundry_runner.control_plane_http.urlopen", peers.core)
    provider = HttpExecutionProvider(endpoint="https://provider.example.test", token_supplier=lambda: "provider-fixture-secret",
        egress_policy=EgressPolicy(frozenset({"provider.example.test"})), transport=peers)
    worker = build_core_artifact_worker(
        binding=h.config, core_origin="https://core.example.test", core_token_supplier=lambda: "service-fixture-secret",
        admissions=h.admissions, package=h.package, artifact_bytes=h.bytes,
        policy=ArtifactWorkPolicy("pol_worker-acceptance.v1", "a" * 64, "AT"), signers=[h.signer],
        state_path=tmp_path / "runtime.db", connection_factory=database, license_id="license_worker-acceptance",
        provider=provider, upload_egress_policy=EgressPolicy(frozenset({"storage.example.test"})),
        upload_transport=peers, clock=lambda: h.now,
    )
    assert worker.run_once()
    assert len(peers.provider_calls) == len(peers.uploads) == 1
    assert [e["kind"] for e in peers.events if "kind" in e] == ["reservation", "usage", "settlement"]
    assert peers.events[-1]["outcome"] == "completed"
    assert h.admissions.verify_event_chain(h.config.tenant_id)
    with database() as db:
        assert db.execute("SELECT count(*) FROM foundry_waw_invocation_claim").fetchone() == (1,)
        assert db.execute("SELECT actual_total_microusd FROM foundry_spend_settlement").fetchone() == (100000,)
        assert db.execute("SELECT reserved_total_microusd FROM foundry_cost_envelope_state").fetchone() == (500000,)


def test_worker_reaches_production_engineering_http_handler_and_accounts_for_its_dop(database, tmp_path, monkeypatch):
    # The upstream completion remains an explicit fixture. The actual model
    # handler, bounded TCP transport, worker, signatures and PostgreSQL are real.
    from engineering_agent.model_http_server import ModelHttpServer
    from engineering_agent.selfhosted_model import ModelSettings, RealCodingModelService, model_http_handler

    h = Harness(tmp_path, monkeypatch)
    prepare(h, database)
    class Storage(Counterparties):
        def request(self, request, *, timeout_seconds, max_response_bytes, checkpoint):
            checkpoint()
            assert request.get_method() == "PUT"
            self.content = request.data
            self.sha256 = hashlib.sha256(self.content).hexdigest()
            plan = json.loads(self.content)
            assert plan["schema_version"] == "dop.v1" and plan["operations"][0]["content"]["data"] == "VALUE = 42\n"
            self.uploads.append(request)
            return HttpResponse(200, b"")
    peers = Storage(h)
    monkeypatch.setattr("foundry_runner.control_plane_http.urlopen", peers.core)
    class Upstream:
        calls = 0
        def complete(self, *, endpoint, token, payload, timeout_seconds):
            self.calls += 1
            assert endpoint == "http://127.0.0.1:8000/v1/chat/completions"
            return {"model": payload["model"], "choices": [{"finish_reason": "stop", "message": {
                "role": "assistant", "content": json.dumps({"files": [{"path": "src/app.py", "content": "VALUE = 42\n"}]})}}],
                "usage": {"prompt_tokens": 64, "completion_tokens": 24, "total_tokens": 88}}
    upstream = Upstream()
    secret = "runner_fixture_" + "a" * 40
    settings = ModelSettings(model_id="isolated-model-interface-fixture", upstream_url="http://127.0.0.1:8000/v1/chat/completions",
        upstream_api_key="upstream_fixture_" + "b" * 40, runner_api_key=secret, policy_sha256="a" * 64,
        journal_path=tmp_path / "inference-journal.db", price_input_per_million_microusd=100000,
        price_output_per_million_microusd=100000, max_output_tokens=h.config.max_output_tokens)
    server = ModelHttpServer(("127.0.0.1", 0), model_http_handler(RealCodingModelService(settings, inference=upstream)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        provider = LocalExecutionProvider(endpoint=f"http://127.0.0.1:{server.server_address[1]}", token_supplier=lambda: secret)
        worker = build_core_artifact_worker(
            binding=h.config, core_origin="https://core.example.test", core_token_supplier=lambda: "service-fixture-secret",
            admissions=h.admissions, package=h.package, artifact_bytes=h.bytes,
            policy=ArtifactWorkPolicy("pol_worker-acceptance.v1", "a" * 64, "AT"), signers=[h.signer],
            state_path=tmp_path / "runtime-model.db", connection_factory=database, license_id="license_worker-acceptance",
            provider=provider, upload_egress_policy=EgressPolicy(frozenset({"storage.example.test"})),
            upload_transport=peers, clock=lambda: h.now,
        )
        assert worker.run_once()
        assert upstream.calls == len(peers.uploads) == 1
        assert peers.events[-1]["outcome"] == "completed"
        with database() as db:
            row = db.execute("SELECT provider_id,actual_total_microusd,input_tokens,output_tokens FROM foundry_spend_settlement").fetchone()
            assert row == ("foundry-selfhosted", 10, 64, 24)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.fixture
def live_coding_runtime(tmp_path, request):
    from live_coding_model import live_model

    if os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.fail("live model acceptance requires the real Docker verifier")
    output_limit = 512 if request.node.callspec.params.get("sandbox") in {"live_units", "live_auto", "live_polyglot"} else 192
    from engineering_agent.model_host import DEFAULT_PROFILE
    profile = DEFAULT_PROFILE
    if request.node.callspec.params.get("sandbox") == "live_context":
        from source_context_acceptance import context_model_profile
        profile = context_model_profile()
    with live_model(tmp_path / "llama", Path(os.environ["FOUNDRY_BUILDER_MODEL_ASSETS"]),
                    max_output_tokens=output_limit, approved_profile=profile) as runtime:
        yield runtime


@pytest.fixture(scope="module")
def quality_coding_runtime(tmp_path_factory):
    from live_coding_model import live_model
    from public_quality import report
    if os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.fail("public quality requires actual isolated runtime execution")
    from dataclasses import replace
    from engineering_agent.model_host import DEFAULT_PROFILE
    from engineering_agent.model_profiles import load_model_profile
    profile_path = os.environ.get("FOUNDRY_QUALITY_MODEL_PROFILE")
    profile = replace(load_model_profile(Path(profile_path)) if profile_path else DEFAULT_PROFILE,
        max_output_tokens=512)
    receipts, repair_receipts = [], []
    directory = tmp_path_factory.mktemp("public-quality")
    with live_model(directory / "llama", Path(os.environ["FOUNDRY_BUILDER_MODEL_ASSETS"]),
                    max_output_tokens=512, approved_profile=profile) as runtime:
        try:
            yield runtime, receipts, profile, repair_receipts
        finally:
            result = report(receipts)
            from public_repairs import report as repair_report
            result["repairEvaluation"] = repair_report(repair_receipts)
            print("PUBLIC_QUALITY_REPORT=" + json.dumps(result, sort_keys=True))
            if os.environ.get("FOUNDRY_QUALITY_REPORT"):
                target = Path(os.environ["FOUNDRY_QUALITY_REPORT"])
                with target.open("x", encoding="utf-8") as file:
                    target.chmod(0o600)
                    json.dump(result, file, sort_keys=True, indent=2)
            if os.environ.get("FOUNDRY_REQUIRE_AGENT_REPAIR_GATE") == "1":
                assert result["repairEvaluation"]["complete"] and result["repairEvaluation"]["regressionGatePassed"], (
                    "Agent quality gate requires all four recorded errors to be independently repaired"
                )


@pytest.mark.parametrize("sandbox", ["unit", "docker", "project", "live", "live_units", "live_auto", "live_polyglot", "live_context", *CASE_IDS, *REPAIR_IDS])
def test_core_builder_runs_metered_model_and_final_scanned_zip(database, tmp_path, monkeypatch, sandbox, request):
    """Signed Builder with actual persistence and optional real model and Docker."""
    import io
    import zipfile
    from dataclasses import replace
    from agent_protocol.execution_grant import derive_execution_grant_id
    from engineering_agent.model_http_server import ModelHttpServer
    from engineering_agent.selfhosted_model import ModelSettings, RealCodingModelService, model_http_handler
    from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile
    from foundry_runner.control_plane_http import ControlPlaneHttpClient
    from platform_agent.artifact_store import ContentAddressedArtifactStore
    from platform_agent.core_builder_runtime import CoreBuilderConfiguration, CoreBuilderWorker
    from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
    from builder_runtime_fixture import Harness as CodeHarness, IMAGE
    quality = sandbox in CASE_IDS
    repair = sandbox in REPAIR_IDS
    evaluating = quality or repair
    if (evaluating or sandbox in {"live", "live_units", "live_auto", "live_polyglot", "live_context"}) and not os.environ.get("FOUNDRY_BUILDER_MODEL_ASSETS"):
        pytest.skip("live model weights are explicitly configured in acceptance")
    if sandbox in {"docker", "project"} and os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.skip("actual Docker execution is mandatory in native integration")
    live = evaluating or sandbox in {"live", "live_units", "live_auto", "live_polyglot", "live_context"}
    live_units = sandbox in {"live_units", "live_auto"}
    auto = sandbox == "live_auto"
    polyglot = sandbox == "live_polyglot"
    larger_context = sandbox == "live_context"
    automatic_plan = None
    project = sandbox == "project"
    from work_unit_fixture import FILES, PARTS, PATHS, UNITS, assigned_unit, verifiers as project_verifiers
    h = Harness(tmp_path, monkeypatch)
    quality_receipts, quality_profile, quality_runtime, repair_receipts = None, None, None, None
    if evaluating:
        quality_runtime, quality_receipts, quality_profile, repair_receipts = request.getfixturevalue("quality_coding_runtime")
    if live:
        h.config = replace(h.config, max_input_tokens=4096, max_output_tokens=512 if live_units or polyglot or evaluating else 192)
        if evaluating:
            h.config = replace(h.config, max_input_tokens=quality_profile.max_input_tokens)
    elif project:
        h.config = replace(h.config, max_input_tokens=4096, max_output_tokens=3072)
    prepare(h, database)
    from polyglot_acceptance import POLYGLOT_OBJECTIVE
    objective = (
        POLYGLOT_OBJECTIVE
        if polyglot else
        "Repair the tenant billing code according to the current approved work-unit data. "
        "Return exactly its outputPaths, never read-only dependency files. "
        "Preserve signatures, exact integer arithmetic and tenant identity. "
        "For pricing multiply price by quantity, and for invoices preserve the supplied tenant. "
        "Produce minimal code without comments or docstrings."
        if live_units else
        "Repair src/app.py. Keep the typed total_cents(lines) signature. "
        "Return the sum of price TIMES quantity for each pair. Empty input totals 0. "
        "Use one return statement, no comments or docstrings."
        if live else "Build a tenant-isolated application in approved work units"
        if project else "Build a function returning 42"
    )
    if larger_context:
        from source_context_acceptance import OBJECTIVE
        objective = OBJECTIVE
        h.config = replace(h.config, max_input_tokens=3072)
    quality_case = None
    if repair:
        from public_repairs import selected, goal as repair_goal
        quality_case = selected(sandbox)
        objective = repair_goal(quality_case)
    elif quality:
        from public_quality import CASES, goal
        quality_case = next(case for case in CASES if case["case_id"] == sandbox)
        objective = goal(quality_case)
    h.job = replace(h.job, objective=objective, id=h.job.id + "-" + sandbox if evaluating else h.job.id)
    if evaluating:
        h.transport.document["executionJobId"] = h.job.id
    code_root = tmp_path / "builder"
    code_root.mkdir(mode=0o700)
    code = CodeHarness(code_root)
    code.tenants = h.tenants
    h.tenants.bind_repository(h.config.tenant_id, h.config.project_id, code.repo)
    snapshot = h.tenants.snapshot(h.config.tenant_id, h.config.project_id, code.repo)
    code.task = replace(code.task, tenant_id=h.config.tenant_id, project_id=h.config.project_id,
        cell_id=snapshot.context.cell_id,
        goal=h.job.objective, model_budget_microusd=h.job.provider_budget_microusd,
        max_rounds=3 if repair else 1 if quality else 4 if live_units else code.task.max_rounds)
    grant = {key: value for key, value in code.grant.items() if key != "signatures"}
    grant["tenant_context"] = snapshot.context.as_dict()
    grant["agent_id"] = h.config.canonical_agent_id
    grant["policy_ref"] = {**grant["policy_ref"], "policy_sha256": "a" * 64}
    if project:
        grant["read_paths"], grant["write_paths"] = list(PATHS), list(PATHS)
    if larger_context:
        grant["read_paths"] = ["src/app.py", "src/reference.py"]
        grant["write_paths"] = ["src/app.py"]
    grant["grant_id"] = derive_execution_grant_id(grant)
    code.grant = sign_execution_grant(grant, signers=(ExecutionGrantSigner("kid_builder-grant.v1",
        code.grant_key.public_key().public_bytes_raw(), code.grant_key.sign),))
    reservation = h.tenants.reserve_run(h.config.tenant_id, h.config.project_id, code.repo,
        run_key=code.admission.dispatch.dispatch_id)
    code.admission = replace(code.admission, tenant_context=snapshot.context,
        reservation=reservation, tenant_snapshot_sha256=snapshot.snapshot_sha256,
        signed_grants=(code.grant,))
    code.artifacts = ContentAddressedArtifactStore(code_root / "tenant-artifacts", h.tenants)
    class Peers(Counterparties):
        def __init__(self, h):
            super().__init__(h)
            self.objects = {}
        def core(self, request, *, timeout):
            if request.full_url.endswith('/outputs'):
                from worker_counterparties import Response
                body = json.loads(request.data)
                identity = 'output_builder_' + str(len(self.objects) + 1)
                self.current = identity
                self.objects[identity] = {**body}
                return Response({'objectId': identity, 'objectKey': 'private/' + identity,
                    'uploadUrl': 'https://storage.example.test/private/' + identity, 'headers': {}})
            if '/outputs/' in request.full_url:
                from worker_counterparties import Response
                identity = request.full_url.rsplit('/', 1)[1]
                return Response({'objectId': identity, 'contentRef': 'object:private/' + identity,
                    'sha256': self.objects[identity]['sha256'], 'status': 'available', 'scanStatus': 'clean',
                    'scanRef': 'scan:' + identity} if request.get_method() == 'GET' else {'status': 'quarantined'})
            return super().core(request, timeout=timeout)
        def request(self, request, *, timeout_seconds, max_response_bytes, checkpoint):
            checkpoint()
            assert request.get_method() == 'PUT'
            assert hashlib.sha256(request.data).hexdigest() == self.objects[self.current]['sha256']
            self.objects[self.current]['content'] = request.data
            self.uploads.append(request)
            return HttpResponse(200, b'')
    peers = Peers(h)
    monkeypatch.setattr('foundry_runner.control_plane_http.urlopen', peers.core)
    class InferenceFixture:
        calls = 0
        def complete(self, *, endpoint, token, payload, timeout_seconds):
            self.calls += 1
            prompt = payload['messages'][1]['content']
            context = json.loads(prompt.split('Task data (JSON):\n')[1])
            if project:
                unit_id = assigned_unit(context['verificationFeedback'])
                files = [{"path": path, "content": content} for path, content in PARTS[unit_id].items()]
                assert len(files) == 8 and len(context['sourceContext']) <= 16
            else:
                source = context['sourceContext'][0]
                file = {'path': source['path'], 'content': 'def main():\n    return ' + ('0' if self.calls == 1 else '42') + '\n'}
                if source['sha256'] is not None:
                    file['expectedSha256'] = source['sha256']
                    assert context['verificationFeedback']
                files = [file]
            return {'model': payload['model'], 'choices': [{'finish_reason': 'stop',
                'message': {'content': json.dumps({'files': files})}}],
                'usage': {'prompt_tokens': 64, 'completion_tokens': 24, 'total_tokens': 88}}
    inference = InferenceFixture()
    secret = 'builder_runner_' + 'r' * 40
    server, thread = None, None
    if live:
        from live_coding_model import MODEL_ID

        if evaluating:
            provider_origin, secret = quality_runtime
        else:
            provider_origin, secret = request.getfixturevalue("live_coding_runtime")
        model_id = MODEL_ID
        if larger_context:
            from source_context_acceptance import context_model_profile, reject_excess_tokens, report_model_errors
            context_profile = context_model_profile()
            model_id = context_profile.model_id
            reject_excess_tokens(provider_origin, secret, tmp_path / "llama/state/inference.sqlite3")
            report_model_errors(monkeypatch, provider_origin)
    else:
        model_id = "core-builder-inference-fixture"
        settings = ModelSettings(model_id=model_id, upstream_url="http://127.0.0.1:8000/v1/chat/completions",
            upstream_api_key="builder_upstream_" + "u" * 40, runner_api_key=secret, policy_sha256='a' * 64,
            journal_path=tmp_path / 'core-builder-inference.db', price_input_per_million_microusd=100000,
            price_output_per_million_microusd=100000, max_output_tokens=h.config.max_output_tokens)
        service = RealCodingModelService(settings, inference=inference)
        server = ModelHttpServer(('127.0.0.1', 0), model_http_handler(service))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        provider_origin = f"http://127.0.0.1:{server.server_address[1]}"
    control = ControlPlaneHttpClient(base_url='https://core.example.test', tenant_id=h.config.tenant_id,
        workspace_id=h.config.workspace_id, token_supplier=lambda: 'service-fixture-secret',
        project_id=h.config.project_id, agent_id=h.config.core_agent_id, work_node_id=h.job.work_node_id)
    model_contexts = []
    def factory(context, tag, ceiling, envelope):
        if context:
            model_contexts.append(context)
        from agent_protocol.schema import canonical_sha256
        invocation = 'inv_' + canonical_sha256([envelope['run_id'], tag])[:32]
        provider = LocalExecutionProvider(endpoint=provider_origin, token_supplier=lambda: secret,
            timeout_seconds=120, model_context=context or None, model_invocation_id=invocation if tag != 'delivery' else None,
            provider_budget_ceiling_microusd=ceiling)
        return build_core_artifact_worker(binding=h.config, core_origin='https://core.example.test',
            core_token_supplier=lambda: 'service-fixture-secret', admissions=h.admissions, package=h.package,
            artifact_bytes=h.bytes, policy=ArtifactWorkPolicy('pol_worker-acceptance.v1', 'a' * 64, 'AT', max_model_calls=code.task.max_rounds),
            signers=[h.signer], state_path=tmp_path / 'core-builder-state.db', connection_factory=database,
            license_id='license_worker-acceptance', provider=provider, upload_egress_policy=EgressPolicy(frozenset({'storage.example.test'})),
            upload_transport=peers, clock=lambda: h.now, control=control, session_envelope=envelope,
            task_id=code.task.task_id, invocation_tag=tag, reservation_ceiling_microusd=ceiling)
    tests = code.workspace / 'tests'
    tests.mkdir(mode=0o755)
    source = code.workspace / "src/app.py"
    if live:
        source.parent.mkdir(mode=0o755)
        source.write_text(
            "def total_cents(lines: list[tuple[int, int]]) -> int:\n"
            "    return sum(price + quantity for price, quantity in lines)\n"
        )
        original = source.read_bytes()
        (tests / "test_app.py").write_text(
            """import sys
import unittest
sys.path.insert(0, "/workspace/src")
from app import total_cents

class OrderTotals(unittest.TestCase):
    def test_quantity_weighted_sum(self):
        self.assertEqual(total_cents([(145, 3), (80, 2), (500, 0)]), 595)
        self.assertEqual(total_cents([(85, 1)]), 85)
        self.assertEqual(total_cents([(1000, 0)]), 0)

    def test_exact_integer_arithmetic(self):
        self.assertEqual(total_cents([(10**30, 13)]), 13 * 10**30)
        self.assertEqual(total_cents([]), 0)
"""
        )
    else:
        (tests / 'test_app.py').write_text("import sys,unittest\nsys.path.insert(0,'/workspace/src')\nfrom app import main\nclass App(unittest.TestCase):\n def test_main(self): self.assertEqual(main(),42)\n")
    evidence = tmp_path / 'core-builder-docker-evidence'
    evidence.mkdir(mode=0o700)
    verifier = DockerSandboxVerifier(workspace=code.workspace, evidence_dir=evidence,
        profile=TrustedSandboxProfile(image=IMAGE, checks=(TrustedCheck('python-unittest',
            ('/usr/local/bin/python','-B','-m','unittest','discover','-s','/workspace/tests')),),
            diagnostic_bytes=384 if larger_context else 0))
    live_paths, live_work_units = (), ()
    if live_units:
        import http.client
        from platform_agent.builder_work_units import BuilderWorkUnit

        original_response = http.client.HTTPConnection.getresponse
        def diagnostic_response(connection):
            response = original_response(connection)
            if not 200 <= response.status < 300:
                body = response.read(4096).decode("utf-8", errors="replace")
                raise AssertionError(f"isolated model response HTTP {response.status}: {body}")
            return response
        monkeypatch.setattr(http.client.HTTPConnection, "getresponse", diagnostic_response)

        source = code.workspace / "src/orders.py"
        (code.workspace / "src/app.py").unlink()
        source.parent.mkdir(mode=0o755, exist_ok=True)
        (code.workspace / "src/pricing.py").write_text(
            "def total_cents(lines):\n    return sum(price + quantity for price, quantity in lines)\n")
        source.write_text("from pricing import total_cents\ndef invoice(tenant, lines):\n"
            "    return {'tenant': 'shared', 'amount': total_cents(lines)}\n")
        original = source.read_bytes()
        (tests / "test_app.py").unlink()
        (tests / "test_pricing.py").write_text(
            "import sys,unittest\nsys.path.insert(0,'/workspace/src')\nfrom pricing import total_cents\n"
            "class Pricing(unittest.TestCase):\n def test_amount(self):\n"
            "  self.assertEqual(total_cents([(145,3),(80,2),(500,0)]),595)\n"
            "  self.assertEqual(total_cents([]),0)\n"
            "  self.assertEqual(total_cents([(10**30,13)]),13*10**30)\n")
        (tests / "test_orders.py").write_text(
            "import sys,unittest\nsys.path.insert(0,'/workspace/src')\nfrom orders import invoice\n"
            "class Invoices(unittest.TestCase):\n def test_tenant(self):\n"
            "  self.assertEqual(invoice('tenant-a',[(145,3),(80,2)]),{'tenant':'tenant-a','amount':595})\n"
            "  self.assertEqual(invoice('tenant-b',[]),{'tenant':'tenant-b','amount':0})\n")
        live_paths = ("src/orders.py", "src/pricing.py")
        live_work_units = (
            BuilderWorkUnit("pricing", "Repair ONLY src/pricing.py; multiply price by quantity",
                ("src/pricing.py",), ("src/pricing.py",), (), 2, ("pricing-check",)),
            BuilderWorkUnit("invoices", "Repair ONLY src/orders.py; preserve the supplied tenant and use total_cents",
                live_paths, ("src/orders.py",), ("pricing",), 2, ("invoices-check",)),
        )
        if auto:
            from platform_agent.builder_auto_plan import AutoPlanSpecification, compile_automatic_plan
            automatic_plan = compile_automatic_plan(authority=code.authority(), workspace=code.workspace,
                specification=AutoPlanSpecification(live_paths,
                    (("src/orders.py", ("invoices-check",)), ("src/pricing.py", ("pricing-check",))), 1, 2))
            live_work_units = automatic_plan.units
            assert [unit.output_paths for unit in live_work_units] == [("src/pricing.py",), ("src/orders.py",)]
            assert live_work_units[1].dependencies == (live_work_units[0].unit_id,)
        checks = tuple(TrustedCheck(check_id, ("/usr/local/bin/python", "-B", "-m", "unittest",
            "discover", "-s", "/workspace/tests", "-p", pattern))
            for check_id, pattern in (("pricing-check", "test_pricing.py"), ("invoices-check", "test_orders.py")))
        verifier = DockerSandboxVerifier(workspace=code.workspace, evidence_dir=evidence,
            profile=TrustedSandboxProfile(image=IMAGE, checks=checks))
        live_verifiers = {unit.unit_id: DockerSandboxVerifier(workspace=code.workspace, evidence_dir=evidence,
            profile=TrustedSandboxProfile(image=IMAGE,
                checks=tuple(check for check in checks if check.check_id in unit.check_ids)))
            for unit in live_work_units}
    if larger_context:
        from platform_agent.builder_work_units import BuilderWorkUnit
        from source_context_acceptance import configure, context_verifier
        reference_bytes = configure(code.workspace)
        verifier = context_verifier(code.workspace, evidence, IMAGE)
        original = source.read_bytes()
        live_paths = ("src/app.py", "src/reference.py")
        live_work_units = (BuilderWorkUnit("reference-adapter", objective, live_paths,
            ("src/app.py",), (), code.task.max_rounds, ("reference-results", "python-unittest")),)
        live_verifiers = {"reference-adapter": verifier}
    if polyglot:
        from engineering_agent.sandbox_matrix import DockerSandboxMatrixVerifier
        from polyglot_acceptance import configure_polyglot, report_model_errors
        report_model_errors(monkeypatch)
        live_paths, matrix = configure_polyglot(code.workspace, IMAGE)
        verifier = DockerSandboxMatrixVerifier(workspace=code.workspace, evidence_dir=evidence, matrix=matrix)
    if evaluating:
        if repair:
            from public_repairs import configure_repair
            verifier = configure_repair(quality_case, code.workspace, evidence, code_root / "oracles", IMAGE)
        else:
            from public_quality import configure
            verifier = configure(quality_case, code.workspace, evidence, code_root / "oracles", IMAGE)
        live_paths = (quality_case["source_path"],)
    if sandbox == 'unit':
        verifier = code.verifier
    unit_verifiers = live_verifiers if live_units or larger_context else None
    if project:
        verifier, unit_verifiers = project_verifiers(code.workspace, evidence, docker=True)
    try:
        if live and not evaluating:
            baseline = verifier.verify(code.task, round_number=1)
            assert not baseline.passed and baseline.evidence_refs
        worker = CoreBuilderWorker(control=control,
            configuration=CoreBuilderConfiguration(code.task, h.config, h.job.work_node_id,
                PATHS if project else live_paths if live_units or polyglot or evaluating or larger_context else ('src/app.py',), code.workspace, code.state,
                work_units=UNITS if project else live_work_units, automatic_plan=automatic_plan, diagnose_first=polyglot or repair),
            authority_factory=lambda check: code.authority(execution_checkpoint=check), worker_factory=factory,
            verifier=verifier, artifacts=code.artifacts,
            tenant_context=lambda: h.admissions.current_context(h.config.tenant_id,h.config.project_id),
            skill_id=h.package['skill_id'], skill_contract_sha256=h.package['skill_contract_sha256'],
            clock=lambda: h.now, unit_verifiers=unit_verifiers)
        if repair:
            from public_repairs import observe as observe_repair
            receipt = observe_repair(worker, case=quality_case, code=code, peers=peers, database=database,
                model_contexts=model_contexts, inference=inference, evidence=evidence, model_profile=quality_profile)
            repair_receipts.append(receipt)
            print("PUBLIC_REPAIR_CASE=" + json.dumps(receipt.case_id) + ":" + receipt.outcome)
            return
        if quality:
            from public_quality import observe
            receipt = observe(worker, case=quality_case, code=code, peers=peers, database=database,
                model_contexts=model_contexts, inference=inference, evidence=evidence, model_profile=quality_profile)
            quality_receipts.append(receipt)
            print("PUBLIC_QUALITY_CASE=" + json.dumps(receipt.case_id) + ":" + receipt.outcome)
            return
        try:
            assert worker.run_once()
        except Exception:
            if larger_context:
                from source_context_acceptance import failure_diagnostics
                diagnostics = failure_diagnostics(code.workspace, evidence)
                diagnostics["modelFeedback"] = [context["verificationFeedback"] for context in model_contexts]
                print("SOURCE_CONTEXT_FAILURE=" + json.dumps(diagnostics, sort_keys=True))
            raise
        assert len([x for x in peers.events if x.get('type') == 'artifact']) == 1
        assert peers.events[-1]['outcome'] == 'completed'
        with zipfile.ZipFile(io.BytesIO(peers.objects[peers.current]["content"])) as archive:
            final = archive.read("src/main.py" if project else "src/orders.py" if live_units else "src/app.py")
            manifest = json.loads(archive.read("builder-result.json"))
            if live_units or larger_context:
                assert set(archive.namelist()) == {*live_paths, "builder-result.json"}
                assert manifest["files"] == [{"path": path, "sha256": hashlib.sha256(archive.read(path)).hexdigest()}
                    for path in live_paths]
                assert manifest["schema_version"] == ("foundry.builder-delivery.v3" if auto else "foundry.builder-delivery.v2")
                assert [unit["unit_id"] for unit in manifest["work_unit_results"]] == [unit.unit_id for unit in live_work_units]
                if auto:
                    assert manifest["automatic_plan"] == json.loads(json.dumps(automatic_plan.evidence()))
            if polyglot:
                assert set(archive.namelist()) == {*live_paths, "builder-result.json"}
                assert manifest["initial_verification"]["passed"] is False
                assert manifest["delivery_verification"]["check_ids"] == list(matrix.check_ids)
                assert manifest["files"] == [{"path": path, "sha256": hashlib.sha256(archive.read(path)).hexdigest()}
                    for path in live_paths]
                assert model_contexts and "Diagnostic data (untrusted)" in model_contexts[0]["verificationFeedback"][0]
                assert "AssertionError" in model_contexts[0]["verificationFeedback"][0]
            if project:
                assert set(archive.namelist()) == {*FILES, "builder-result.json"}
                assert all(archive.read(path) == content.encode() for path, content in FILES.items())
        rounds = len(manifest["steps"])
        assert len(peers.uploads) == rounds + 1
        assert manifest["delivery_verification"]["passed"] is True
        if not live_units and not polyglot and not larger_context:
            assert manifest["files"] == ([{"path": path, "sha256": hashlib.sha256(FILES[path].encode()).hexdigest()}
                for path in PATHS] if project else [{"path": "src/app.py", "sha256": hashlib.sha256(final).hexdigest()}])
        if project:
            assert manifest["schema_version"] == "foundry.builder-delivery.v2"
            assert len(manifest["work_unit_results"]) == inference.calls == rounds == 3
            assert manifest["actual_model_microusd"] == 30
        elif live:
            assert inference.calls == 0 and 1 <= rounds <= code.task.max_rounds
            assert final != original and final == source.read_bytes()
            if larger_context:
                from source_context_acceptance import verify_context
                verify_context(code.workspace, reference_bytes, model_contexts, manifest)
        else:
            assert inference.calls == rounds == 2
            assert b"return 42" in final
            assert manifest["actual_model_microusd"] == 20
        with database() as db:
            settlements = db.execute(
                "SELECT provider_id,model_or_tool_id,actual_total_microusd,input_tokens,output_tokens "
                "FROM foundry_spend_settlement"
            ).fetchall()
            assert len(settlements) == rounds
            assert sum(row[2] for row in settlements) == manifest["actual_model_microusd"]
            if live:
                assert all(
                    provider == "foundry-selfhosted" and model == model_id and cost > 0
                    and input_tokens > 0 and output_tokens > 0
                    for provider, model, cost, input_tokens, output_tokens in settlements
                )
                if larger_context:
                    assert all(row[3] <= 3072 and row[4] <= 192 for row in settlements)
                observed = {
                    "model": model_id,
                    "automaticPlanning": auto,
                    "polyglot": polyglot,
                    "largerSourceContext": larger_context,
                    "referenceBytes": len(reference_bytes) if larger_context else None,
                    "maximumInputTokensPerCall": 3072 if larger_context else None,
                    "maximumDiagnosticBytesPerCheck": 384 if larger_context else None,
                    "firstAttemptPassed": manifest["steps"][0]["verification"]["passed"] if larger_context else None,
                    "verificationCheckIds": manifest["delivery_verification"]["check_ids"] if larger_context else None,
                    "publicCounterexampleFeedbackUsed": any("Public counterexample:" in feedback
                        for context in model_contexts for feedback in context["verificationFeedback"]) if larger_context else None,
                    "referenceSha256": hashlib.sha256(reference_bytes).hexdigest() if larger_context else None,
                    "languages": ["Python", "JavaScript", "Go"] if polyglot else ["Python"],
                    "planSha256": automatic_plan.evidence()["plan_sha256"] if auto else None,
                    "rounds": rounds,
                    "inputTokens": sum(row[3] for row in settlements),
                    "outputTokens": sum(row[4] for row in settlements),
                    "sourceSha256": hashlib.sha256(final).hexdigest(),
                    "verifiedDelivery": manifest["delivery_verification"]["evidence_refs"],
                }
                print(json.dumps(observed, sort_keys=True))
                if larger_context and os.environ.get("FOUNDRY_CONTEXT_REPORT"):
                    from engineering_agent.model_host import RUNTIME
                    observed.update(schemaVersion="foundry.actual-source-context.v1",
                        profile=replace(context_profile, max_output_tokens=192).identity(),
                        runtimeSha256=RUNTIME.sha256, excessTokensRejectedBeforeClaim=True,
                        referenceUnchanged=True, privateCandidateVerified=True,
                        enterpriseReleaseApproved=False, marketRankClaim=False)
                    print("SOURCE_CONTEXT_REPORT=" + json.dumps(observed, sort_keys=True))
                    target = Path(os.environ["FOUNDRY_CONTEXT_REPORT"])
                    with target.open("x", encoding="utf-8") as report_file:
                        target.chmod(0o600)
                        json.dump(observed, report_file, sort_keys=True, indent=2)
            assert db.execute('SELECT count(*) FROM foundry_waw_invocation_claim').fetchone() == (rounds,)
            assert db.execute("SELECT reserved_paid_invocations FROM foundry_budget_scope WHERE scope_type='task'").fetchone() == (rounds,)
    finally:
        if server is not None and thread is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            assert not thread.is_alive()
