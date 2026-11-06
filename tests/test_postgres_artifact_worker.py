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
