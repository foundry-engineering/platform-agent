"""Long local calls require an equally bounded, explicitly signed live authority."""
from __future__ import annotations

from datetime import timedelta

import pytest

from agent_protocol.work_authority import validate_work_authority_at, verify_work_authority_signatures
from foundry_runner.core_work_binding import VerifiedCoreWorkBinding, CoreWorkBindingDenied
from platform_agent.artifact_worker_runtime import build_core_artifact_worker
from platform_agent.core_work_authority_issuer import ArtifactWorkPolicy, CoreWorkAuthorityIssuer
from test_core_work_authority_issuer import Harness, NOW


@pytest.mark.parametrize('local,lifetime,valid', [
    (False, 120, True), (False, 121, False), (True, 330, True), (True, 600, True),
    (True, 601, False), (True, True, False), ('yes', 330, False),
])
def test_authority_lifetime_requires_explicit_local_policy(local, lifetime, valid):
    if not valid:
        with pytest.raises(ValueError):
            ArtifactWorkPolicy('pol_cpu-local.v1', 'a' * 64, 'AT',
                lifetime_seconds=lifetime, local_cpu_execution=local)
        return
    policy = ArtifactWorkPolicy('pol_cpu-local.v1', 'a' * 64, 'AT',
        lifetime_seconds=lifetime, local_cpu_execution=local)
    assert policy.lifetime_seconds == lifetime


def test_signed_local_authority_survives_old_deadline_and_expires_at_new_bound(monkeypatch):
    import json
    h = Harness(monkeypatch)
    h.issuer = CoreWorkAuthorityIssuer(client=h.transport.client, admissions=h.admissions,
        policy=ArtifactWorkPolicy('pol_cpu-local.v1', 'a' * 64, 'AT',
            lifetime_seconds=330, local_cpu_execution=True), clock=lambda: h.current)
    document = h.issue()
    assert document['budget']['max_wall_seconds'] == 330
    assert document['budget']['max_cost_microusd'] == h.binding.provider_budget_microusd
    assert document['budget']['max_model_calls'] == 1
    assert verify_work_authority_signatures(document, {h.signer.kid: h.signer.public_key}) == (h.signer.kid,)
    validate_work_authority_at(document, now=NOW + timedelta(seconds=125))
    binding = VerifiedCoreWorkBinding(document['authority_id'], document['agent_id'],
        h.binding.authority_id, h.binding.agent_id, h.binding.execution_job_id, json.dumps(document))
    binding.require_current(NOW + timedelta(seconds=329))
    with pytest.raises(CoreWorkBindingDenied):
        binding.require_current(NOW + timedelta(seconds=330))


def test_extended_authority_cannot_be_composed_with_remote_provider(monkeypatch):
    from test_core_execution_authorizer import Harness as WorkerHarness
    from pathlib import Path
    import tempfile
    from foundry_runner.network_egress import EgressPolicy

    with tempfile.TemporaryDirectory() as temporary:
        h = WorkerHarness(Path(temporary), monkeypatch)
        policy = ArtifactWorkPolicy('pol_cpu-local.v1', 'a' * 64, 'AT',
            lifetime_seconds=330, local_cpu_execution=True)
        with pytest.raises(ValueError, match='explicit local provider'):
            build_core_artifact_worker(binding=h.config, core_origin='https://core.example.test',
                core_token_supplier=lambda: 'test-token', admissions=h.admissions, package=h.package,
                artifact_bytes=h.bytes, policy=policy, signers=[h.signer],
                state_path=Path(temporary) / 'runtime.sqlite', connection_factory=lambda: None,
                license_id='license_test', provider=h.provider,
                upload_egress_policy=EgressPolicy(frozenset({'storage.example.test'})))


def test_extended_local_work_cannot_create_its_own_budget_session(tmp_path, monkeypatch):
    from test_core_execution_authorizer import Harness as WorkerHarness
    from foundry_runner.execution_provider import LocalExecutionProvider
    from foundry_runner.network_egress import EgressPolicy

    h = WorkerHarness(tmp_path, monkeypatch)
    provider = LocalExecutionProvider(endpoint='http://127.0.0.1:8010',
        token_supplier=lambda: 'test-token', timeout_seconds=300)
    with pytest.raises(ValueError, match='approved Builder budget session'):
        build_core_artifact_worker(binding=h.config, core_origin='https://core.example.test',
            core_token_supplier=lambda: 'test-token', admissions=h.admissions, package=h.package,
            artifact_bytes=h.bytes, policy=ArtifactWorkPolicy('pol_cpu-local.v1', 'a' * 64, 'AT',
                lifetime_seconds=330, local_cpu_execution=True), signers=[h.signer],
            state_path=tmp_path / 'runtime.sqlite', connection_factory=lambda: None,
            license_id='license_test', provider=provider,
            upload_egress_policy=EgressPolicy(frozenset({'storage.example.test'})))
