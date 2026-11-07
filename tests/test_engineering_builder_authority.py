"""Actual Ed25519 issuance and canonical DOP authorization; no authority doubles."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from agent_protocol.execution_grant import ExecutionGrantSignatureError
from agent_protocol.workspace_binding import verify_workspace_binding_signatures
from agent_protocol.authority_witness import verify_authority_witness_signatures
from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.execution_gate import ExecutionAuthorizationError, execute_authorized_dop

from platform_agent.runtime_authority import RuntimeAuthorityError, AuthorityWitnessSigner
from platform_agent.tenant_authority import WorkspaceBindingSigner
from builder_runtime_fixture import Harness


def test_real_signed_issuer_authorizes_and_executes_actual_dop(tmp_path):
    h = Harness(tmp_path)
    issuer = h.authority()
    plan = h.plan()
    admitted = issuer.issue(h.task, plan)
    assert verify_workspace_binding_signatures(admitted.workspace_binding,
        admitted.trusted_workspace_keys) == ("kid_builder-workspace.v1",)
    assert verify_authority_witness_signatures(admitted.authority_witness,
        admitted.trusted_witness_keys) == ("kid_builder-witness.v1",)
    receipt = execute_authorized_dop(plan, admitted.grant, admitted.workspace_binding,
        admitted.authority_witness, workspace=h.workspace,
        repository_id=h.task.repository_id, workspace_base_commit_sha=h.task.workspace_base_commit_sha,
        trusted_grant_keys=admitted.trusted_grant_keys,
        trusted_workspace_keys=admitted.trusted_workspace_keys,
        trusted_witness_keys=admitted.trusted_witness_keys, trusted_now=admitted.trusted_now)
    assert receipt["dop_result"]["status"] == "applied"
    assert "return 42" in (h.workspace / "src/app.py").read_text()
    assert h.tenants.snapshot(h.task.tenant_id, h.task.project_id, h.repo).usage.active_runs == 1


@pytest.mark.parametrize("change", ["tenant", "project", "cell", "task", "repository"])
def test_foreign_builder_task_is_rejected_before_signing(tmp_path, change):
    h = Harness(tmp_path)
    field = {"tenant": "tenant_id", "project": "project_id", "cell": "cell_id",
             "task": "task_id", "repository": "repository_id"}[change]
    value = "foreign/repository" if change == "repository" else "foreign_scope"
    with pytest.raises(BuilderBoundaryError):
        h.authority(task=replace(h.task, **{field: value}))


def test_changed_budget_goal_or_workspace_cannot_reuse_bound_issuer(tmp_path):
    h = Harness(tmp_path)
    issuer = h.authority()
    for change in ({"goal": "different task"}, {"model_budget_microusd": 100},
                   {"workspace_id": "wsp_foreign"}, {"workspace_base_commit_sha": "b" * 40}):
        with pytest.raises(BuilderBoundaryError, match="task changed"):
            issuer.issue(replace(h.task, **change), h.plan())


@pytest.mark.parametrize("revoke", ["epoch", "reservation", "keyset", "project"])
def test_live_revocation_prevents_new_builder_authority(tmp_path, revoke):
    h = Harness(tmp_path)
    issuer = h.authority()
    if revoke == "epoch":
        h.tenants.bump_authority_epoch(h.task.tenant_id, reason="test revocation")
    elif revoke == "reservation":
        h.tenants.release_run(h.reservation.reservation_id)
    elif revoke == "keyset":
        h.tenants.rotate_keyset(h.task.tenant_id, keyset_id="keyset_new.v1", reason="test rotation")
    else:
        h.tenants.set_project_status(h.task.tenant_id, h.task.project_id, "suspended", reason="test suspension")
    with pytest.raises((RuntimeError, ValueError)):
        issuer.issue(h.task, h.plan())


def test_untrusted_execution_grant_key_cannot_issue_workspace_or_witness(tmp_path):
    h = Harness(tmp_path)
    with pytest.raises(ExecutionGrantSignatureError):
        h.authority(trusted_grant_keys={"kid_other.v1": b"x" * 32})


def test_mutating_caller_owned_grant_cannot_widen_bound_authority(tmp_path):
    h = Harness(tmp_path)
    issuer = h.authority()
    h.grant["write_paths"] = ["."]
    admitted = issuer.issue(h.task, h.plan())
    assert admitted.grant["write_paths"] == ["src"]


def test_candidate_policy_or_write_scope_cannot_be_laundered(tmp_path):
    h = Harness(tmp_path)
    issuer = h.authority()
    plan = h.plan()
    plan["policy_ref"]["policy_sha256"] = "b" * 64
    from engineering_agent.dop_executor import _derive_dop_id
    plan["dop_id"] = _derive_dop_id(plan)
    with pytest.raises(ExecutionAuthorizationError):
        issuer.issue(h.task, plan)


def test_revocation_inside_external_signer_callback_stops_issuance(tmp_path):
    h = Harness(tmp_path)
    def sign(message):
        h.tenants.bump_authority_epoch(h.task.tenant_id, reason="test in-flight revoke")
        return h.workspace_key.sign(message)
    issuer = h.authority(workspace_signers=(WorkspaceBindingSigner("kid_workspace.v1",
        h.workspace_key.public_key().public_bytes_raw(), sign),))
    with pytest.raises(RuntimeAuthorityError):
        issuer.issue(h.task, h.plan())


def test_slow_signing_cannot_return_expired_authority(tmp_path):
    h = Harness(tmp_path)
    now = datetime.now(UTC)
    calls = 0
    def clock():
        nonlocal calls
        calls += 1
        return now if calls == 1 else now + timedelta(seconds=61)
    with pytest.raises(ExecutionAuthorizationError):
        h.authority(clock=clock).issue(h.task, h.plan())


def test_duplicate_witness_signers_are_rejected(tmp_path):
    h = Harness(tmp_path)
    from platform_agent.runtime_authority import AuthorityWitnessSignerSet
    signer = AuthorityWitnessSigner("kid_duplicate.v1", h.witness_key.public_key().public_bytes_raw(), h.witness_key.sign)
    with pytest.raises(ValueError):
        h.authority(witness_signers=AuthorityWitnessSignerSet(h.admission.tenant_context.keyset_id, (signer, signer)))
