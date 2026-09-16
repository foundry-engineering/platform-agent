from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import platform_agent.runtime_authority as runtime
from platform_agent.runtime_authority import (
    AuthorityWitnessSigner,
    AuthorityWitnessSignerSet,
    RuntimeAuthorityError,
    issue_authority_witness,
)
from platform_agent.tenant_control import (
    RunReservation,
    TenantContext,
    TenantExecutionSnapshot,
    TenantQuotaLimits,
    TenantQuotaUsage,
)

TENANT = TenantContext(
    tenant_id="tnt_fixture0001",
    project_id="prj_fixture0001",
    cell_id="cell_" + "a" * 32,
    authority_epoch=1,
    keyset_id="keyset_fixture.v1",
)
REPO = "foundry-engineering/example"
REPO_TWO = "foundry-engineering/second"
DISPATCH_ID = "dsp_" + "e" * 32
GRANT_ID = "sgr_" + "b" * 32
GRANT_TWO_ID = "sgr_" + "2" * 32
TASK_ID = "tsk_" + "1" * 32
TASK_TWO_ID = "tsk_" + "2" * 32
BINDING_ID = "wsb_" + "c" * 32
NOW = datetime(2026, 9, 15, 20, 30, tzinfo=UTC)


def _sha(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _repo_hash(repositories: tuple[str, ...]) -> str:
    return _sha(
        {
            "schema_version": "foundry.run-repository-set.v1",
            "repository_ids": list(repositories),
        }
    )


def _reservation(repositories: tuple[str, ...]) -> RunReservation:
    canonical = tuple(sorted(repositories))
    return RunReservation(
        reservation_id="rsv_" + "d" * 32,
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        run_key=DISPATCH_ID,
        repository_ids=canonical,
        repository_set_sha256=_repo_hash(canonical),
    )


def _grant(
    *,
    grant_id: str = GRANT_ID,
    task_id: str = TASK_ID,
    repo: str = REPO,
    context: TenantContext = TENANT,
    dispatch_id: str = DISPATCH_ID,
) -> dict[str, object]:
    return {
        "schema_version": "execution-grant.v1",
        "grant_id": grant_id,
        "authority": {"dispatch_id": dispatch_id},
        "task_id": task_id,
        "tenant_context": context.as_dict(),
        "repo": repo,
        "signatures": [{"kid": "kid_grant.v1"}],
    }


def _binding(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "workspace-binding.v1",
        "binding_id": BINDING_ID,
        "tenant_context": TENANT.as_dict(),
        "repository_id": REPO,
    }
    value.update(overrides)
    return value


def _dispatch(task_ids: tuple[str, ...]):
    return SimpleNamespace(
        dispatch_id=DISPATCH_ID,
        assignments=tuple(SimpleNamespace(task_id=task_id) for task_id in task_ids),
    )


def _admission(
    grants: tuple[dict[str, object], ...] | None = None,
    *,
    reservation: RunReservation | None = None,
):
    actual = grants or (_grant(),)
    repositories = tuple(sorted({str(item["repo"]) for item in actual}))
    return SimpleNamespace(
        tenant_context=TENANT,
        reservation=reservation or _reservation(repositories),
        signed_grants=actual,
        dispatch=_dispatch(tuple(str(item["task_id"]) for item in actual)),
    )


def _snapshot(repository_id: str, context: TenantContext = TENANT) -> TenantExecutionSnapshot:
    body: dict[str, object] = {
        "context": context.as_dict(),
        "repository_id": repository_id,
        "tenant_status": "active",
        "project_status": "active",
    }
    return TenantExecutionSnapshot(
        context=context,
        repository_id=repository_id,
        tenant_status="active",
        project_status="active",
        quotas=TenantQuotaLimits(),
        usage=TenantQuotaUsage(active_runs=1, artifact_bytes=0),
        snapshot_sha256=_sha(body),
    )


class FakeState:
    def __init__(
        self,
        *,
        contexts: dict[str, TenantContext] | None = None,
        reservation_active: bool = True,
    ) -> None:
        self.contexts = contexts or {REPO: TENANT, REPO_TWO: TENANT}
        self.reservation_active = reservation_active
        self.snapshots_requested: list[str] = []

    def snapshot(self, tenant_id: str, project_id: str, repository_id: str):
        assert tenant_id == TENANT.tenant_id
        assert project_id == TENANT.project_id
        self.snapshots_requested.append(repository_id)
        if repository_id not in self.contexts:
            raise RuntimeAuthorityError("repository is no longer bound")
        return _snapshot(repository_id, self.contexts[repository_id])

    def reservation_is_active(self, reservation: RunReservation) -> bool:
        return self.reservation_active


def _install_protocol(
    monkeypatch: pytest.MonkeyPatch,
    *,
    verify_error: Exception | None = None,
) -> None:
    def derive(value: object) -> str:
        return "taw_" + "f" * 32

    def verify(value: object, keys: object) -> tuple[str, ...]:
        if verify_error is not None:
            raise verify_error
        assert isinstance(keys, dict)
        return tuple(sorted(keys))

    monkeypatch.setattr(
        runtime.importlib,
        "import_module",
        lambda name: SimpleNamespace(
            derive_authority_witness_id=derive,
            authority_witness_signed_payload_sha256=lambda value: "1" * 64,
            authority_witness_signing_message=lambda value: b"witness-message",
            validate_authority_witness=lambda value: None,
            verify_authority_witness_signatures=verify,
        ),
    )


def _signers() -> AuthorityWitnessSignerSet:
    return AuthorityWitnessSignerSet(
        keyset_id=TENANT.keyset_id,
        signers=(
            AuthorityWitnessSigner(
                kid="kid_authority.v1",
                public_key=b"p" * 32,
                sign=lambda message: b"s" * 64,
            ),
        ),
    )


def _issue(monkeypatch: pytest.MonkeyPatch, admission=None, *, state=None):
    _install_protocol(monkeypatch)
    return issue_authority_witness(
        admission or _admission(),
        grant=_grant(),
        workspace_binding=_binding(),
        repository_id=REPO,
        authority_state=state or FakeState(),
        signer_set=_signers(),
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )


def test_live_reserved_authority_issues_signed_witness(monkeypatch: pytest.MonkeyPatch) -> None:
    document = _issue(monkeypatch)
    assert document["witness_id"] == "taw_" + "f" * 32
    assert document["reservation_id"] == "rsv_" + "d" * 32
    assert document["execution_grant_id"] == GRANT_ID


def test_all_repositories_in_admission_are_revalidated_before_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second = _grant(grant_id=GRANT_TWO_ID, task_id=TASK_TWO_ID, repo=REPO_TWO)
    state = FakeState()
    _issue(monkeypatch, _admission((_grant(), second)), state=state)
    assert state.snapshots_requested == [REPO, REPO_TWO]


def test_repository_set_reservation_must_exactly_match_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second = _grant(grant_id=GRANT_TWO_ID, task_id=TASK_TWO_ID, repo=REPO_TWO)
    admission = _admission((_grant(), second), reservation=_reservation((REPO,)))
    with pytest.raises(RuntimeAuthorityError, match="repository set differs"):
        _issue(monkeypatch, admission)


def test_repository_set_hash_must_be_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = RunReservation(
        reservation_id="rsv_" + "d" * 32,
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        run_key=DISPATCH_ID,
        repository_ids=(REPO,),
        repository_set_sha256="0" * 64,
    )
    with pytest.raises(RuntimeAuthorityError, match="repository-set hash"):
        _issue(monkeypatch, _admission(reservation=bad))


def test_stale_second_repository_blocks_first_repository_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second = _grant(grant_id=GRANT_TWO_ID, task_id=TASK_TWO_ID, repo=REPO_TWO)
    revoked = TenantContext(
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        cell_id=TENANT.cell_id,
        authority_epoch=2,
        keyset_id=TENANT.keyset_id,
    )
    state = FakeState(contexts={REPO: TENANT, REPO_TWO: revoked})
    with pytest.raises(RuntimeAuthorityError, match="admitted repository"):
        _issue(monkeypatch, _admission((_grant(), second)), state=state)


def test_reservation_must_be_bound_to_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    wrong = RunReservation(
        reservation_id="rsv_" + "d" * 32,
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        run_key="dsp_" + "9" * 32,
        repository_ids=(REPO,),
        repository_set_sha256=_repo_hash((REPO,)),
    )
    with pytest.raises(RuntimeAuthorityError, match="not bound to the admitted dispatch"):
        _issue(monkeypatch, _admission(reservation=wrong))


def test_grant_tasks_must_exactly_match_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    admission = _admission()
    admission.dispatch = _dispatch((TASK_ID, TASK_TWO_ID))
    with pytest.raises(RuntimeAuthorityError, match="do not exactly match"):
        _issue(monkeypatch, admission)


def test_revoked_epoch_blocks_witness_issuance(monkeypatch: pytest.MonkeyPatch) -> None:
    revoked = TenantContext(
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        cell_id=TENANT.cell_id,
        authority_epoch=2,
        keyset_id=TENANT.keyset_id,
    )
    with pytest.raises(RuntimeAuthorityError, match="authority changed"):
        _issue(monkeypatch, state=FakeState(contexts={REPO: revoked, REPO_TWO: revoked}))


def test_released_reservation_blocks_witness_issuance(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeAuthorityError, match="reservation is no longer active"):
        _issue(monkeypatch, state=FakeState(reservation_active=False))


def test_grant_not_in_admission_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    with pytest.raises(RuntimeAuthorityError, match="not exactly part"):
        issue_authority_witness(
            _admission(),
            grant=_grant(grant_id="sgr_" + "9" * 32),
            workspace_binding=_binding(),
            repository_id=REPO,
            authority_state=FakeState(),
            signer_set=_signers(),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
        )


def test_signer_response_is_cryptographically_reverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch, verify_error=ValueError("bad signature"))
    with pytest.raises(RuntimeAuthorityError, match="trust verification"):
        issue_authority_witness(
            _admission(),
            grant=_grant(),
            workspace_binding=_binding(),
            repository_id=REPO,
            authority_state=FakeState(),
            signer_set=_signers(),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
        )


def test_witness_lifetime_is_bounded_before_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    with pytest.raises(RuntimeAuthorityError, match="<= 120 seconds"):
        issue_authority_witness(
            _admission(),
            grant=_grant(),
            workspace_binding=_binding(),
            repository_id=REPO,
            authority_state=FakeState(),
            signer_set=_signers(),
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
