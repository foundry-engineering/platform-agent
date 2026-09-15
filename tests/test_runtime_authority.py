from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

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
GRANT_ID = "sgr_" + "b" * 32
BINDING_ID = "wsb_" + "c" * 32
RESERVATION = RunReservation(
    reservation_id="rsv_" + "d" * 32,
    tenant_id=TENANT.tenant_id,
    project_id=TENANT.project_id,
    run_key="dsp_" + "e" * 32,
)
NOW = datetime(2026, 9, 15, 20, 30, tzinfo=UTC)


def _grant(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "execution-grant.v1",
        "grant_id": GRANT_ID,
        "tenant_context": TENANT.as_dict(),
        "repo": REPO,
        "signatures": [{"kid": "kid_grant.v1"}],
    }
    value.update(overrides)
    return value


def _binding(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "workspace-binding.v1",
        "binding_id": BINDING_ID,
        "tenant_context": TENANT.as_dict(),
        "repository_id": REPO,
    }
    value.update(overrides)
    return value


def _admission(grant: dict[str, object] | None = None):
    actual = grant or _grant()
    return SimpleNamespace(
        tenant_context=TENANT,
        reservation=RESERVATION,
        signed_grants=(actual,),
    )


def _snapshot(context: TenantContext = TENANT) -> TenantExecutionSnapshot:
    body: dict[str, object] = {
        "context": context.as_dict(),
        "repository_id": REPO,
        "tenant_status": "active",
        "project_status": "active",
    }
    return TenantExecutionSnapshot(
        context=context,
        repository_id=REPO,
        tenant_status="active",
        project_status="active",
        quotas=TenantQuotaLimits(),
        usage=TenantQuotaUsage(active_runs=1, artifact_bytes=0),
        snapshot_sha256=runtime._sha256(body),
    )


class FakeState:
    def __init__(self, *, context: TenantContext = TENANT, reservation_active: bool = True) -> None:
        self.context = context
        self.reservation_active = reservation_active

    def snapshot(self, tenant_id: str, project_id: str, repository_id: str):
        assert tenant_id == TENANT.tenant_id
        assert project_id == TENANT.project_id
        assert repository_id == REPO
        return _snapshot(self.context)

    def reservation_is_active(self, reservation: RunReservation) -> bool:
        assert reservation == RESERVATION
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


def test_live_reserved_authority_issues_signed_witness(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    document = issue_authority_witness(
        _admission(),
        grant=_grant(),
        workspace_binding=_binding(),
        repository_id=REPO,
        authority_state=FakeState(),
        signer_set=_signers(),
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )
    assert document["witness_id"] == "taw_" + "f" * 32
    assert document["reservation_id"] == RESERVATION.reservation_id
    assert document["execution_grant_id"] == GRANT_ID


def test_revoked_epoch_blocks_witness_issuance(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    revoked = TenantContext(
        tenant_id=TENANT.tenant_id,
        project_id=TENANT.project_id,
        cell_id=TENANT.cell_id,
        authority_epoch=2,
        keyset_id=TENANT.keyset_id,
    )
    with pytest.raises(RuntimeAuthorityError, match="authority changed"):
        issue_authority_witness(
            _admission(),
            grant=_grant(),
            workspace_binding=_binding(),
            repository_id=REPO,
            authority_state=FakeState(context=revoked),
            signer_set=_signers(),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
        )


def test_released_reservation_blocks_witness_issuance(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    with pytest.raises(RuntimeAuthorityError, match="reservation is no longer active"):
        issue_authority_witness(
            _admission(),
            grant=_grant(),
            workspace_binding=_binding(),
            repository_id=REPO,
            authority_state=FakeState(reservation_active=False),
            signer_set=_signers(),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
        )


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
