from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

import platform_agent.skill_admission as admission_module
from platform_agent.skill_admission import (
    SQLiteSkillAdmissionStore,
    SkillAdmissionConflictError,
    SkillAdmissionError,
    SkillAdmissionRevokedError,
)
from platform_agent.tenant_control import TenantContext


def _ref(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _contract() -> dict[str, object]:
    return {
        "schema_version": "foundry.skill-manifest.v2",
        "skill_id": "finance.reconcile",
        "version": "1.0.0",
        "authority_class": "work-authority",
        "implementation_policy": {
            "binding": "runtime-skill-pack",
            "version_binding": "exact",
            "missing_implementation": "deny",
        },
    }


def _package(contract_sha: str, package_id: str = "skp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") -> tuple[dict[str, object], dict[str, bytes]]:
    artifact = b"package-bytes-v1"
    sbom = b'{"bom":"test"}\n'
    provenance = b'{"source":"test-only"}\n'
    evidence = b"verification-evidence\n"
    package: dict[str, object] = {
        "schema_version": "skill-package.v1",
        "package_id": package_id,
        "skill_id": "finance.reconcile",
        "skill_version": "1.0.0",
        "skill_contract_sha256": contract_sha,
        "runtime_api_version": "foundry.skill-runtime.v1",
        "authority_class": "work-authority",
        "source": {
            "repository_id": "foundry-engineering/skill-finance",
            "commit_sha": "a" * 40,
            "subpath": "skills/finance/reconcile",
        },
        "artifact": {
            "digest": _ref(artifact),
            "media_type": "application/octet-stream",
            "size_bytes": len(artifact),
            "sbom_ref": _ref(sbom),
            "provenance_ref": _ref(provenance),
        },
        "required_capabilities": ["finance.read"],
        "resource_types": ["business-record"],
        "verification": {
            "profile_id": "foundry.finance.v1",
            "result": "passed",
            "evaluator_ids": ["evaluator_test.fixture"],
            "evidence_refs": [_ref(evidence)],
            "verified_at": "2026-09-16T09:59:00Z",
        },
        "signatures": [
            {
                "kid": "kid_test.fixture",
                "alg": "ed25519",
                "signed_sha256": "0" * 64,
                "sig_b64": "A" * 86 + "==",
            }
        ],
    }
    return package, {
        "artifact": artifact,
        "sbom": sbom,
        "provenance": provenance,
        "evidence": evidence,
    }


def _context(cell_id: str = "cell_0123456789abcdef") -> TenantContext:
    return TenantContext(
        tenant_id="tnt_fixture0001",
        project_id="prj_fixture0001",
        cell_id=cell_id,
        authority_epoch=7,
        keyset_id="keyset_fixture.v1",
    )


def _patch_protocol(monkeypatch: pytest.MonkeyPatch, expected_package_id: str) -> None:
    monkeypatch.setattr(admission_module, "validate_skill_package_against_contract", lambda *_: None)
    monkeypatch.setattr(
        admission_module,
        "verify_skill_package_signatures",
        lambda *_: ("kid_test.fixture",),
    )
    monkeypatch.setattr(admission_module, "verify_skill_package_artifact", lambda *_: None)
    monkeypatch.setattr(admission_module, "derive_skill_package_id", lambda *_: expected_package_id)


def _admit(
    store: SQLiteSkillAdmissionStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    package_id: str = "skp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    now: datetime | None = None,
    replace_active: bool = False,
):
    contract = _contract()
    contract_sha = admission_module.canonical_sha256(contract)
    package, payloads = _package(contract_sha, package_id)
    _patch_protocol(monkeypatch, package_id)
    verification = package["verification"]
    assert isinstance(verification, dict)
    evidence_refs = verification["evidence_refs"]
    assert isinstance(evidence_refs, list)
    evidence_ref = evidence_refs[0]
    assert isinstance(evidence_ref, str)
    return store.admit(
        context=_context(),
        role_id="bookkeeper",
        package=package,
        skill_contract=contract,
        trusted_signing_keys={"kid_test.fixture": b"k" * 32},
        artifact_bytes=payloads["artifact"],
        sbom_bytes=payloads["sbom"],
        provenance_bytes=payloads["provenance"],
        verification_evidence={evidence_ref: payloads["evidence"]},
        reason="test admission",
        now=now or datetime(2026, 9, 16, 10, 0, tzinfo=UTC),
        replace_active=replace_active,
    )


def test_admit_resolve_and_idempotency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    first = _admit(store, monkeypatch)
    second = _admit(store, monkeypatch)

    assert first == second
    resolved = store.resolve(
        context=_context(),
        role_id="bookkeeper",
        skill_id="finance.reconcile",
        package_id=first.package_id,
    )
    assert resolved == first
    assert store.verify_event_chain(first.tenant_id)


def test_different_package_requires_explicit_rollout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    first = _admit(store, monkeypatch)

    with pytest.raises(SkillAdmissionConflictError):
        _admit(
            store,
            monkeypatch,
            package_id="skp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )

    replacement = _admit(
        store,
        monkeypatch,
        package_id="skp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        replace_active=True,
    )
    assert replacement.package_id != first.package_id
    with pytest.raises(SkillAdmissionRevokedError):
        store.resolve(
            context=_context(),
            role_id="bookkeeper",
            skill_id="finance.reconcile",
            package_id=first.package_id,
        )
    assert store.verify_event_chain(first.tenant_id)


def test_revocation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    record = _admit(store, monkeypatch)
    store.revoke(record.admission_id, reason="verification superseded")

    with pytest.raises(SkillAdmissionRevokedError):
        store.resolve(
            context=_context(),
            role_id="bookkeeper",
            skill_id="finance.reconcile",
        )
    assert store.verify_event_chain(record.tenant_id)


def test_isolation_cell_rebinding_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    _admit(store, monkeypatch)

    with pytest.raises(SkillAdmissionRevokedError):
        store.resolve(
            context=_context("cell_ffffffffffffffff"),
            role_id="bookkeeper",
            skill_id="finance.reconcile",
        )


def test_stale_verification_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    with pytest.raises(SkillAdmissionError, match="stale"):
        _admit(
            store,
            monkeypatch,
            now=datetime(2026, 10, 17, 10, 0, tzinfo=UTC),
        )


def test_event_chain_detects_tampering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteSkillAdmissionStore(tmp_path / "skill-admission.db")
    record = _admit(store, monkeypatch)

    import sqlite3

    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE skill_admission_events SET reason='tampered' WHERE tenant_id=?",
            (record.tenant_id,),
        )
    with pytest.raises(SkillAdmissionError, match="hash mismatch"):
        store.verify_event_chain(record.tenant_id)
