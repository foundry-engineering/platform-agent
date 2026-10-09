from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

import platform_agent.skill_admission as admission_module
from platform_agent.skill_admission import SQLiteSkillAdmissionStore
from platform_agent.skill_admission_service import GovernedSkillAdmissionService
from platform_agent.tenant_control import SQLiteTenantControlStore, TenantNotActiveError


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


def _package(contract_sha: str) -> tuple[dict[str, object], dict[str, bytes]]:
    artifact = b"package-bytes-v1"
    sbom = b'{"bom":"test"}\n'
    provenance = b'{"source":"test-only"}\n'
    evidence = b"verification-evidence\n"
    package: dict[str, object] = {
        "schema_version": "skill-package.v1",
        "package_id": "skp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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


def _patch_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admission_module, "validate_skill_package_against_contract", lambda *_: None)
    monkeypatch.setattr(
        admission_module,
        "verify_skill_package_signatures",
        lambda *_: ("kid_test.fixture",),
    )
    monkeypatch.setattr(admission_module, "verify_skill_package_artifact", lambda *_: None)
    monkeypatch.setattr(
        admission_module,
        "derive_skill_package_id",
        lambda *_: "skp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )


def test_service_derives_live_context_and_blocks_suspended_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_protocol(monkeypatch)
    tenant_store = SQLiteTenantControlStore(tmp_path / "tenant.db")
    tenant_store.create_tenant("tnt_fixture0001", keyset_id="keyset_fixture.v1")
    tenant_store.create_project("tnt_fixture0001", "prj_fixture0001")
    admission_store = SQLiteSkillAdmissionStore(tmp_path / "skill.db")
    service = GovernedSkillAdmissionService(
        tenant_store=tenant_store,
        admission_store=admission_store,
    )

    contract = _contract()
    package, payloads = _package(admission_module.canonical_sha256(contract))
    verification = package["verification"]
    assert isinstance(verification, dict)
    refs = verification["evidence_refs"]
    assert isinstance(refs, list) and isinstance(refs[0], str)

    record = service.admit(
        tenant_id="tnt_fixture0001",
        project_id="prj_fixture0001",
        role_id="bookkeeper",
        package=package,
        skill_contract=contract,
        trusted_signing_keys={"kid_test.fixture": b"k" * 32},
        artifact_bytes=payloads["artifact"],
        sbom_bytes=payloads["sbom"],
        provenance_bytes=payloads["provenance"],
        verification_evidence={refs[0]: payloads["evidence"]},
        reason="approved for project",
        now=datetime(2026, 9, 16, 10, 0, tzinfo=UTC),
    )
    assert service.resolve(
        tenant_id="tnt_fixture0001",
        project_id="prj_fixture0001",
        role_id="bookkeeper",
        skill_id="finance.reconcile",
        package_id=record.package_id,
    ) == record

    tenant_store.set_project_status(
        "tnt_fixture0001",
        "prj_fixture0001",
        "suspended",
        reason="security hold",
    )
    with pytest.raises(TenantNotActiveError):
        service.resolve(
            tenant_id="tnt_fixture0001",
            project_id="prj_fixture0001",
            role_id="bookkeeper",
            skill_id="finance.reconcile",
        )
