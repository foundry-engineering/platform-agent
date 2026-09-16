from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocol.schema import canonical_sha256
from agent_protocol.skill_activation import verify_skill_activation_signatures
from agent_protocol.skill_package import (
    derive_skill_package_id,
    skill_package_signed_payload_sha256,
)
from platform_agent.skill_activation_issuer import (
    SkillActivationIssuer,
    SkillActivationIssuerError,
    SkillActivationSigner,
)
from platform_agent.skill_admission import SkillAdmissionRecord
from platform_agent.tenant_control import TenantContext, TenantNotActiveError


class FakeAdmissions:
    def __init__(self, *, active: bool = True) -> None:
        self.active = active
        self.context = TenantContext(
            tenant_id="tnt_fixture0001",
            project_id="prj_fixture0001",
            cell_id="cell_0123456789abcdef",
            authority_epoch=7,
            keyset_id="keyset_fixture.v1",
        )
        self.record: SkillAdmissionRecord | None = None

    def current_context(self, tenant_id: str, project_id: str) -> TenantContext:
        if not self.active:
            raise TenantNotActiveError("tenant/project is not active")
        assert tenant_id == self.context.tenant_id
        assert project_id == self.context.project_id
        return self.context

    def resolve(
        self,
        *,
        tenant_id: str,
        project_id: str,
        role_id: str,
        skill_id: str,
        package_id: str | None = None,
    ) -> SkillAdmissionRecord:
        if not self.active:
            raise TenantNotActiveError("tenant/project is not active")
        assert tenant_id == self.context.tenant_id
        assert project_id == self.context.project_id
        assert role_id == "bookkeeper"
        assert skill_id == "finance.reconcile"
        assert self.record is not None
        if package_id is not None and package_id != self.record.package_id:
            raise RuntimeError("package mismatch")
        return self.record


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


def _package() -> dict[str, object]:
    contract_sha = canonical_sha256(_contract())
    document: dict[str, object] = {
        "schema_version": "skill-package.v1",
        "package_id": "skp_" + "0" * 32,
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
            "digest": "sha256:" + "1" * 64,
            "media_type": "application/octet-stream",
            "size_bytes": 128,
            "sbom_ref": "sha256:" + "2" * 64,
            "provenance_ref": "sha256:" + "3" * 64,
        },
        "required_capabilities": ["finance.read"],
        "resource_types": ["business-record"],
        "verification": {
            "profile_id": "skill-verification.finance.v1",
            "result": "passed",
            "evaluator_ids": ["evaluator_skill-tests.v1"],
            "evidence_refs": ["sha256:" + "4" * 64],
            "verified_at": "2026-09-16T10:10:00Z",
        },
    }
    document["package_id"] = derive_skill_package_id(document)
    payload_hash = skill_package_signed_payload_sha256(document)
    document["signatures"] = [
        {
            "kid": "kid_package-fixture.v1",
            "alg": "ed25519",
            "signed_sha256": payload_hash,
            "sig_b64": base64.b64encode(b"x" * 64).decode("ascii"),
        }
    ]
    return document


def _admission(package: dict[str, object]) -> SkillAdmissionRecord:
    artifact = package["artifact"]
    assert isinstance(artifact, dict)
    return SkillAdmissionRecord(
        admission_id="ska_" + "c" * 32,
        tenant_id="tnt_fixture0001",
        project_id="prj_fixture0001",
        cell_id="cell_0123456789abcdef",
        role_id="bookkeeper",
        skill_id="finance.reconcile",
        skill_version="1.0.0",
        package_id=str(package["package_id"]),
        skill_contract_sha256=str(package["skill_contract_sha256"]),
        artifact_digest=str(artifact["digest"]),
        source_repository_id="foundry-engineering/skill-finance",
        source_commit_sha="a" * 40,
        verified_signer_kids=("kid_package-fixture.v1",),
        admitted_at="2026-09-16T10:11:00Z",
        verification_verified_at="2026-09-16T10:10:00Z",
        status="active",
    )


def _signer() -> tuple[SkillActivationSigner, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return (
        SkillActivationSigner(
            kid="kid_activation-test.v1",
            public_key=public_key,
            sign=private_key.sign,
        ),
        public_key,
    )


def test_issue_real_signed_activation_for_exact_admitted_package() -> None:
    package = _package()
    admissions = FakeAdmissions()
    admissions.record = _admission(package)
    authority_checks: list[tuple[str, str, str, str]] = []

    def verify_authority(
        authority_class: str,
        authority_id: str,
        context: TenantContext,
        task_id: str,
        agent_id: str,
    ) -> None:
        assert context == admissions.context
        authority_checks.append((authority_class, authority_id, task_id, agent_id))

    signer, public_key = _signer()
    issuer = SkillActivationIssuer(
        admissions=admissions,  # type: ignore[arg-type]
        verify_authority_binding=verify_authority,
    )
    activation = issuer.issue(
        tenant_id="tnt_fixture0001",
        project_id="prj_fixture0001",
        role_id="bookkeeper",
        skill_id="finance.reconcile",
        package_id=str(package["package_id"]),
        package=package,
        run_id="run_" + "b" * 32,
        task_id="tsk_" + "a" * 32,
        agent_id="agent_finance.worker",
        authority_class="work-authority",
        authority_id="wka_" + "f" * 32,
        signers=[signer],
        now=datetime(2026, 9, 16, 10, 12, tzinfo=UTC),
    )

    assert activation["package_id"] == package["package_id"]
    assert activation["admission_id"] == admissions.record.admission_id
    assert authority_checks == [
        (
            "work-authority",
            "wka_" + "f" * 32,
            "tsk_" + "a" * 32,
            "agent_finance.worker",
        )
    ]
    assert verify_skill_activation_signatures(
        activation,
        {"kid_activation-test.v1": public_key},
    ) == ("kid_activation-test.v1",)


def test_different_package_binding_is_rejected() -> None:
    package = _package()
    admissions = FakeAdmissions()
    admissions.record = replace(_admission(package), artifact_digest="sha256:" + "9" * 64)
    signer, _ = _signer()
    issuer = SkillActivationIssuer(
        admissions=admissions,  # type: ignore[arg-type]
        verify_authority_binding=lambda *_: None,
    )

    with pytest.raises(SkillActivationIssuerError, match="active persisted admission"):
        issuer.issue(
            tenant_id="tnt_fixture0001",
            project_id="prj_fixture0001",
            role_id="bookkeeper",
            skill_id="finance.reconcile",
            package_id=str(package["package_id"]),
            package=package,
            run_id="run_" + "b" * 32,
            task_id="tsk_" + "a" * 32,
            agent_id="agent_finance.worker",
            authority_class="work-authority",
            authority_id="wka_" + "f" * 32,
            signers=[signer],
            now=datetime(2026, 9, 16, 10, 12, tzinfo=UTC),
        )


def test_bad_external_signer_output_fails_closed() -> None:
    package = _package()
    admissions = FakeAdmissions()
    admissions.record = _admission(package)
    issuer = SkillActivationIssuer(
        admissions=admissions,  # type: ignore[arg-type]
        verify_authority_binding=lambda *_: None,
    )
    bad_signer = SkillActivationSigner(
        kid="kid_activation-test.v1",
        public_key=b"p" * 32,
        sign=lambda _: b"not-a-signature",
    )

    with pytest.raises(SkillActivationIssuerError, match="64 Ed25519 bytes"):
        issuer.issue(
            tenant_id="tnt_fixture0001",
            project_id="prj_fixture0001",
            role_id="bookkeeper",
            skill_id="finance.reconcile",
            package_id=str(package["package_id"]),
            package=package,
            run_id="run_" + "b" * 32,
            task_id="tsk_" + "a" * 32,
            agent_id="agent_finance.worker",
            authority_class="work-authority",
            authority_id="wka_" + "f" * 32,
            signers=[bad_signer],
            now=datetime(2026, 9, 16, 10, 12, tzinfo=UTC),
        )


def test_inactive_tenant_or_project_cannot_receive_activation() -> None:
    package = _package()
    admissions = FakeAdmissions(active=False)
    admissions.record = _admission(package)
    signer, _ = _signer()
    issuer = SkillActivationIssuer(
        admissions=admissions,  # type: ignore[arg-type]
        verify_authority_binding=lambda *_: None,
    )

    with pytest.raises(TenantNotActiveError):
        issuer.issue(
            tenant_id="tnt_fixture0001",
            project_id="prj_fixture0001",
            role_id="bookkeeper",
            skill_id="finance.reconcile",
            package_id=str(package["package_id"]),
            package=package,
            run_id="run_" + "b" * 32,
            task_id="tsk_" + "a" * 32,
            agent_id="agent_finance.worker",
            authority_class="work-authority",
            authority_id="wka_" + "f" * 32,
            signers=[signer],
            now=datetime(2026, 9, 16, 10, 12, tzinfo=UTC),
        )
