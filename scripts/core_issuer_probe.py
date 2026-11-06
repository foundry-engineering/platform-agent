"""Isolated admission/issuer composition for the native real-Core acceptance.

Fixture package bytes, manifests, provenance and keys are deliberately created
here. Admission persistence, signature checks and issuer paths are actual code.
No supplied package is executed and no model/provider is contacted.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocol.schema import canonical_sha256
from agent_protocol.skill_package import (
    derive_skill_package_id, skill_package_signed_payload_sha256, skill_package_signing_message,
)
from agent_protocol.work_access_witness import verify_work_access_witness_signatures
from platform_agent.core_authority import ClaimedCoreAuthority, CoreAuthorityClient, CoreAuthorityVerifier
from platform_agent.core_work_authority_issuer import (
    ArtifactWorkPolicy, CoreWorkAuthorityIssuer, CoreWorkAuthorityIssuerError, CoreWorkAuthoritySigner,
)
from platform_agent.skill_activation_issuer import SkillActivationIssuer, SkillActivationSigner
from platform_agent.skill_admission import SQLiteSkillAdmissionStore
from platform_agent.skill_admission_service import GovernedSkillAdmissionService
from platform_agent.tenant_control import SQLiteTenantControlStore
from platform_agent.work_access_witness_issuer import WorkAccessWitnessIssuer, WorkAccessWitnessSigner


def _ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_core_work_authority_issuer(binding: ClaimedCoreAuthority, client: CoreAuthorityClient) -> int:
    now = datetime.now(UTC).replace(microsecond=0)
    key = Ed25519PrivateKey.generate()
    kid, public = "kid_core-issuer-probe.v1", key.public_key().public_bytes_raw()
    contract = {
        "schema_version": "foundry.skill-manifest.v2", "skill_id": binding.scope.skill_id,
        "version": "1.0.0", "authority_class": "work-authority",
        "implementation_policy": {"binding": "runtime-skill-pack", "version_binding": "exact",
                                  "missing_implementation": "deny"},
    }
    artifact = b"Isolated authority-composition fixture; never executed.\n"
    sbom, provenance, evidence = b'{"test_only":true}', b'{"isolated_provenance":true}', b"fixture verification"
    package: dict[str, Any] = {
        "schema_version": "skill-package.v1", "package_id": "", "skill_id": binding.scope.skill_id,
        "skill_version": "1.0.0", "skill_contract_sha256": canonical_sha256(contract),
        "runtime_api_version": "foundry.skill-runtime.v1", "authority_class": "work-authority",
        "source": {"repository_id": "foundry-engineering/platform-agent", "commit_sha": "b" * 40,
                   "subpath": "isolated-core-issuer-fixture"},
        "artifact": {"digest": _ref(artifact), "media_type": "application/octet-stream",
                     "size_bytes": len(artifact), "sbom_ref": _ref(sbom), "provenance_ref": _ref(provenance)},
        "required_capabilities": [], "resource_types": ["artifact"],
        "verification": {"profile_id": "core-issuer-probe.v1", "result": "passed",
                         "evaluator_ids": ["evaluator_core-issuer.v1"], "evidence_refs": [_ref(evidence)],
                         "verified_at": now.isoformat().replace("+00:00", "Z")},
    }
    package["package_id"] = derive_skill_package_id(package)
    package["signatures"] = [{"kid": kid, "alg": "ed25519",
        "signed_sha256": skill_package_signed_payload_sha256(package),
        "sig_b64": base64.b64encode(key.sign(skill_package_signing_message(package))).decode()}]
    b = replace(binding, scope=replace(binding.scope, skill_manifest_ref="sha256:" + canonical_sha256(contract)))
    with TemporaryDirectory(prefix="core-issuer-acceptance-") as directory:
        root = Path(directory)
        tenants = SQLiteTenantControlStore(root / "tenants.db")
        tenants.create_tenant(b.tenant_id, keyset_id="keyset_core-issuer-probe.v1")
        tenants.create_project(b.tenant_id, b.project_id)
        admissions = GovernedSkillAdmissionService(
            tenant_store=tenants, admission_store=SQLiteSkillAdmissionStore(root / "admissions.db"),
        )
        record = admissions.admit(
            tenant_id=b.tenant_id, project_id=b.project_id, role_id=b.scope.role_id,
            package=package, skill_contract=contract, trusted_signing_keys={kid: public},
            artifact_bytes=artifact, sbom_bytes=sbom, provenance_bytes=provenance,
            verification_evidence={_ref(evidence): evidence}, reason="Isolated actual Core issuer acceptance", now=now,
        )
        checks = 1
        assert admissions.verify_event_chain(b.tenant_id)
        context = admissions.current_context(b.tenant_id, b.project_id)
        assert context.authority_epoch == b.authority_epoch
        signatures: list[bytes] = []
        def sign(message: bytes) -> bytes:
            signatures.append(message)
            return key.sign(message)
        signer = CoreWorkAuthoritySigner(kid, public, sign)
        issuer = CoreWorkAuthorityIssuer(
            client=client, admissions=admissions,
            policy=ArtifactWorkPolicy("pol_core-issuer-probe.v1", "b" * 64, "AT"),
        )
        task, agent = "tsk_core-issuer-0001", "core-issuer-worker"
        authority = issuer.issue(binding=b, task_id=task, agent_id=agent,
                                 package_id=record.package_id, signers=[signer])
        assert authority["resources"][0]["resource_id"] == b.artifact_id
        assert len(signatures) == 1
        checks += 1
        activation = SkillActivationIssuer(
            admissions=admissions, verify_authority_binding=CoreAuthorityVerifier(
                client=client, binding=b, resolve_work_authority=lambda _: authority,
                trusted_work_authority_keys={kid: public},
            ),
        ).issue(
            tenant_id=b.tenant_id, project_id=b.project_id, role_id=b.scope.role_id,
            skill_id=b.scope.skill_id, package_id=record.package_id, package=package,
            run_id="run_" + "c" * 32, task_id=task, agent_id=agent,
            authority_class="work-authority", authority_id=authority["authority_id"],
            signers=[SkillActivationSigner(kid, public, key.sign)], now=datetime.now(UTC),
        )
        request = {"tool_id": "foundry.provider.execute", "connector_id": None,
                   "resource": {"resource_type": "artifact", "resource_id": b.artifact_id, "action": "create"},
                   "arguments": {"isolated_core_job": b.execution_job_id}}
        witness = WorkAccessWitnessIssuer(
            admissions=admissions, resolve_authority=lambda _: authority,
            resolve_activation=lambda _: activation,
        ).issue(
            tenant_id=b.tenant_id, project_id=b.project_id,
            work_authority_id=authority["authority_id"], skill_activation_id=str(activation["activation_id"]),
            invocation_id="inv_" + "d" * 32, request=request,
            signers=[WorkAccessWitnessSigner(kid, public, key.sign)], now=datetime.now(UTC),
        )
        assert verify_work_access_witness_signatures(witness, {kid: public}) == (kid,)
        checks += 1
        try:
            issuer.issue(binding=replace(b, artifact_id="foreign_artifact"), task_id=task, agent_id=agent,
                         package_id=record.package_id, signers=[signer])
        except CoreWorkAuthorityIssuerError:
            checks += 1
        else:
            raise AssertionError("Core issuer signed authority for a different live target")
        assert len(signatures) == 1
        admissions.revoke(record.admission_id, reason="Isolated acceptance revocation")
        try:
            issuer.issue(binding=b, task_id=task, agent_id=agent,
                         package_id=record.package_id, signers=[signer])
        except CoreWorkAuthorityIssuerError:
            checks += 1
        else:
            raise AssertionError("revoked persisted package received new authority")
        assert len(signatures) == 1 and admissions.verify_event_chain(b.tenant_id)
        return checks
