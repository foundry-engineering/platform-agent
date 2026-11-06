"""Verify real registry manifests through persisted admission, issuance and runner admission.

All identities, signing keys, packages and databases are isolated test fixtures.
This verifies the contract handoff; it does not certify a deployed Core or a paid provider.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocol.schema import canonical_sha256
from agent_protocol.skill_package import (
    derive_skill_package_id,
    skill_package_signed_payload_sha256,
    skill_package_signing_message,
)
from agent_protocol.work_authority import (
    derive_work_authority_id, validate_work_authority,
    work_authority_signed_payload_sha256, work_authority_signing_message,
)
from foundry_runner.work_access_gate import InMemoryWitnessReplayStore, WorkAccessDenied, WorkAccessGate
from foundry_runner.profession_assignment import ProfessionAssignmentError
from foundry_runner.skill_runtime_gate import SkillRuntimeAdmissionError, admit_skill_launch
from platform_agent.skill_activation_issuer import (
    SkillActivationIssuer,
    SkillActivationIssuerError,
    SkillActivationSigner,
    VerifiedExecutionScope,
)
from platform_agent.work_access_witness_issuer import (
    WorkAccessWitnessIssuer, WorkAccessWitnessIssuerError, WorkAccessWitnessSigner,
)
from platform_agent.skill_admission import SQLiteSkillAdmissionStore
from platform_agent.skill_admission_service import GovernedSkillAdmissionService
from platform_agent.tenant_control import (
    SQLiteTenantControlStore,
    TenantContext,
    TenantNotActiveError,
)


def ref(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def denied(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except (
        SkillRuntimeAdmissionError,
        SkillActivationIssuerError,
        ProfessionAssignmentError,
        TenantNotActiveError,
        WorkAccessDenied,
        WorkAccessWitnessIssuerError,
    ):
        print("Contract check passed: " + label)
        return
    raise AssertionError("Unsafe handoff accepted: " + label)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-root", type=Path, required=True)
    parser.add_argument("--registry-commit", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[a-f0-9]{40}", args.registry_commit) is None:
        raise ValueError("Exact registry commit SHA required")
    role: dict[str, Any] = json.loads((args.registry_root / "agents/bookkeeper.json").read_text())
    skill: dict[str, Any] = json.loads(
        (args.registry_root / "skills/v2/bookkeeping.reconcile.json").read_text()
    )
    assert role["schema_version"] == "foundry.role-manifest.v2"
    assert skill["schema_version"] == "foundry.skill-manifest.v2"
    assert skill["skill_id"] in role["skill_ids"]
    assert role["authority_class"] == skill["authority_class"] == "work-authority"
    now = datetime(2026, 10, 11, 17, 0, tzinfo=UTC)
    artifact = b"Isolated contract-test package; no business execution.\n"
    sbom = b'{"test_only":true,"components":[]}\n'
    provenance = json.dumps({"registry_commit": args.registry_commit, "test_only": True}).encode()
    evidence = b"Isolated contract-verification evidence\n"
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    package: dict[str, Any] = {
        "schema_version": "skill-package.v1",
        "package_id": "",
        "skill_id": skill["skill_id"],
        "skill_version": skill["version"],
        "skill_contract_sha256": canonical_sha256(skill),
        "runtime_api_version": "foundry.skill-runtime.v1",
        "authority_class": skill["authority_class"],
        "source": {
            "repository_id": "foundry-engineering/foundry-registry",
            "commit_sha": args.registry_commit,
            "subpath": "skills/v2",
        },
        "artifact": {
            "digest": ref(artifact),
            "media_type": "application/octet-stream",
            "size_bytes": len(artifact),
            "sbom_ref": ref(sbom),
            "provenance_ref": ref(provenance),
        },
        "required_capabilities": skill["tool_policy"]["capabilities"],
        "resource_types": skill["resource_policy"]["resource_types"],
        "verification": {
            "profile_id": "verification-contract.v1",
            "result": "passed",
            "evaluator_ids": ["evaluator_contract.v1"],
            "evidence_refs": [ref(evidence)],
            "verified_at": "2026-10-11T17:00:00Z",
        },
    }
    package["package_id"] = derive_skill_package_id(package)
    package["signatures"] = [
        {
            "kid": "kid_contract-test.v1",
            "alg": "ed25519",
            "signed_sha256": skill_package_signed_payload_sha256(package),
            "sig_b64": base64.b64encode(key.sign(skill_package_signing_message(package))).decode(),
        }
    ]
    with TemporaryDirectory(prefix="foundry-contract-") as directory:
        root = Path(directory)
        tenants = SQLiteTenantControlStore(root / "tenants.db")
        tenants.create_tenant("tnt_contract0001", keyset_id="keyset_contract.v1")
        tenants.create_project("tnt_contract0001", "prj_contract0001")
        service = GovernedSkillAdmissionService(
            tenant_store=tenants, admission_store=SQLiteSkillAdmissionStore(root / "admissions.db")
        )
        record = service.admit(
            tenant_id="tnt_contract0001",
            project_id="prj_contract0001",
            role_id=role["id"],
            package=package,
            skill_contract=skill,
            trusted_signing_keys={"kid_contract-test.v1": public},
            artifact_bytes=artifact,
            sbom_bytes=sbom,
            provenance_bytes=provenance,
            verification_evidence={ref(evidence): evidence},
            reason="Isolated contract verification",
            now=now,
        )
        assert (
            service.resolve(
                tenant_id=record.tenant_id,
                project_id=record.project_id,
                role_id=role["id"],
                skill_id=skill["skill_id"],
            )
            == record
        )
        assert service.verify_event_chain(record.tenant_id)
        print("Contract check passed: real registry manifests and signed package admitted durably")
        scope = VerifiedExecutionScope(
            workspace_id="workspace_contract",
            assignment_ref="assignment_contract",
            role_id=role["id"],
            role_manifest_ref="sha256:" + canonical_sha256(role),
            skill_id=skill["skill_id"],
            skill_manifest_ref="sha256:" + canonical_sha256(skill),
        )
        task = "tsk_" + "b" * 32
        agent = "bookkeeper-worker"
        request: dict[str, Any] = {
            "tool_id": "finance.ledger-read", "connector_id": None,
            "resource": {"resource_type": "business-record", "resource_id": "ledger:contract-test", "action": "read"},
            "arguments": {"test_only": True},
        }
        scoped_context = {**service.current_context(record.tenant_id, record.project_id).as_dict(),
                          "execution_scope": scope.as_dict()}
        work_authority: dict[str, Any] = {
            "schema_version": "work-authority.v1", "authority_id": "",
            "tenant_context": scoped_context, "task_id": task, "agent_id": agent, "role_id": role["id"],
            "request_sha256": canonical_sha256(request),
            "policy_ref": {"policy_id": "contract-test.v1", "policy_sha256": "a" * 64,
                           "jurisdiction": "AT", "constraints": []},
            "issued_at": "2026-10-11T17:00:00Z", "expires_at": "2026-10-11T17:01:00Z",
            "resources": [{"resource_type": "business-record", "resource_id": "ledger:contract-test",
                           "actions": ["read"], "data_classification": "internal"}],
            "tool_ids": [request["tool_id"]], "connector_ids": [],
            "budget": {"max_model_calls": 1, "max_tool_calls": 1,
                       "max_cost_microusd": 1, "max_wall_seconds": 60},
            "approvals": [], "constraint_evidence": [], "regulated_reviews": [],
        }
        authority = derive_work_authority_id(work_authority)
        work_authority["authority_id"] = authority
        work_authority["signatures"] = [{"kid": "kid_authority-contract.v1", "alg": "ed25519",
            "signed_sha256": work_authority_signed_payload_sha256(work_authority),
            "sig_b64": base64.b64encode(key.sign(work_authority_signing_message(work_authority))).decode()}]
        validate_work_authority(work_authority)

        def verify_authority(
            kind: str, identity: str, context: TenantContext, task_id: str, agent_id: str
        ) -> VerifiedExecutionScope:
            assert kind == "work-authority" and identity == authority
            assert context.tenant_id == record.tenant_id and context.project_id == record.project_id
            assert task_id == task and agent_id == agent
            return scope

        issuer = SkillActivationIssuer(
            admissions=service, verify_authority_binding=verify_authority
        )
        signer = SkillActivationSigner(
            kid="kid_activation-contract.v1", public_key=public, sign=key.sign
        )
        activation = issuer.issue(
            tenant_id=record.tenant_id,
            project_id=record.project_id,
            role_id=role["id"],
            skill_id=skill["skill_id"],
            package_id=record.package_id,
            package=package,
            run_id="run_" + "c" * 32,
            task_id=task,
            agent_id=agent,
            authority_class="work-authority",
            authority_id=authority,
            signers=[signer],
            now=now,
        )

        def launch(
            document: dict[str, Any],
            payload: bytes = artifact,
            clock: datetime = now,
            trusted: bytes = public,
        ) -> object:
            return admit_skill_launch(
                activation=document,
                skill_package=package,
                artifact_bytes=payload,
                trusted_activation_keys={signer.kid: trusted},
                now=clock,
            )

        admitted = admit_skill_launch(
            activation=activation,
            skill_package=package,
            artifact_bytes=artifact,
            trusted_activation_keys={signer.kid: public},
            now=now,
        )
        assert admitted.assignment.tenant_context.workspace_id == scope.workspace_id
        assert admitted.assignment.tenant_context.assignment_ref == scope.assignment_ref
        assert admitted.assignment.role_manifest_ref == scope.role_manifest_ref
        assert admitted.assignment.skill_manifest_ref == scope.skill_manifest_ref
        assert admitted.assignment.admission_id == record.admission_id
        print("Contract check passed: platform-issued activation accepted by actual runner")
        witness_issuer = WorkAccessWitnessIssuer(
            admissions=service, resolve_authority=lambda _: work_authority,
            resolve_activation=lambda _: activation,
        )
        witness_signer = WorkAccessWitnessSigner(kid="kid_witness-contract.v1", public_key=public, sign=key.sign)

        def issue_witness() -> dict[str, object]:
            return witness_issuer.issue(tenant_id=record.tenant_id, project_id=record.project_id,
                work_authority_id=authority, skill_activation_id=str(activation["activation_id"]),
                invocation_id="inv_" + "d" * 32, request=request, signers=[witness_signer], now=now)

        witness = issue_witness()
        assert witness["tenant_context"] == admitted.assignment.tenant_context.as_dict()
        effects: list[str] = []
        access = WorkAccessGate(replay_store=InMemoryWitnessReplayStore(),
                               trusted_keys={witness_signer.kid: public})
        def fixture_read() -> str:
            effects.append("fixture-read")
            return "ok"

        assert access.invoke(witness=witness, request=request, now=now, operation=fixture_read) == "ok"
        assert effects == ["fixture-read"]
        print("Contract check passed: Platform scoped witness accepted by actual Runner access gate")
        denied("one-use witness replay rejected", lambda: access.invoke(
            witness=witness, request=request, now=now, operation=lambda: effects.append("replay")))
        denied("changed tool request rejected", lambda: access.invoke(
            witness=witness, request={**request, "arguments": {"changed": True}},
            now=now, operation=lambda: effects.append("changed")))
        assert effects == ["fixture-read"]
        altered: dict[str, Any] = copy.deepcopy(activation)
        altered["tenant_context"]["execution_scope"]["workspace_id"] = "workspace_foreign"
        denied("signed workspace substitution rejected", lambda: launch(altered))
        denied("artifact substitution rejected", lambda: launch(activation, b"tampered"))
        denied("untrusted activation key rejected", lambda: launch(activation, trusted=b"x" * 32))
        denied(
            "expired activation rejected",
            lambda: launch(activation, clock=now + timedelta(minutes=2)),
        )
        service.revoke(record.admission_id, reason="Contract test revocation", now=now)
        denied("revoked package cannot issue another witness", issue_witness)
        tenants.set_project_status(
            record.tenant_id, record.project_id, "suspended", reason="Test hold"
        )
        denied(
            "suspended canonical project cannot reissue activation",
            lambda: issuer.issue(
                tenant_id=record.tenant_id,
                project_id=record.project_id,
                role_id=role["id"],
                skill_id=skill["skill_id"],
                package_id=record.package_id,
                package=package,
                run_id="run_" + "c" * 32,
                task_id=task,
                agent_id=agent,
                authority_class="work-authority",
                authority_id=authority,
                signers=[signer],
                now=now,
            ),
        )
    print(
        "Registry/Protocol/Platform/Runner contract integration: 11 checks passed; provider calls: 0"
    )


if __name__ == "__main__":
    main()
