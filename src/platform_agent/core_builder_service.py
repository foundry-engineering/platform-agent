"""Operational entrypoint for one configured, approved Core engineering job."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engineering_agent.builder import BuilderTask
from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile
from foundry_runner.control_plane_http import ControlPlaneHttpClient
from foundry_runner.execution_provider import ExecutionWorker

from .admitted_scheduler import AdmittedSchedule
from .artifact_store import ContentAddressedArtifactStore
from .control_plane import DispatchPlan, TaskAssignment
from .core_builder_runtime import CoreBuilderConfiguration, CoreBuilderWorker
from .core_execution_authorizer import ArtifactWorkerBinding
from .core_worker_service import WorkerConfigurationError, _secret, _unique_object, load_worker, private_file
from .engineering_builder_authority import TenantBuilderAuthority
from .runtime_authority import AuthorityWitnessSigner, AuthorityWitnessSignerSet, SQLiteAuthorityStateProvider
from .skill_admission import SQLiteSkillAdmissionStore
from .skill_admission_service import GovernedSkillAdmissionService
from .task_graph import TaskDecision, TaskGraphSnapshot
from .tenant_authority import TenantSandboxAdmission, WorkspaceBindingSigner
from .tenant_control import RunReservation, SQLiteTenantControlStore, TenantContext


def _document(path: object, maximum: int = 512 * 1024) -> dict[str, Any]:
    value = json.loads(private_file(path, maximum=maximum), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise WorkerConfigurationError("private configuration object required")
    return value


def _admission(data: dict[str, Any]) -> TenantSandboxAdmission:
    context = dict(data["tenant_context"])
    if context.pop("schema_version") != "tenant-context.v1":
        raise WorkerConfigurationError("current tenant admission context required")
    dispatch = data["dispatch"]
    schedule = dispatch["schedule"]
    graph = schedule["graph"]
    decisions = tuple(TaskDecision(item["task_id"], item["state"], tuple(item["waiting_on"]),
        tuple(item["failed_dependencies"]), tuple(item["missing_preconditions"])) for item in graph["decisions"])
    assignments = tuple(TaskAssignment(item["task_id"], item["agent_id"],
        tuple(item["required_capabilities"]), item["admission_id"], item["candidate_sha256"],
        item["registry_sha256"]) for item in dispatch["assignments"])
    result = TenantSandboxAdmission(data["schema_version"], data["admission_id"], TenantContext(**context),
        data["tenant_snapshot_sha256"], RunReservation(**data["reservation"]),
        DispatchPlan(dispatch["schema_version"], dispatch["dispatch_id"], dispatch["admission_id"],
            dispatch["candidate_sha256"], dispatch["registry_sha256"], assignments,
            AdmittedSchedule(schedule["admission_id"], schedule["candidate_sha256"],
                TaskGraphSnapshot(tuple(graph["topological_order"]), decisions))), tuple(data["signed_grants"]))
    if result.schema_version != "foundry.tenant-sandbox-admission.v1" or result.as_dict() != data:
        raise WorkerConfigurationError("exact serialized tenant admission required")
    return result


def _signers(entries: object) -> list[tuple[str, Ed25519PrivateKey]]:
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise WorkerConfigurationError("explicit operational signers required")
    result = []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"kid", "privateKeyFile"} or not isinstance(item["kid"], str):
            raise WorkerConfigurationError("exact operational signer profile required")
        raw = base64.b64decode(private_file(item["privateKeyFile"], maximum=128).strip(), validate=True)
        result.append((item["kid"], Ed25519PrivateKey.from_private_bytes(raw)))
    return result


def load_builder(profile_path: Path) -> CoreBuilderWorker:
    data = _document(str(profile_path), 64 * 1024)
    keys = {"schemaVersion", "artifactWorkerProfileFile", "builderTaskFile", "tenantAdmissionFile",
        "grantTrustedKeysFile", "workspaceSigners", "witnessSigners", "coreWorkNodeId", "workspace",
        "sourcePaths", "stateDirectory", "artifactStoreRoot", "verificationEvidenceDirectory",
        "sandbox", "maximumSeconds"}
    if set(data) != keys or data["schemaVersion"] != "foundry.core-builder-profile.v1":
        raise WorkerConfigurationError("exact Core Builder operational profile required")
    runtime_path = Path(data["artifactWorkerProfileFile"])
    runtime = _document(str(runtime_path), 64 * 1024)
    frozen_runtime = json.dumps(runtime, sort_keys=True, separators=(",", ":"))
    task = BuilderTask(**_document(data["builderTaskFile"], 32 * 1024))
    admission = _admission(_document(data["tenantAdmissionFile"]))
    grant_keys = _document(data["grantTrustedKeysFile"], 16 * 1024)
    trusted_keys = {kid: base64.b64decode(value, validate=True) for kid, value in grant_keys.items()}
    workspace_signers = tuple(WorkspaceBindingSigner(kid, key.public_key().public_bytes_raw(), key.sign)
        for kid, key in _signers(data["workspaceSigners"]))
    witness_signers = AuthorityWitnessSignerSet(admission.tenant_context.keyset_id,
        tuple(AuthorityWitnessSigner(kid, key.public_key().public_bytes_raw(), key.sign)
              for kid, key in _signers(data["witnessSigners"])))
    # These are existing authority databases. Startup never creates a tenant,
    # grants a package, manufactures approval, or supplies default signing keys.
    private_file(runtime["tenantStoreFile"], maximum=64 * 1024 * 1024)
    private_file(runtime["admissionStoreFile"], maximum=64 * 1024 * 1024)
    tenants = SQLiteTenantControlStore(Path(runtime["tenantStoreFile"]))
    admissions = GovernedSkillAdmissionService(tenant_store=tenants,
        admission_store=SQLiteSkillAdmissionStore(Path(runtime["admissionStoreFile"])))
    package = _document(runtime["packageFile"])
    binding = ArtifactWorkerBinding(runtime["tenantId"], runtime["projectId"], runtime["workspaceId"],
        runtime["coreAgentId"], runtime["professionalRole"], runtime["canonicalAgentId"],
        runtime["roleId"], runtime["roleManifestRef"], runtime["maxInputTokens"], runtime["maxOutputTokens"])
    if (task.tenant_id != binding.tenant_id or task.project_id != binding.project_id
            or task.cell_id != admission.tenant_context.cell_id):
        raise WorkerConfigurationError("Builder task and Core runtime have different project ownership")
    control = ControlPlaneHttpClient(base_url=runtime["coreOrigin"], tenant_id=binding.tenant_id,
        workspace_id=binding.workspace_id, token_supplier=_secret(runtime["coreTokenFile"]),
        project_id=binding.project_id, agent_id=binding.core_agent_id, work_node_id=data["coreWorkNodeId"])
    sandbox = dict(data["sandbox"])
    sandbox["checks"] = tuple(TrustedCheck(item["check_id"], tuple(item["argv"])) for item in sandbox["checks"])
    verifier = DockerSandboxVerifier(workspace=Path(data["workspace"]),
        evidence_dir=Path(data["verificationEvidenceDirectory"]), profile=TrustedSandboxProfile(**sandbox))
    artifacts = ContentAddressedArtifactStore(Path(data["artifactStoreRoot"]), tenants)
    config = CoreBuilderConfiguration(task, binding, data["coreWorkNodeId"], tuple(data["sourcePaths"]),
        Path(data["workspace"]), Path(data["stateDirectory"]), data["maximumSeconds"])
    # Validate the configured execution identity and existing signed grant before
    # claiming a Core job. The online Core lease is attached after that claim.
    def authority_factory(checkpoint: Callable[[], None]) -> TenantBuilderAuthority:
        return TenantBuilderAuthority(task=task, admission=admission,
            authority_state=SQLiteAuthorityStateProvider(tenants), trusted_grant_keys=trusted_keys,
            workspace_signers=workspace_signers, witness_signers=witness_signers,
            execution_checkpoint=checkpoint)
    preflight = authority_factory(lambda: None)
    if preflight.agent_id != binding.canonical_agent_id:
        raise WorkerConfigurationError("Builder Execution Grant authorizes a different canonical agent")
    def worker_factory(context: Mapping[str, Any], tag: str, ceiling: int | None,
                       envelope: Mapping[str, Any]) -> ExecutionWorker:
        current = _document(str(runtime_path), 64 * 1024)
        if json.dumps(current, sort_keys=True, separators=(",", ":")) != frozen_runtime:
            raise WorkerConfigurationError("Core Builder runtime configuration changed in flight")
        return load_worker(runtime_path, model_context=context or None, control=control,
            session_envelope=envelope, task_id=task.task_id, invocation_tag=tag,
            reservation_ceiling_microusd=ceiling, max_model_calls=task.max_rounds)
    return CoreBuilderWorker(control=control, configuration=config, authority_factory=authority_factory,
        worker_factory=worker_factory, verifier=verifier, artifacts=artifacts,
        tenant_context=lambda: admissions.current_context(task.tenant_id, task.project_id),
        skill_id=package["skill_id"], skill_contract_sha256=package["skill_contract_sha256"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute one configured, approved Core engineering job")
    parser.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args()
    try:
        worker = load_builder(args.profile)
        handled = worker.run_once()
        print(json.dumps({"status": "handled" if handled else "idle"}))
        return 0
    except Exception:
        print("Engineering agent stopped; inspect the private attempt and economic state before recovery.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
