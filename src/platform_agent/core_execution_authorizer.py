"""Concrete Core/Platform/Runner composition for one configured artifact worker.

Install platform-agent[worker]. Core retains business approval; existing Runner
gates retain reservation, replay protection, liveness, scanning and settlement.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from agent_protocol.cost_envelope import derive_cost_envelope_id, validate_cost_envelope_at
from agent_protocol.schema import canonical_sha256
from agent_protocol.skill_package import validate_skill_package, verify_skill_package_artifact
from foundry_runner.control_plane_admission import AdmittedControlPlaneWork
from foundry_runner.control_plane_http import ClaimedExecutionJob
from foundry_runner.core_work_binding import bind_core_work_authority
from foundry_runner.economic_gate import CostReservationRequest
from foundry_runner.execution_provider import ExecutionAuthorization, HttpExecutionProvider
from foundry_runner.skill_runtime_gate import admit_skill_launch

from .artifact_execution_store import SQLiteArtifactExecutionStore
from .core_authority import ClaimedCoreAuthority, CoreAuthorityClient, CoreAuthorityVerifier
from .core_work_authority_issuer import ArtifactWorkPolicy, CoreWorkAuthorityIssuer, CoreWorkAuthoritySigner
from .skill_activation_issuer import SkillActivationIssuer, SkillActivationSigner, VerifiedExecutionScope
from .skill_admission_service import GovernedSkillAdmissionService
from .work_access_witness_issuer import WorkAccessWitnessIssuer, WorkAccessWitnessSigner


class CoreExecutionAuthorizationError(RuntimeError):
    pass


class CostEnvelopeRegistrar(Protocol):
    def register(self, envelope: Mapping[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class ArtifactWorkerBinding:
    tenant_id: str
    project_id: str
    workspace_id: str
    core_agent_id: str
    professional_role: str
    canonical_agent_id: str
    role_id: str
    role_manifest_ref: str
    max_input_tokens: int = 32768
    max_output_tokens: int = 2048

    def __post_init__(self) -> None:
        for field in ("max_input_tokens", "max_output_tokens"):
            value = getattr(self, field)
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError("trusted artifact token ceilings must be bounded positive integers")


class CoreExecutionAuthorizer:
    def __init__(
        self, *, binding: ArtifactWorkerBinding, client: CoreAuthorityClient,
        admissions: GovernedSkillAdmissionService, package: Mapping[str, Any], artifact_bytes: bytes,
        policy: ArtifactWorkPolicy, signers: Sequence[CoreWorkAuthoritySigner],
        store: SQLiteArtifactExecutionStore, economics: CostEnvelopeRegistrar,
        provider: HttpExecutionProvider, clock: Callable[[], datetime] | None = None,
    ) -> None:
        validate_skill_package(dict(package))
        verify_skill_package_artifact(dict(package), artifact_bytes)
        if not signers or len({signer.kid for signer in signers}) != len(signers):
            raise ValueError("unique trusted artifact worker signers required")
        if package.get("authority_class") != "work-authority":
            raise ValueError("artifact worker requires an admitted Work Authority package")
        self._binding, self._client, self._admissions = binding, client, admissions
        self._package, self._artifact = deepcopy(dict(package)), bytes(artifact_bytes)
        self._policy, self._signers, self._store = policy, tuple(signers), store
        self._keys = {signer.kid: signer.public_key for signer in signers}
        self._economics, self._provider = economics, provider
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def trusted_keys(self) -> dict[str, bytes]:
        return dict(self._keys)

    def _material(self, job: ClaimedExecutionJob) -> tuple[str, str, ClaimedCoreAuthority]:
        b = self._binding
        if (job.project_id != b.project_id or job.workspace_id != b.workspace_id
                or job.agent_id != b.core_agent_id or job.professional_role != b.professional_role):
            raise CoreExecutionAuthorizationError("job differs from the configured artifact worker")
        scope = VerifiedExecutionScope(
            workspace_id=b.workspace_id, assignment_ref=job.assignment_id,
            role_id=b.role_id, role_manifest_ref=b.role_manifest_ref,
            skill_id=str(self._package["skill_id"]),
            skill_manifest_ref="sha256:" + str(self._package["skill_contract_sha256"]),
        )
        claimed = ClaimedCoreAuthority(
            tenant_id=b.tenant_id, project_id=job.project_id, execution_job_id=job.id,
            work_node_id=job.work_node_id, agent_id=job.agent_id, authority_id=job.authority_id,
            authority_epoch=job.authority_epoch, professional_role=job.professional_role,
            provider_budget_microusd=job.provider_budget_microusd,
            allowed_actions=job.allowed_actions, scope=scope, artifact_id=job.artifact_id,
        )
        job_key = canonical_sha256([b.tenant_id, job.workspace_id, job.id])
        digest = canonical_sha256({"job": asdict(job), "worker": asdict(b),
                                   "package_id": self._package["package_id"]})
        return job_key, digest, claimed

    def _admitted(
        self, job: ClaimedExecutionJob, claimed: ClaimedCoreAuthority, documents: dict[str, Any],
    ) -> AdmittedControlPlaneWork:
        authority, activation = documents["authority"], documents["activation"]
        launch = admit_skill_launch(
            activation=activation, skill_package=self._package, artifact_bytes=self._artifact,
            trusted_activation_keys=self._keys, now=self._clock(),
        )
        admitted = AdmittedControlPlaneWork(job.assignment_id, launch.assignment,
                                           job.provider_budget_microusd, deepcopy(authority))
        bind_core_work_authority(job=job, assignment=launch.assignment, tenant_id=claimed.tenant_id,
                                 authority=authority, trusted_keys=self._keys, now=self._clock())
        context = self._admissions.current_context(claimed.tenant_id, claimed.project_id)
        admission = self._admissions.resolve(
            tenant_id=claimed.tenant_id, project_id=claimed.project_id, role_id=claimed.scope.role_id,
            skill_id=claimed.scope.skill_id, package_id=str(self._package["package_id"]),
        )
        if admission.as_dict() != documents["admission"]:
            raise CoreExecutionAuthorizationError("persisted package admission changed")
        CoreAuthorityVerifier(client=self._client, binding=claimed,
                              resolve_work_authority=lambda _: authority,
                              trusted_work_authority_keys=self._keys, clock=self._clock)(
            "work-authority", launch.assignment.authority_id, context,
            launch.assignment.task_id, launch.assignment.agent_id,
        )
        return admitted

    def admit(self, job: ClaimedExecutionJob) -> AdmittedControlPlaneWork:
        key, digest, claimed = self._material(job)
        fresh, documents = self._store.begin(key, digest)
        if not fresh:
            return self._admitted(job, claimed, documents)
        try:
            task_id, run_id = "tsk_" + key[:32], "run_" + key[:32]
            authority = CoreWorkAuthorityIssuer(
                client=self._client, admissions=self._admissions, policy=self._policy, clock=self._clock,
            ).issue(binding=claimed, task_id=task_id, agent_id=self._binding.canonical_agent_id,
                    package_id=str(self._package["package_id"]), signers=self._signers)
            activation = SkillActivationIssuer(
                admissions=self._admissions, verify_authority_binding=CoreAuthorityVerifier(
                    client=self._client, binding=claimed, resolve_work_authority=lambda _: authority,
                    trusted_work_authority_keys=self._keys, clock=self._clock,
                ),
            ).issue(
                tenant_id=claimed.tenant_id, project_id=claimed.project_id, role_id=claimed.scope.role_id,
                skill_id=claimed.scope.skill_id, package_id=str(self._package["package_id"]),
                package=self._package, run_id=run_id, task_id=task_id, agent_id=self._binding.canonical_agent_id,
                authority_class="work-authority", authority_id=str(authority["authority_id"]),
                signers=[SkillActivationSigner(s.kid, s.public_key, s.sign) for s in self._signers],
                now=self._clock(), lifetime_seconds=min(60, self._policy.lifetime_seconds),
            )
            admission = self._admissions.resolve(
                tenant_id=claimed.tenant_id, project_id=claimed.project_id, role_id=claimed.scope.role_id,
                skill_id=claimed.scope.skill_id, package_id=str(self._package["package_id"]),
            )
            documents = {"authority": authority, "activation": activation, "admission": admission.as_dict()}
            admitted = self._admitted(job, claimed, documents)
            self._store.transition(key, before="issuing", after="admitted", documents=documents)
            return admitted
        except Exception:
            self._store.transition(key, before="issuing", after="failed")
            raise CoreExecutionAuthorizationError("artifact admission failed closed") from None

    def authorize(
        self, job: ClaimedExecutionJob, *, admitted: AdmittedControlPlaneWork, request: Mapping[str, Any],
    ) -> ExecutionAuthorization:
        key, digest, claimed = self._material(job)
        _, documents = self._store.begin(key, digest, create=False)
        expected = self._admitted(job, claimed, documents)
        if admitted != expected or canonical_sha256(request) != canonical_sha256(self._provider.work_request(
            job, tenant_id=claimed.tenant_id, assignment=expected.profession_assignment,
        )):
            raise CoreExecutionAuthorizationError("execution request changed its exact admitted work")
        self._store.transition(key, before="admitted", after="authorizing")
        try:
            assignment = admitted.profession_assignment
            authority, activation = documents["authority"], documents["activation"]
            current = self._clock().astimezone(UTC).replace(microsecond=0)
            expiry = min(str(authority["expires_at"]), str(activation["expires_at"]))
            envelope: dict[str, Any] = {
                "schema_version": "cost-envelope.v1", "cost_envelope_id": "",
                "tenant_context": assignment.tenant_context.as_dict(), "run_id": assignment.run_id,
                "task_id": assignment.task_id, "agent_id": assignment.agent_id, "currency": "USD",
                "issued_at": current.isoformat().replace("+00:00", "Z"), "expires_at": expiry,
                "limits": {"max_total_cost_microusd": job.provider_budget_microusd,
                           "max_model_cost_microusd": job.provider_budget_microusd,
                           "max_external_tool_cost_microusd": 0, "max_paid_invocations": 1,
                           "max_retries": 0, "max_child_tasks": 0, "max_parallel_paid_invocations": 1,
                           "max_input_tokens": self._binding.max_input_tokens,
                           "max_output_tokens": self._binding.max_output_tokens, "premium_model_allowed": False},
            }
            envelope["cost_envelope_id"] = derive_cost_envelope_id(envelope)
            validate_cost_envelope_at(envelope, now=self._clock())
            # Registration creates only the approved envelope and its run/task
            # children. Shared platform/tenant/license/agent ceilings pre-exist.
            self._economics.register(envelope)
            self._admitted(job, claimed, documents)
            remaining = int((datetime.fromisoformat(expiry.replace("Z", "+00:00")) - self._clock()).total_seconds())
            witness = WorkAccessWitnessIssuer(
                admissions=self._admissions, resolve_authority=lambda _: authority,
                resolve_activation=lambda _: activation,
            ).issue(
                tenant_id=claimed.tenant_id, project_id=claimed.project_id,
                work_authority_id=assignment.authority_id, skill_activation_id=assignment.skill_activation_id,
                invocation_id="inv_" + key[:32], request=request,
                signers=[WorkAccessWitnessSigner(s.kid, s.public_key, s.sign) for s in self._signers],
                now=self._clock(), lifetime_seconds=min(15, remaining),
            )
            self._admitted(job, claimed, documents)
            reservation = CostReservationRequest(
                cost_envelope_id=str(envelope["cost_envelope_id"]), invocation_id="inv_" + key[:32],
                estimated_total_microusd=job.provider_budget_microusd,
                estimated_model_microusd=job.provider_budget_microusd, estimated_external_tool_microusd=0,
                input_tokens=self._binding.max_input_tokens, max_output_tokens=self._binding.max_output_tokens,
            )
            self._store.transition(key, before="authorizing", after="authorized", documents={
                **documents, "cost_envelope": envelope, "witness": witness, "request_sha256": canonical_sha256(request),
            })
            return ExecutionAuthorization(admitted, deepcopy(envelope), deepcopy(witness), reservation)
        except Exception:
            self._store.transition(key, before="authorizing", after="failed")
            raise CoreExecutionAuthorizationError("artifact paid authorization failed closed") from None
