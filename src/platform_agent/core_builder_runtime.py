"""Run one Core engineering job through the actual paid Runner and Builder.

Every model round uses the existing signed paid gate, durable PostgreSQL
reservation/settlement and independent Core output scanner. Only the final
verified ZIP is projected as the job's result. No model fixture is installed.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Any

from agent_protocol.cost_envelope import derive_cost_envelope_id, validate_cost_envelope_at
from agent_protocol.schema import canonical_sha256
from engineering_agent.builder import BuilderBoundaryError, BuilderTask, IndependentVerifier
from engineering_agent.builder_runner import RunnerModelArtifact, RunnerModelRequest
from foundry_runner.control_plane_http import (
    ClaimedExecutionJob, ControlPlaneHttpClient, ControlPlaneRevocationSource,
)
from foundry_runner.execution_provider import ExecutionWorker, ProducedArtifact, ProviderResult, ProviderUsage
from foundry_runner.project_execution_bridge import (
    ProjectAction, ProjectExecutionEnvelope, RuntimeProjectionTransport, runtime_completion_event,
)

from .artifact_store import ContentAddressedArtifactStore
from .core_execution_authorizer import ArtifactWorkerBinding
from .engineering_builder_authority import TenantBuilderAuthority
from .engineering_builder_runtime import BuilderDeliveryResult, TenantBuilderRuntime
from .skill_activation_issuer import VerifiedExecutionScope
from .tenant_control import TenantContext

WorkerFactory = Callable[[Mapping[str, Any], str, int | None, Mapping[str, Any]], ExecutionWorker]
AuthorityFactory = Callable[[Callable[[], None]], TenantBuilderAuthority]


class CoreClaimGuard:
    """Sticky Core revocation/lease guard shared with every Builder checkpoint."""
    def __init__(self, control: ControlPlaneHttpClient, job: ClaimedExecutionJob,
                 clock: Callable[[], datetime]) -> None:
        self._control, self._job, self._clock = control, job, clock
        self._denied = Event()

    def checkpoint(self) -> None:
        if self._denied.is_set():
            raise BuilderBoundaryError("Core Builder claim has lost live authority")
        try:
            self._control.require_claim(self._job)
            decision = ControlPlaneRevocationSource(self._control).check(
                tenant_id=self._control.tenant_id, workspace_id=self._job.workspace_id,
                project_id=self._job.project_id, assignment_ref=self._job.assignment_id,
                agent_id=self._job.agent_id, authority_id=self._job.authority_id,
                authority_epoch=self._job.authority_epoch)
            if not decision.allowed:
                raise BuilderBoundaryError("Core revoked the Builder assignment")
            beat = self._control.heartbeat(self._job.id)
            expiry = beat.get("leaseExpiresAt")
            now = self._clock()
            if (beat.get("id") != self._job.id or beat.get("status") != "running"
                    or not isinstance(expiry, str) or now.tzinfo is None):
                raise BuilderBoundaryError("Core Builder lease is unavailable")
            expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if expires.tzinfo is None or expires <= now:
                raise BuilderBoundaryError("Core Builder lease expired")
        except Exception:
            self._denied.set()
            raise BuilderBoundaryError("Core Builder liveness cannot be proven") from None


def builder_session_envelope(
    *, task: BuilderTask, binding: ArtifactWorkerBinding, job: ClaimedExecutionJob,
    context: TenantContext, skill_id: str, skill_contract_sha256: str,
    now: datetime, maximum_seconds: int,
) -> dict[str, Any]:
    if (task.tenant_id != binding.tenant_id or task.tenant_id != context.tenant_id
            or task.project_id != binding.project_id or task.project_id != job.project_id
            or job.workspace_id != binding.workspace_id
            or task.cell_id != context.cell_id or job.agent_id != binding.core_agent_id
            or job.professional_role != binding.professional_role or job.objective != task.goal
            or task.model_budget_microusd != job.provider_budget_microusd
            or task.model_budget_microusd < task.max_rounds
            or now.tzinfo is None or now.utcoffset() is None
            or type(maximum_seconds) is not int or not 30 <= maximum_seconds <= 1800):
        raise BuilderBoundaryError("Core job differs from the configured approved Builder task")
    scope = VerifiedExecutionScope(binding.workspace_id, job.assignment_id, binding.role_id,
        binding.role_manifest_ref, skill_id, "sha256:" + skill_contract_sha256)
    issued = now.astimezone(UTC).replace(microsecond=0)
    value: dict[str, Any] = {
        "schema_version": "cost-envelope.v1", "cost_envelope_id": "",
        "tenant_context": {**context.as_dict(), "execution_scope": scope.as_dict()},
        "run_id": "run_" + canonical_sha256([task.tenant_id, job.workspace_id, job.id, task.task_id])[:32],
        "task_id": task.task_id, "agent_id": binding.canonical_agent_id, "currency": "USD",
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(seconds=maximum_seconds)).isoformat().replace("+00:00", "Z"),
        "limits": {"max_total_cost_microusd": task.model_budget_microusd,
            "max_model_cost_microusd": task.model_budget_microusd, "max_external_tool_cost_microusd": 0,
            "max_paid_invocations": task.max_rounds, "max_retries": task.max_rounds - 1,
            "max_child_tasks": 0, "max_parallel_paid_invocations": 1,
            "max_input_tokens": binding.max_input_tokens * task.max_rounds,
            "max_output_tokens": binding.max_output_tokens * task.max_rounds,
            "premium_model_allowed": False},
    }
    value["cost_envelope_id"] = derive_cost_envelope_id(value)
    validate_cost_envelope_at(value, now=now)
    return value


class CoreBuilderModel:
    """Concrete AdmittedRunnerModel; economic and scan references are real outputs."""
    def __init__(self, *, task: BuilderTask, job: ClaimedExecutionJob,
                 session_envelope: Mapping[str, Any], factory: WorkerFactory,
                 checkpoint: Callable[[], None]) -> None:
        self._task, self._job, self._envelope = task, job, deepcopy(dict(session_envelope))
        self._factory, self._checkpoint = factory, checkpoint
        self.outputs: list[ProducedArtifact] = []

    def produce(self, request: RunnerModelRequest) -> RunnerModelArtifact:
        task = self._task
        for key in ("task_id", "tenant_id", "project_id", "workspace_id", "cell_id", "repository_id"):
            if getattr(request, key) != getattr(task, key):
                raise BuilderBoundaryError("model request changed the admitted Core Builder scope")
        if (request.base_commit_sha != task.workspace_base_commit_sha or request.goal != task.goal
                or request.output_format != "dop.v1" or len(self.outputs) >= task.max_rounds
                or type(request.maximum_spend_microusd) is not int
                or not 0 < request.maximum_spend_microusd <= task.model_budget_microusd):
            raise BuilderBoundaryError("model request exceeds the admitted Builder session")
        self._checkpoint()
        # A fixed fraction of the already approved total is reserved per call;
        # unused rounds are never dispatched or charged. No paid-call retry.
        ceiling = min(task.model_budget_microusd // task.max_rounds, request.maximum_spend_microusd)
        worker = self._factory(request.model_context_fields(),
            "model-" + str(len(self.outputs) + 1), ceiling, self._envelope)
        result = worker.produce_claimed(self._job, checkpoint=self._checkpoint)
        admitted = result.authorization.admitted
        assignment = admitted.profession_assignment
        if (assignment.task_id != task.task_id or assignment.run_id != self._envelope["run_id"]
                or assignment.tenant_context.tenant_id != task.tenant_id
                or assignment.tenant_context.project_id != task.project_id
                or assignment.tenant_context.cell_id != task.cell_id
                or assignment.tenant_context.workspace_id != self._job.workspace_id
                or assignment.tenant_context.assignment_ref != self._job.assignment_id
                or result.staged.result.cost_microusd > ceiling
                or admitted.signed_work_authority is None):
            raise BuilderBoundaryError("paid Runner output differs from the Builder session")
        self.outputs.append(result)
        self._checkpoint()
        output = result.staged.result
        reservation = result.authorization.reservation
        return RunnerModelArtifact(task_id=task.task_id, tenant_id=task.tenant_id,
            workspace_id=task.workspace_id, project_id=task.project_id, cell_id=task.cell_id,
            repository_id=task.repository_id, base_commit_sha=task.workspace_base_commit_sha,
            content_bytes=output.content_bytes, content_sha256=output.content_sha256,
            actual_usage_microusd=output.cost_microusd,
            model_usage_evidence_ref=output.evidence_refs[0],
            signed_admission_ref="sha256:" + canonical_sha256(admitted.signed_work_authority),
            reservation_ref="runner:reservation:" + reservation.invocation_id,
            settlement_ref="runner:settlement:" + reservation.cost_envelope_id + ":" + reservation.invocation_id,
            independent_scan_ref=result.staged.scan_ref)

    def publish(self, completed: BuilderDeliveryResult, artifacts: ContentAddressedArtifactStore,
                context: TenantContext) -> None:
        if completed.artifact is None or completed.execution.status != "verified" or not self.outputs:
            raise BuilderBoundaryError("only a verified, metered Builder result can be published")
        record = completed.artifact
        content = artifacts.read_bytes(context, repository_id=self._task.repository_id,
            artifact_id=record.artifact_id)
        usages = [item.staged.result.usage for item in self.outputs]
        if any((u.provider_id, u.model_or_tool_id, u.pricing_version) !=
               (usages[0].provider_id, usages[0].model_or_tool_id, usages[0].pricing_version) for u in usages):
            raise BuilderBoundaryError("Builder model/pricing changed during the session")
        usage = ProviderUsage(usages[0].provider_id, usages[0].model_or_tool_id, usages[0].pricing_version,
            sum(u.model_microusd for u in usages), sum(u.external_tool_microusd for u in usages),
            sum(u.input_tokens for u in usages), sum(u.output_tokens for u in usages),
            sum(u.cached_input_tokens for u in usages))
        total = sum(item.staged.result.cost_microusd for item in self.outputs)
        if total != completed.execution.used_model_microusd or total > self._task.model_budget_microusd:
            raise BuilderBoundaryError("Builder delivery changed its settled actual usage")
        refs = tuple(dict.fromkeys(ref for item in self.outputs
            for ref in (*item.staged.result.evidence_refs, item.staged.scan_ref)))
        result = ProviderResult(self._job.artifact_id, record.name, content, record.sha256,
            "application/zip", refs + ("sha256:" + record.sha256,), total,
            "builder:" + hashlib.sha256((self._job.id + record.sha256).encode()).hexdigest(), usage)
        self._checkpoint()
        self._factory({}, "delivery", None, self._envelope).publish_claimed(self._job, result,
            checkpoint=self._checkpoint)


@dataclass(frozen=True, slots=True)
class CoreBuilderConfiguration:
    task: BuilderTask
    binding: ArtifactWorkerBinding
    core_work_node_id: str
    source_paths: tuple[str, ...]
    workspace: Path
    state_directory: Path
    maximum_seconds: int = 600


class CoreBuilderWorker:
    """One real Core job from claim through verified final artifact projection."""
    def __init__(self, *, control: ControlPlaneHttpClient, configuration: CoreBuilderConfiguration,
                 authority_factory: AuthorityFactory, worker_factory: WorkerFactory,
                 verifier: IndependentVerifier, artifacts: ContentAddressedArtifactStore,
                 tenant_context: Callable[[], TenantContext], skill_id: str, skill_contract_sha256: str,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._control, self._config = control, configuration
        self._authority_factory, self._worker_factory = authority_factory, worker_factory
        self._verifier, self._artifacts = verifier, artifacts
        self._context, self._skill, self._contract = tenant_context, skill_id, skill_contract_sha256
        self._clock = clock

    def run_once(self) -> bool:
        job = self._control.claim()
        if job is None:
            return False
        try:
            config = self._config
            if job.work_node_id != config.core_work_node_id:
                raise BuilderBoundaryError("Core claimed a different configured Builder work node")
            guard = CoreClaimGuard(self._control, job, self._clock)
            guard.checkpoint()
            envelope = builder_session_envelope(task=config.task, binding=config.binding, job=job,
                context=self._context(), skill_id=self._skill, skill_contract_sha256=self._contract,
                now=self._clock(), maximum_seconds=config.maximum_seconds)
            expires = datetime.fromisoformat(envelope["expires_at"].replace("Z", "+00:00"))
            def checkpoint() -> None:
                if self._clock() >= expires:
                    raise BuilderBoundaryError("Core Builder session exceeded its total deadline")
                guard.checkpoint()
            authority = self._authority_factory(checkpoint)
            if authority.task != config.task or authority.agent_id != config.binding.canonical_agent_id:
                raise BuilderBoundaryError("Builder authority changed its configured task")
            model = CoreBuilderModel(task=config.task, job=job, session_envelope=envelope,
                factory=self._worker_factory, checkpoint=authority.checkpoint)
            completed = TenantBuilderRuntime(authority=authority, workspace=config.workspace,
                source_paths=config.source_paths, runner=model, verifier=self._verifier,
                artifacts=self._artifacts, state_directory=config.state_directory).run()
            model.publish(completed, self._artifacts, authority.context)
            return True
        except Exception:
            try:
                failed_scope = ProjectExecutionEnvelope(self._control.tenant_id, job.workspace_id,
                    job.project_id, job.assignment_id, job.work_node_id, job.agent_id, job.authority_id,
                    frozenset(ProjectAction(action) for action in job.allowed_actions), job.provider_budget_microusd)
                RuntimeProjectionTransport(self._control.project_event).completion(
                    runtime_completion_event(failed_scope, outcome="failed", evidence_refs=("builder:execution-failed",)))
            except Exception:
                pass
            raise
        finally:
            self._control.forget_claim(job.id)
