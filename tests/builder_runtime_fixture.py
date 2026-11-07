"""Isolated approved-grant/model fixtures; actual crypto, stores and DOP execution."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_protocol.execution_grant import derive_execution_grant_id
from engineering_agent.builder import BuilderTask, Verification
from engineering_agent.builder_runner import RunnerModelArtifact
from engineering_agent.selfhosted_model import _files_to_dop

from platform_agent.admitted_scheduler import AdmittedSchedule
from platform_agent.artifact_store import ContentAddressedArtifactStore
from platform_agent.control_plane import DispatchPlan, TaskAssignment
from platform_agent.engineering_builder_authority import TenantBuilderAuthority
from platform_agent.engineering_builder_runtime import TenantBuilderRuntime
from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
from platform_agent.runtime_authority import (
    AuthorityWitnessSigner, AuthorityWitnessSignerSet, SQLiteAuthorityStateProvider,
)
from platform_agent.task_graph import TaskDecision, TaskGraphSnapshot
from platform_agent.tenant_authority import TenantSandboxAdmission, WorkspaceBindingSigner
from platform_agent.tenant_control import SQLiteTenantControlStore

IMAGE = "docker.io/library/python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"


class ModelPortFixture:
    """Only model/admission/scanner counterparties are fixtures, never the issuer."""
    def __init__(self, h, *, always_fail=False):
        self.h, self.always_fail = h, always_fail
        self.requests = []

    def produce(self, request):
        self.requests.append(request)
        current = request.source_context[0]
        value = 0 if len(self.requests) == 1 or self.always_fail else 42
        item = {"path": "src/app.py", "content": f"def main():\n    return {value}\n"}
        if current.sha256 is not None:
            item["expectedSha256"] = current.sha256
        plan = _files_to_dop({"files": [item]}, task_id=request.task_id,
            policy_sha256="f" * 64, source_context=request.source_context)
        body = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return RunnerModelArtifact(
            task_id=request.task_id, tenant_id=request.tenant_id,
            workspace_id=request.workspace_id, project_id=request.project_id,
            cell_id=request.cell_id, repository_id=request.repository_id,
            base_commit_sha=request.base_commit_sha, content_bytes=body,
            content_sha256=hashlib.sha256(body).hexdigest(), actual_usage_microusd=1,
            model_usage_evidence_ref="fixture:usage", signed_admission_ref="fixture:admission",
            reservation_ref="fixture:reservation", settlement_ref="fixture:settlement",
            independent_scan_ref="fixture:scan",
        )


class IndependentValueFixture:
    """Nonexecuting unit verifier; the separate Docker case runs actual code."""
    def __init__(self, h):
        self.h, self.calls = h, []

    def verify(self, task, *, round_number):
        self.calls.append(round_number)
        content = (self.h.workspace / "src/app.py").read_bytes()
        passed = b"return 42" in content
        return Verification(passed, ("independent-value",),
            ("sha256:" + hashlib.sha256(content).hexdigest(),),
            "" if passed else "Expected return value 42; independent check failed")


class Harness:
    def __init__(self, root):
        self.root = root
        self.workspace = root / "workspace"
        self.workspace.mkdir(mode=0o755)
        self.state = root / "builder-state"
        self.state.mkdir(mode=0o700)
        self.tenants = SQLiteTenantControlStore(root / "control" / "tenant.db")
        self.tenants.create_tenant("tnt_builder-test", keyset_id="keyset_builder-test.v1")
        self.tenants.create_project("tnt_builder-test", "prj_builder-test")
        self.repo = "foundry-engineering/builder-test"
        self.tenants.bind_repository("tnt_builder-test", "prj_builder-test", self.repo)
        snapshot = self.tenants.snapshot("tnt_builder-test", "prj_builder-test", self.repo)
        context = snapshot.context
        self.task = BuilderTask(task_id="tsk_" + "a" * 32, tenant_id=context.tenant_id,
            project_id=context.project_id, cell_id=context.cell_id,
            workspace_id="wsp_" + "a" * 32, repository_id=self.repo,
            workspace_base_commit_sha="a" * 40, goal="Build a function returning 42",
            max_rounds=3, model_budget_microusd=5)
        self.grant_key, self.workspace_key, self.witness_key = (
            Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        dispatch_id = "dsp_" + "d" * 32
        plan = self.plan()
        unsigned = {
            "schema_version": "execution-grant.v1", "grant_id": "sgr_" + "0" * 32,
            "authority": {"dispatch_id": dispatch_id, "plan_admission_id": "adm_" + "a" * 32,
                "candidate_sha256": "b" * 64, "registry_sha256": "c" * 64},
            "tenant_context": context.as_dict(), "task_id": self.task.task_id,
            "agent_id": "engineering-agent", "policy_ref": plan["policy_ref"],
            "request_sha256": "e" * 64, "repo": self.repo,
            "read_paths": ["src", "tests"], "write_paths": ["src"], "allow_delete": False,
            "max_file_bytes": 262144, "tool_ids": ["tool_file.write"],
            "network_hosts": [], "network_ports": [], "environment_keys": [],
            "resources": {"wall_time_seconds": 120, "cpu_time_seconds": 100,
                "memory_mb": 512, "max_processes": 32, "max_output_bytes": 262144},
            "approvals": [], "constraint_evidence": [{"constraint": "fs.write:scoped",
                "evaluator_id": "evaluator_builder-scope.v1", "evidence_ref": "sha256:" + "c" * 64}],
        }
        unsigned["grant_id"] = derive_execution_grant_id(unsigned)
        self.grant = sign_execution_grant(unsigned, signers=(ExecutionGrantSigner(
            "kid_builder-grant.v1", self.grant_key.public_key().public_bytes_raw(), self.grant_key.sign),))
        self.reservation = self.tenants.reserve_run(context.tenant_id, context.project_id,
            self.repo, run_key=dispatch_id)
        graph = TaskGraphSnapshot((self.task.task_id,), (TaskDecision(self.task.task_id, "ready"),))
        schedule = AdmittedSchedule("adm_" + "a" * 32, "b" * 64, graph)
        dispatch = DispatchPlan("foundry.dispatch-plan.v1", dispatch_id, "adm_" + "a" * 32,
            "b" * 64, "c" * 64, (TaskAssignment(self.task.task_id, "engineering-agent", (),
                "adm_" + "a" * 32, "b" * 64, "c" * 64),), schedule)
        self.admission = TenantSandboxAdmission("foundry.tenant-sandbox-admission.v1",
            "tsa_" + "b" * 32, context, snapshot.snapshot_sha256, self.reservation, dispatch, (self.grant,))
        self.artifacts = ContentAddressedArtifactStore(root / "artifacts", self.tenants)
        self.runner = ModelPortFixture(self)
        self.verifier = IndependentValueFixture(self)

    def plan(self, *, content="def main():\n    return 42\n", path="src/app.py"):
        return _files_to_dop({"files": [{"path": path, "content": content}]},
            task_id=self.task.task_id, policy_sha256="f" * 64)

    def authority(self, **overrides):
        values = dict(task=self.task, admission=self.admission,
            authority_state=SQLiteAuthorityStateProvider(self.tenants),
            trusted_grant_keys={"kid_builder-grant.v1": self.grant_key.public_key().public_bytes_raw()},
            workspace_signers=(WorkspaceBindingSigner("kid_builder-workspace.v1",
                self.workspace_key.public_key().public_bytes_raw(), self.workspace_key.sign),),
            witness_signers=AuthorityWitnessSignerSet(self.admission.tenant_context.keyset_id,
                (AuthorityWitnessSigner("kid_builder-witness.v1",
                    self.witness_key.public_key().public_bytes_raw(), self.witness_key.sign),)),
            clock=lambda: datetime.now(UTC))
        values.update(overrides)
        return TenantBuilderAuthority(**values)

    def runtime(self, **overrides):
        values = dict(authority=self.authority(), workspace=self.workspace,
            source_paths=("src/app.py",), runner=self.runner, verifier=self.verifier,
            artifacts=self.artifacts, state_directory=self.state)
        values.update(overrides)
        return TenantBuilderRuntime(**values)

    def task_with(self, **changes):
        return replace(self.task, **changes)


def link_core_code_authority(h, root):
    """Separate canonical code workspace and Core record workspace; same approved task."""
    code = Harness(root)
    code.tenants = h.tenants
    h.tenants.bind_repository(h.config.tenant_id, h.config.project_id, code.repo)
    snapshot = h.tenants.snapshot(h.config.tenant_id, h.config.project_id, code.repo)
    code.task = replace(code.task, tenant_id=h.config.tenant_id, project_id=h.config.project_id,
        cell_id=snapshot.context.cell_id, goal=h.job.objective,
        model_budget_microusd=h.job.provider_budget_microusd)
    grant = {key: value for key, value in code.grant.items() if key != 'signatures'}
    grant['tenant_context'] = snapshot.context.as_dict()
    grant['agent_id'] = h.config.canonical_agent_id
    grant['policy_ref'] = {**grant['policy_ref'], 'policy_sha256': 'a' * 64}
    grant['grant_id'] = derive_execution_grant_id(grant)
    code.grant = sign_execution_grant(grant, signers=(ExecutionGrantSigner('kid_builder-grant.v1',
        code.grant_key.public_key().public_bytes_raw(), code.grant_key.sign),))
    reservation = h.tenants.reserve_run(h.config.tenant_id, h.config.project_id, code.repo,
        run_key=code.admission.dispatch.dispatch_id)
    code.admission = replace(code.admission, tenant_context=snapshot.context,
        reservation=reservation, tenant_snapshot_sha256=snapshot.snapshot_sha256, signed_grants=(code.grant,))
    code.artifacts = ContentAddressedArtifactStore(root / 'tenant-artifacts', h.tenants)
    return code
