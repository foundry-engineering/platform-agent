"""Stable public surface for verified execution-authority admission.

The authority engine lives in :mod:`platform_agent.execution_authority`.  This
module deliberately adds the public fail-closed filesystem scope guard before
calling that engine so callers cannot delegate the whole workspace or Foundry/VCS
metadata even if an older internal helper is still present in a stacked branch.
"""

from collections.abc import Mapping, Sequence

from platform_agent.capability_router import CapabilityRegistry
from platform_agent.execution_authority import (
    ApprovalGrant,
    ApprovalVerifier,
    ConstraintEvaluator,
    ConstraintGrant,
    ExecutionAuthority,
    ExecutionGrant,
    ExecutionRequest,
    PolicyRefBinding,
    ResourceRequest,
    SandboxAdmission,
    SandboxAdmissionError,
    VerificationContext,
    VerifiedApproval,
    VerifiedConstraintEvidence,
    admit_dispatch_to_sandbox as _admit_dispatch_to_sandbox,
    builtin_constraint_evaluators,
    verify_sandbox_admission as _verify_sandbox_admission,
)
from platform_agent.plan_admission import PlanAdmission
from platform_agent.scope_guard import ScopeGuardError, validate_execution_request_scopes


def _guard(requests: Sequence[ExecutionRequest]) -> None:
    try:
        validate_execution_request_scopes(requests)
    except ScopeGuardError as exc:
        raise SandboxAdmissionError(str(exc)) from exc


def admit_dispatch_to_sandbox(
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    approval_verifiers: Mapping[str, ApprovalVerifier] | None = None,
    constraint_evaluators: Mapping[str, ConstraintEvaluator] | None = None,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> SandboxAdmission:
    _guard(requests)
    return _admit_dispatch_to_sandbox(
        plan,
        admission=admission,
        registry=registry,
        requests=requests,
        policies=policies,
        approval_verifiers=approval_verifiers,
        constraint_evaluators=constraint_evaluators,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )


def verify_sandbox_admission(
    current: SandboxAdmission,
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    approval_verifiers: Mapping[str, ApprovalVerifier] | None = None,
    constraint_evaluators: Mapping[str, ConstraintEvaluator] | None = None,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> None:
    _guard(requests)
    _verify_sandbox_admission(
        current,
        plan,
        admission=admission,
        registry=registry,
        requests=requests,
        policies=policies,
        approval_verifiers=approval_verifiers,
        constraint_evaluators=constraint_evaluators,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )


__all__ = [
    "ApprovalGrant",
    "ApprovalVerifier",
    "ConstraintEvaluator",
    "ConstraintGrant",
    "ExecutionAuthority",
    "ExecutionGrant",
    "ExecutionRequest",
    "PolicyRefBinding",
    "ResourceRequest",
    "SandboxAdmission",
    "SandboxAdmissionError",
    "VerificationContext",
    "VerifiedApproval",
    "VerifiedConstraintEvidence",
    "admit_dispatch_to_sandbox",
    "builtin_constraint_evaluators",
    "verify_sandbox_admission",
]
