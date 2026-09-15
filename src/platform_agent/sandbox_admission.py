"""Compatibility surface for the verified execution-authority runtime.

The implementation lives in :mod:`platform_agent.execution_authority` so that
approval/constraint verification, policy admission, and canonical Execution
Grant construction have one implementation.  Keep imports through this module
stable for callers while the control plane evolves.
"""

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
    admit_dispatch_to_sandbox,
    builtin_constraint_evaluators,
    verify_sandbox_admission,
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
