"""Compose the actual worker with durable adapters and configured operational authority."""
from __future__ import annotations

import ssl
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psycopg import Connection

from foundry_runner.control_plane_http import ControlPlaneHttpClient
from foundry_runner.economic_gate import EconomicGate
from foundry_runner.execution_provider import ExecutionWorker, HttpExecutionProvider
from foundry_runner.http_transport import HttpTransport
from foundry_runner.network_egress import EgressPolicy
from foundry_runner.paid_dispatch import HeartbeatPaidDispatcher, PaidDispatchPolicy
from foundry_runner.paid_invocation_gate import PaidInvocationGate
from foundry_runner.postgres_economic_store import PostgresEconomicReservationStore
from foundry_runner.postgres_paid_concurrency import PostgresPaidConcurrencyLeaseStore
from foundry_runner.postgres_spend_ledger import PostgresSpendLedger
from foundry_runner.postgres_spend_reconciler import PostgresSpendReconciler
from foundry_runner.postgres_waw_replay_store import PostgresWitnessReplayStore
from foundry_runner.work_access_gate import WorkAccessGate

from .artifact_execution_store import SQLiteArtifactExecutionStore
from .core_authority import CoreAuthorityClient
from .core_execution_authorizer import ArtifactWorkerBinding, CoreExecutionAuthorizer
from .core_work_authority_issuer import ArtifactWorkPolicy, CoreWorkAuthoritySigner
from .postgres_artifact_budget import PostgresArtifactBudgetRegistrar
from .skill_admission_service import GovernedSkillAdmissionService


def build_core_artifact_worker(
    *, binding: ArtifactWorkerBinding, core_origin: str, core_token_supplier: Callable[[], str],
    admissions: GovernedSkillAdmissionService, package: Mapping[str, Any], artifact_bytes: bytes,
    policy: ArtifactWorkPolicy, signers: Sequence[CoreWorkAuthoritySigner], state_path: Path,
    connection_factory: Callable[[], Connection[tuple[Any, ...]]], license_id: str,
    provider: HttpExecutionProvider, upload_egress_policy: EgressPolicy,
    clock: Callable[[], datetime] | None = None, core_ssl_context: ssl.SSLContext | None = None,
    upload_transport: HttpTransport | None = None,
) -> ExecutionWorker:
    """No memory stores, automatic budget provisioning or default signing keys.

    The database schema and four parent budget scopes must already be deployed
    by their authority owner. A missing/expired scope denies registration. The
    caller runs run_once under its process supervisor and owns service-token
    renewal, external signer provisioning and package deployment.
    """
    now = clock or (lambda: datetime.now(UTC))
    core = CoreAuthorityClient(origin=core_origin, token_supplier=core_token_supplier,
                               ssl_context=core_ssl_context)
    authorizer = CoreExecutionAuthorizer(
        binding=binding, client=core, admissions=admissions, package=package, artifact_bytes=artifact_bytes,
        policy=policy, signers=signers, store=SQLiteArtifactExecutionStore(state_path),
        economics=PostgresArtifactBudgetRegistrar(connection_factory=connection_factory,
            tenant_id=binding.tenant_id, license_id=license_id, agent_id=binding.canonical_agent_id),
        provider=provider, clock=now,
    )
    paid_gate = PaidInvocationGate(
        economic_gate=EconomicGate(reservation_store=PostgresEconomicReservationStore(connection_factory=connection_factory)),
        work_access_gate=WorkAccessGate(replay_store=PostgresWitnessReplayStore(connection_factory=connection_factory),
                                       trusted_keys=authorizer.trusted_keys),
        paid_dispatcher=HeartbeatPaidDispatcher(
            lease_store=PostgresPaidConcurrencyLeaseStore(connection_factory=connection_factory),
            policy=PaidDispatchPolicy(),
        ), clock=now,
    )
    return ExecutionWorker(
        control=ControlPlaneHttpClient(base_url=core_origin, tenant_id=binding.tenant_id,
            workspace_id=binding.workspace_id, token_supplier=core_token_supplier),
        provider=provider, authorizer=authorizer, paid_gate=paid_gate,
        spend_ledger=PostgresSpendLedger(connection_factory=connection_factory),
        spend_reconciler=PostgresSpendReconciler(connection_factory=connection_factory),
        upload_egress_policy=upload_egress_policy, upload_transport=upload_transport, clock=now,
        trusted_work_authority_keys=authorizer.trusted_keys,
    )
