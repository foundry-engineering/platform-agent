"""Provision exact Core-approved leaf budgets beneath existing operator ceilings."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from agent_protocol.cost_envelope import validate_cost_envelope_at
from psycopg import Connection


class ArtifactBudgetRegistrationError(RuntimeError):
    pass


class PostgresArtifactBudgetRegistrar:
    def __init__(
        self, *, connection_factory: Callable[[], Connection[tuple[Any, ...]]],
        tenant_id: str, license_id: str, agent_id: str,
    ) -> None:
        if any(not value or value.strip() != value for value in (tenant_id, license_id, agent_id)):
            raise ValueError("trusted tenant, license and agent bindings required")
        self._connect = connection_factory
        self._tenant, self._license, self._agent = tenant_id, license_id, agent_id

    def register(self, envelope: Mapping[str, Any]) -> None:
        try:
            with self._connect() as db, db.cursor() as cursor:
                cursor.execute("SELECT clock_timestamp()")
                row = cursor.fetchone()
                if row is None or not isinstance(row[0], datetime):
                    raise ArtifactBudgetRegistrationError("database clock unavailable")
                validate_cost_envelope_at(dict(envelope), now=row[0])
                if (envelope["tenant_context"]["tenant_id"] != self._tenant
                        or envelope["agent_id"] != self._agent):
                    raise ArtifactBudgetRegistrationError("economic registration changed configured ownership")
                limits = envelope["limits"]
                issued = datetime.fromisoformat(envelope["issued_at"].replace("Z", "+00:00"))
                expires = datetime.fromisoformat(envelope["expires_at"].replace("Z", "+00:00"))
                leaf = (limits["max_total_cost_microusd"], limits["max_paid_invocations"],
                        limits["max_input_tokens"], limits["max_output_tokens"])
                for scope_type, scope_id in (("platform", "platform"), ("tenant", self._tenant),
                                             ("license", self._license), ("agent", self._agent)):
                    cursor.execute(
                        "SELECT max_total_cost_microusd,max_paid_invocations,max_input_tokens,"
                        "max_output_tokens,effective_from,expires_at FROM foundry_budget_scope "
                        "WHERE scope_type=%s AND scope_id=%s FOR UPDATE", (scope_type, scope_id),
                    )
                    root = cursor.fetchone()
                    if (root is None or any(root[i] < leaf[i] for i in range(4))
                            or root[4] > issued or root[5] < expires):
                        raise ArtifactBudgetRegistrationError("existing authoritative parent budget cannot admit work")
                # Never reset counters, renew deadlines or raise existing ceilings.
                for scope_type, scope_id in (("run", envelope["run_id"]), ("task", envelope["task_id"])):
                    cursor.execute(
                        "INSERT INTO foundry_budget_scope(scope_type,scope_id,max_total_cost_microusd,"
                        "max_paid_invocations,max_input_tokens,max_output_tokens,effective_from,expires_at) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (scope_type, scope_id, *leaf, issued, expires),
                    )
                    cursor.execute(
                        "SELECT max_total_cost_microusd,max_paid_invocations,max_input_tokens,"
                        "max_output_tokens,effective_from,expires_at FROM foundry_budget_scope "
                        "WHERE scope_type=%s AND scope_id=%s FOR UPDATE", (scope_type, scope_id),
                    )
                    if cursor.fetchone() != (*leaf, issued, expires):
                        raise ArtifactBudgetRegistrationError("existing leaf authority cannot be replaced")
                keys = (
                    "max_total_cost_microusd", "max_model_cost_microusd", "max_external_tool_cost_microusd",
                    "max_paid_invocations", "max_retries", "max_child_tasks", "max_input_tokens",
                    "max_output_tokens", "premium_model_allowed", "max_parallel_paid_invocations",
                )
                values = (envelope["cost_envelope_id"], self._tenant, self._license, envelope["run_id"],
                          envelope["task_id"], self._agent, *(limits[key] for key in keys), expires)
                columns = "cost_envelope_id,tenant_id,license_id,run_id,task_id,agent_id," + ",".join(keys) + ",expires_at"
                cursor.execute(
                    "INSERT INTO foundry_cost_envelope_state(" + columns + ") VALUES(" +
                    ",".join(["%s"] * len(values)) + ") ON CONFLICT DO NOTHING", values,
                )
                cursor.execute("SELECT " + columns + " FROM foundry_cost_envelope_state "
                               "WHERE cost_envelope_id=%s FOR UPDATE", (envelope["cost_envelope_id"],))
                if cursor.fetchone() != values:
                    raise ArtifactBudgetRegistrationError("persisted Cost Envelope differs from approved work")
                cursor.execute("SELECT clock_timestamp()")
                final = cursor.fetchone()
                if final is None or not issued <= final[0] < expires:
                    raise ArtifactBudgetRegistrationError("economic authority expired during registration")
        except Exception:
            # Connection context rolls back every child/envelope insert together.
            # SQL details, DSNs and provider material never enter the public error.
            raise ArtifactBudgetRegistrationError("approved artifact budget registration failed closed") from None
