# Concrete artifact worker runtime

Install `platform-agent[worker]` to use `build_core_artifact_worker`. The optional
dependency pins the exact verified Runner source and its typed public interfaces.
Core remains the owner of business approval and the canonical job. This runtime
produces a quarantined candidate for Core review; it does not approve its own work.

The configured worker binds one tenant, project, workspace, Core agent record,
profession label, canonical agent/role and exact role manifest. Package bytes are
hashed and matched to the persisted verified admission. Model output cannot choose
these bindings, keys, policy, token ceilings, license or provider endpoint.

`CoreExecutionAuthorizer` implements the actual Runner admission/authorization
interface. It obtains signed parent Work Authority from live Core, issues and
verifies Skill Activation, rechecks the live admission and exact request, registers
the approved Cost Envelope, and issues the one-use Work Access Witness. Each
existing issuer retains its signature domain and validation rules. The complete
Core provider ceiling and configured token ceilings are reserved before execution.

Private SQLite issuance state is shared by processes on one trusted host. A job
has stable run/task/invocation identities. Restart can resume an unchanged, still
valid admission without issuing another parent. Beginning authorization consumes
that transition atomically. Authorized, failed or interrupted issuance never
automatically creates fresh spend authority; explicit recovery owns uncertainty.
Different job contents, package, scope, target or budget cannot replace the stored
commitment. The state directory and database must be private to their owner.

The production factory wires PostgreSQL reservations, witness replay claims,
paid concurrency, spend settlement and reconciliation. It has no memory-store or
default-key fallback. `PostgresArtifactBudgetRegistrar` requires existing active
platform/tenant/license/agent ceilings and registers only exact run/task children
and the approved envelope. Existing counters, deadlines and ceilings cannot be
reset or enlarged. Missing roots or conflicting leaves roll back the transaction.
The database authority rechecks every applicable scope at actual reservation.

Operators supply deployed schemas, admitted package bytes, operational signers,
service-token renewal, the existing HTTPS Core origin, private upload policy,
provider configuration and process supervision. The factory returns the actual
Runner `ExecutionWorker`; call `run_once()` under that supervisor. An uncertain
failed invocation must use the existing recovery process rather than retry.

Acceptance uses explicit fixture Core/provider/storage counterparties around the
actual issuers and worker. Native PostgreSQL acceptance exercises the real durable
gates, six budget scopes, permanent replay protection and settlement. The existing
separate HTTPS/OIDC/PostgreSQL probe verifies the built Core boundary. These tests
do not constitute live model inference, independent model quality evaluation,
deployed operational keys or customer delivery.
