# Engineering Builder runtime

`TenantBuilderAuthority` binds one immutable Engineering `BuilderTask` to an
existing `TenantSandboxAdmission`. It verifies the exact admitted Execution
Grant against configured public keys, reads live tenant/repository state and the
existing run reservation, then uses Platform's canonical workspace-binding and
authority-witness issuers. No tenant, approval, grant, signer, run reservation or
budget is created by this adapter. External signer callbacks stay in the trusted
process. A key rotation, suspended project, released reservation or changed task
stops issuance; an external signing callback cannot hide an intervening revoke.

`TenantBuilderRuntime` composes that issuer with `RunnerBudgetedPlanner`, fresh
`ScopedSourceContext`, the canonical signed DOP executor, an independently
configured verifier and `ContentAddressedArtifactStore`. Construct it with the
approved authority, an absolute isolated workspace, an explicit tuple of `src/`
paths, the trusted `AdmittedRunnerModel` port, an independent verifier, the
existing tenant artifact store and a pre-existing private state directory outside
the workspace. Install `platform-agent[worker,integration]` for this composition.

The Runner port remains trusted infrastructure: it must establish signed
admission, durable reservation/settlement and independent scanning before
returning a model artifact. A raw provider JSON response or user-supplied evidence
reference is insufficient. The runtime does not turn a new direct model HTTP
adapter into a paid or approved Runner invocation.

Every model round and independent check revalidates current tenant authority.
Only the configured source files may be written. An exclusive, fsynced attempt
record consumes each Execution Grant once before dispatch. Restarting after an
unknown outcome cannot repeat model calls or mutations; recovery requires fresh
approved authority and reconciliation of the original attempt. The runtime does
not release the caller-owned reservation or refund consumed model spend.

Failed, repeated or exhausted candidates produce no customer artifact. After a
successful repair, the runtime snapshots the configured source files, performs
another independent check and rejects a changed or missing snapshot. Only those
sealed bytes enter the deterministic ZIP, together with scope, base commit,
Execution Grant ID, actual model cost, step receipts and final check references.
The existing artifact backend enforces tenant/project/repository access and
rehashes reads. Artifacts, state and verification evidence must live outside the
model workspace. Use the existing `DockerSandboxVerifier` with a reviewed image
digest and fixed checks on an appropriately isolated worker.

## Core job execution

`CoreBuilderWorker` claims the configured Core project, agent and work node. The
Core job must match the pre-approved Builder task's tenant, project, goal and
total model budget. A single shared cost envelope binds its immutable task and
run IDs across all rounds. PostgreSQL registers the existing tenant, cell,
project, workspace, assignment and run budget scopes. Each round reserves only
its share of the total and gets a distinct signed invocation ID. The model
service deduplicates that invocation, rather than suppressing a legitimate
repair because it belongs to the same Core job.

`CoreBuilderModel` is the concrete paid Runner adapter. It invokes the signed
paid gate, records durable usage and settlement, uploads the returned DOP and
requires the independent Core scanner before passing those bytes to the signed
Builder executor. Fresh source hashes and independently generated verification
feedback reach the next admitted model round. The job remains running during
repair. Only the verified final ZIP is projected as its artifact and completion;
its cost is the sum of actual settled rounds, without another model charge.

The opaque Core workspace ID and the canonical `wsp_` code-workspace ID are
separate configured identities. The mapping is anchored by the same immutable
Builder task, tenant, project, cell, repository and signed code grant; neither
workspace schema is relaxed. Source paths must be covered by both the grant's
read and write capabilities before source disclosure. Model execution, uploads,
verification and final publication all recheck the enclosing code grant,
reservation, Core lease, revocation state and total deadline.

## Operator entrypoint

Install the pinned `worker` and `integration` extras and execute one approved job:

```sh
uv sync --extra worker --extra integration --locked
uv run foundry-engineering-agent --profile /absolute/private/core-builder.json
```

The profile is an owner-only JSON file with schemaVersion
`foundry.core-builder-profile.v1` and these exact fields:

| Field | Required value |
| --- | --- |
| artifactWorkerProfileFile | Absolute path to the existing `foundry.artifact-worker-profile.v1` runtime profile; supplies Core and provider origins, private tokens, PostgreSQL connection, approved package, tenant stores, execution state and WorkAuthority signers. |
| builderTaskFile | Absolute path to the approved serialized `BuilderTask`. |
| tenantAdmissionFile | Absolute path to the existing `TenantSandboxAdmission.as_dict()` JSON, including the reservation and signed Execution Grant. |
| grantTrustedKeysFile | Absolute path to a JSON map of approved grant key IDs to base64 Ed25519 public keys. |
| workspaceSigners, witnessSigners | Lists of objects containing exactly `kid` and `privateKeyFile`; each file contains the base64 Ed25519 private seed for an existing operational signer. |
| coreWorkNodeId | The exact approved Core work node. |
| workspace | Absolute isolated code workspace. |
| sourcePaths | Explicit list of permitted `src/` paths. |
| stateDirectory | Existing private attempt-state directory outside the code workspace. |
| artifactStoreRoot | Existing private tenant artifact-store directory outside the code workspace. |
| verificationEvidenceDirectory | Existing private verification-evidence directory outside the code workspace. |
| sandbox | A `TrustedSandboxProfile` object with a reviewed immutable image digest and fixed checks; each check contains `check_id` and `argv`. |
| maximumSeconds | Integer session deadline from 30 through 1800 seconds. |

Startup validates the existing signed code grant and canonical agent before
claiming work. It creates no approvals, budgets, production signing keys or model
credentials. Changing the runtime configuration during a session stops further
dispatch. A process restart cannot replay a consumed code grant. Reconcile
unknown provider outcomes and issue fresh approved authority before recovery.

## Acceptance and deployment evidence

Native CI exercises actual Ed25519 verification, tenant/reservation state,
PostgreSQL budget accounting, paid dispatch, signed DOP execution, Core scanning
and private ZIP delivery. The full session acceptance requires two metered model
rounds, two settlements, a failed independent check, a successful Docker repair,
three scanned uploads and exactly one final Core artifact/completion. Separate
actual Core HTTPS/PostgreSQL tests reject mismatched project, agent and work-node
selectors. Negative cases cover replay, scope, revocation and pre-provider
cancellation.

The test model server and Core/storage counterparties in the session test are
explicit fixtures. Actual Core HTTP contracts and real Docker checks run in
their own mandatory integration steps. These checks establish executable
application-to-Runner orchestration; they are not evidence of deployed model
weights or a live customer execution. Live operation requires the provisioned
model service, real private profile/secrets, reviewed sandbox image and existing
approved authority and budgets. Production code has no fixture-model fallback.
