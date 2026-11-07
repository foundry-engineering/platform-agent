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

Native acceptance uses actual Ed25519 verification, SQLite tenant/reservation
state, signed DOP writes, private artifact storage, replay rejection and negative
scope/revocation cases. Its explicit model and economic counterparties remain
fixtures. The mandatory Docker case exercises failing code, a checksum-bound
repair, passing code and final private packaging through real containers. This
does not establish deployed model inference or complete application-to-Runner
job orchestration.
