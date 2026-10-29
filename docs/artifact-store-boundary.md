# Foundry Artifact Store v1 boundary

The local/on-prem artifact backend is a real storage boundary, not a dashboard cache.

## Guarantees

- Every artifact is bound to a current Foundry tenant/project isolation context and repository.
- Content identity is SHA-256; artifact identity additionally binds tenant context, source run and Execution Grant.
- Physical bytes are addressed inside a tenant-specific artifact namespace. Identical content in one tenant/project namespace is stored once while multiple logical artifact records may reference it.
- New physical bytes reserve tenant quota before activation. Interrupted writes may conservatively over-account quota but are reconciled before the next write; the design does not silently exceed quota.
- Writes are staged in a private directory, fsync'd and atomically promoted.
- Reads re-hash bytes before returning them. Tampering fails closed.
- Read/list/export APIs require a live tenant context and repository match. Knowledge of an artifact id is not sufficient authority.
- Tenant epoch/keyset/project changes invalidate stale context before artifact access.
- Export manifests and integrity scrub receipts are content-addressed.
- Tenant purge removes artifact metadata/objects and releases quota before tenant control state may be hard-deleted.

## Trust boundaries

`platform-agent.tenant_control` owns tenant/project/repository status, current authority epoch, isolation cell and quota policy. `artifact_store` owns artifact metadata and content objects. A runtime must not infer tenant authority from artifact metadata alone.

## Backend model

v1 is intentionally dependency-light and suitable for a single-node or on-prem Foundry deployment: SQLite metadata plus private content-addressed filesystem objects. The API is structured so an S3/object-storage backend can implement the same semantic guarantees without changing Execution Grant or PCRun contracts.

## Non-negotiable failure behavior

Hash mismatch, stale tenant context, wrong repository, cross-tenant access, symlink redirection or quota violation must deny the operation. No fallback to best-effort reads or untracked output is permitted.
