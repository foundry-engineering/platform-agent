# Signed canonical work over live Core records

`CoreAuthorityVerifier` can now verify canonical Work Authority identities while
Core retains its separately persisted authorization and agent-record references.
Configure `resolve_work_authority`, `trusted_work_authority_keys` and a trusted
clock. The resolver is trusted runtime infrastructure; neither keys nor documents
are accepted from model text. Existing direct-reference callers remain compatible.

The existing Work Authority's signed request commitment binds the complete
professional tenant context, Core job/node/authority/agent references, canonical
task and agent, exact profession label, ordinary actions and provider ceiling.
Validation uses agent-protocol's single shared contract and returns a detached
snapshot. Invalid signatures or mismatched commitments stop before Core I/O.
The verifier then performs its existing direct verified-TLS read of the exact
claimed Core job and compares every live binding. Only both checks together can
release Skill Activation issuance; no identifier or signed document is rewritten.

The actual activation-signing tests prove that a canonical Work Authority can
activate its package across distinct Core references and that Core revocation
blocks the signer. The native Core/Platform HTTPS/PostgreSQL probe additionally
checks genuine Ed25519 fixture authorities over the actual built Core service:
valid work, substituted job/node/agent/epoch/budget/scope and untrusted TLS.
Its fixture keys and authority documents do not represent production issuance.

This closes the verified reference association needed by the Runner worker.
Operators still compose approved signing keys, package admission, durable stores
and real inference. No live model or private customer delivery is certified here.
