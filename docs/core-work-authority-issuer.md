# Core-backed artifact Work Authority issuer

`CoreWorkAuthorityIssuer` issues the existing signed `work-authority.v1`
document for ordinary artifact production. Its inputs come from trusted
platform configuration and a claimed Core job, never from model output.

Before signing, the issuer verifies the current tenant context, exact active
package admission and the live Core authority over the configured authenticated
HTTPS client. The Core snapshot must match the claimed job, assignment, node,
agent, profession, workspace, project, epoch, budget and artifact target. The
existing request commitment binds Core references to canonical signed identities.

The resulting authority permits one provider call and one tool call, creation
of the exact claimed artifact, the exact approved provider budget and a maximum
120-second lifetime. It grants no connector access and invents no approvals or
regulated reviews. Policy identity, jurisdiction and policy digest are trusted
configuration. External signing callbacks receive the existing protocol signing
message; returned Ed25519 signatures are verified before returning the document.

Tenant context, admission snapshot, Core authority and deadline are rechecked
before each signature and after the last signature. A revocation, rotation,
package change, expired lease or changed target causes issuance to fail closed.
The caller receives a detached verified document and remains responsible for
durable storage, signer provisioning and connecting the production authorizer.

The native Core acceptance probe uses actual SQLite admission stores and signed
package verification, then composes this issuer with Skill Activation and Work
Access Witness issuance against the built Core HTTP application. Package bytes,
policy, provenance and signing keys in that probe are explicit isolated test
fixtures. It verifies target substitution and persisted admission revocation.
The probe does not contact a model or demonstrate a deployed production agent.
