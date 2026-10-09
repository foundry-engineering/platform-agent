# Skill admission trust boundary

`platform-agent` owns the tenant/project decision that an immutable Skill Package may be used for a professional role.

Admission requires all of the following before persistence:

- canonical Skill Package validation against the exact Skill Manifest
- trusted package signature verification
- exact package artifact byte hash and size verification
- SBOM and provenance hash verification
- exact verification-evidence closure
- verification freshness according to tenant policy
- live active tenant/project state derived from the control-plane database
- explicit role + skill binding

Only one package may be active for a tenant/project/role/skill tuple. Changing package versions is an explicit atomic rollout; silent replacement is rejected. Revocation fails closed.

The admission store is a persistence adapter. Production callers use `GovernedSkillAdmissionService`, which derives tenant/project context from live control-plane state instead of trusting caller-supplied context.

The runner receives an exact admission/package/artifact binding. It does not decide whether a package is trusted and cannot override a revoked or missing admission.

Every admission/replacement/revocation produces a tenant-scoped hash-chained event. This local chain is tamper-evident; external anchoring/signing remains a deployment integration requirement and must not be represented as already provided by this store.
