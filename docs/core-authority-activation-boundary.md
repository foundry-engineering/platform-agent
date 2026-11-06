# Live Core authority and Skill Activation boundary

CoreAuthorityVerifier is the concrete callback for
SkillActivationIssuer.verify_authority_binding. Its trusted input is the exact
claimed job and an explicitly configured professional/skill manifest binding.
A browser or model cannot supply this callback or create a claimed job by
constructing its input dataclass.

For every issuance, the verifier makes an authenticated direct HTTPS read of
Core's versioned foundry.core-runtime-authority.v1 snapshot. It compares the
exact tenant, workspace, project, job, work node, assignment, agent, Work Authority,
authority epoch, professional label, manifest digest, skill membership, allowed
actions and provider budget. Denial, missing fields, ambiguity, expiry/revocation,
transport failure and substituted scope stop issuance before signing.

The adapter does not normalize a display label into a role ID. The trusted
registry mapping keeps Core's professional label and Protocol's role ID distinct,
bound to the configured manifest digest. GovernedSkillAdmissionService continues
to validate the actual package, skill contract and immutable package admission.
Execution Grants and consequential actions remain outside this ordinary artifact
Work Authority adapter; it must not be used to bypass their dedicated gates.

Only certificate- and hostname-verified TLS is accepted. There are no redirects,
proxy forwarding or automatic retries. Responses have a 64 KiB ceiling; connected
I/O and response time are bounded. Duplicate JSON keys and nonstandard numbers
are rejected. Service credentials stay in HTTP headers and errors never repeat
tokens or upstream bodies. OS DNS resolution is outside the connected deadline.

The native acceptance runs Platform's actual TLS client against the actual built
Core application, signed fixture authentication and isolated PostgreSQL. Fixture
material is delivered through private stdin. Positive scope, eight substitutions
and untrusted TLS are checked; a separate issuer test proves revocation prevents
the real activation signer from being called. Fixtures are explicit: no live model,
production identity, package-quality, independent evaluation or delivery approval
is established by this boundary test.

This adapter closes live Core verification for activation issuance. It does not
provide a production tenant/admission database, private signing service, the full
ExecutionAuthorizer composition, live model or overall Enterprise release approval.


## Scoped one-use witness continuation

WorkAccessWitnessIssuer preserves the exact professionally scoped context from
its resolved activation after comparing the base tenant/project/cell/epoch/keyset
to live state. It rechecks the current package admission and both upstream
lifetimes before signing, denies a witness that would outlive its authority, and
uses detached authority/activation/request snapshots across signing callbacks.

Ten focused regressions cover the former scope loss, changed live context,
expired/short activation, revoked package admission and callback mutation. The
existing four-repository handoff now uses a canonical real signed Work Authority,
actual persisted package admission, actual activation/witness issuance and Runner's
actual one-use access gate. Eleven checks reject replay, changed requests,
workspace/artifact/key substitution, expiry and revocation. The side effect and
replay adapter are explicit single-process contract fixtures, not a paid provider
or a distributed-production acceptance claim.
