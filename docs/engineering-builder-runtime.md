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
approved authority, an absolute isolated workspace, an explicit tuple of project file
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
| sourcePaths | Explicit list of permitted project paths, covered by both signed read and write capabilities. |
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

The two-round regression uses an explicit model-response fixture to guarantee
a failed first candidate. The PR and manual CI runs start Engineering's
deployable `foundry-model-host` with the pinned Qwen2.5-Coder-7B assets. The live
test first verifies that a seeded pricing bug fails the Docker checks. It then
requires the signed worker to repair the source, settle the measured tokens in
PostgreSQL, pass independent Docker checks and produce a ZIP containing the
verified bytes. The job log records the model, token counts, source digest and
verification references. The token tariff is for test accounting.

On 15 November 2026 the local run repaired the seeded bug with 331 input and
125 output tokens in one model invocation. The inference took 61.35 seconds.
PostgreSQL 16 stored the settlement. Independent checks ran in read-only,
network-denied Linux namespaces on that host. The verified source SHA-256 was
`713150536ec72e73a0b80ea57b40cc874c64589771fda55b69affc8f168a34b4`.
The equivalent Docker check is required separately in the native CI run.

The worker test uses isolated Core/storage counterparties. Actual Core HTTP
contracts run in a separate integration step. A live customer execution still
requires the deployed model service, private profile and secrets, reviewed
sandbox image, and existing approved authority and budgets. Production code
has no fixture-model fallback.

## Explicit project files

Engineering main `b297f509fe0addb8f7c907b0262023b0cbce654c` extends each
work unit to `src/`, `app/`, `lib/`, `public/` and `migrations/`, together with
`package.json`, `pyproject.toml`, `tsconfig.json`, `README.md`, `index.html`,
`next.config.ts`, `next.config.mjs`, `vite.config.ts` and `Dockerfile`. SQL and
JavaScript module outputs are supported. Every non-`src/` output must have an
exact supplied source snapshot, including null snapshots for new files.

The worker still requires the exact operational `sourcePaths` list to be
covered by both read and write capabilities in an existing signed grant. A
manifest or migration path does not extend an earlier `src/`-only grant. Hidden
metadata, credentials and independent test files remain excluded. Full-file
replacements retain their expected SHA-256 precondition.

The signed delivery regression assembles a manifest, application module, SQL
migration and public page, seals their exact bytes and verifies the private ZIP
manifest. Its Docker variant runs the migration and two-tenant application
queries in the existing isolated immutable Python image. Model/economic
counterparties in these regressions are explicit fixtures. The ordinary real
model worker acceptance remains a separate check.

This is bounded project-file support: each work unit still carries at most 16
source snapshots, eight output files per model round and 32 KiB of total source
context. Larger platforms require separately admitted work units; this change
does not establish unrestricted project generation or a production release.

## Coordinated work units in one approved job

The optional `foundry.core-builder-profile.v2` operator profile replaces
`sourcePaths` with `workUnits`. Every other top-level field is unchanged. It
uses the existing Core job, immutable Builder task, signed Execution Grant,
shared PostgreSQL cost envelope, scanner and final private output projection.
Work units are operational subdivisions, not new canonical child jobs or new
approvals. Their instructions and dependencies come from the trusted operator
profile, never from a model response.

Each work-unit object contains exactly these fields:

| Field | Meaning |
| --- | --- |
| unitId | Unique lowercase identifier for this operational unit. |
| objective | Bounded task data, within the existing root goal and authority. |
| sourcePaths | At most 16 explicit project files, including dependencies and missing output snapshots. |
| outputPaths | At most eight sourcePaths entries this unit may replace. |
| dependencies | Unit IDs whose independently checked results must exist first. |
| maxRounds | Attempt allowance; the sum across units cannot exceed the original task's max_rounds. |
| checkIds | IDs of existing fixed checks in the root sandbox profile. |

The existing task-graph evaluator determines execution order. Cycles, unknown
dependencies, duplicated output ownership, file/directory aliases, undeclared
producer dependencies and excess total rounds fail before model dispatch. A
unit may read an earlier dependency's file but cannot write it. The existing
signed grant must cover all configured source paths; work units create no
additional authority.

Every unit uses a fresh source snapshot and the existing signed Builder repair
loop. The original immutable task is retained. Only its round count and
remaining total model budget are narrowed for each unit. A failed unit prevents
its dependents from starting. All actual rounds remain in the same durable
Core/Runner accounting session, with distinct admitted invocation IDs and
globally numbered independent verification evidence.

After all units pass, the runtime snapshots every explicit project file in
bounded groups, runs all root integration checks and rejects any changed or
missing snapshot. It emits one `foundry.builder-delivery.v2` ZIP manifest with
work-unit definitions/results, all step receipts, total usage and exact file
hashes. The legacy profile continues producing its v1 manifest. No per-unit
customer completion or intermediate delivery is published. The original grant
is consumed once; a crash still requires explicit reconciliation and fresh
approved authority, with no automatic repeat of spent work.

The acceptance fixture builds 24 files in three dependent units. Its native
Docker checks execute the shared SQL migration, tenant-isolated service and
application entry point. The PostgreSQL session case traverses the real model
HTTP handler, signed Runner, durable settlements, actual DOP mutations and
final scanned ZIP projection. Inference and Core/storage counterparties in
that specific test are controlled fixtures. The existing separate Qwen test
continues to require actual model inference.

Operating bounds remain explicit: at most six units and six total admitted
model calls per root task, 16 source snapshots and 32 KiB per request, eight
output files per model response and a 256 KiB final ZIP. This enables larger
compositions within one job; automatic decomposition of arbitrary large
repositories and complete customer-scale project generation remain separate
acceptance targets.

### Real-model work-unit acceptance

The native live-model step also requires `live_units`: two dependent units over
seeded pricing and invoice bugs. Actual Qwen inference must repair the price
calculation first, then repair the invoice module while retaining the already
verified pricing input. The trusted Docker checks exercise exact integer
arithmetic and tenant-preserving invoice output. The same PostgreSQL session
accounts for every actual inference and permits one final v2 ZIP only after
both units and the complete integration check pass. The test uses isolated
Core/storage counterparts; its model responses have no fixture fallback.

The first native multi-unit model attempts exposed checksum transcription
failures. The accepted source-aware model contract asks for paths and full
source only; Engineering derives omitted overwrite preconditions from the
verified request snapshots. Explicit wrong/null hashes remain rejected, and
actual file changes after a snapshot still prevent execution. The isolated
multi-unit model profile explicitly allows up to 512 output tokens; the
existing single-file acceptance retains its 192-token profile.


## Automatic planning from approved source imports

`foundry.core-builder-profile.v3` replaces `sourcePaths`/`workUnits` with one
`autoPlan` object. All other private profile fields and existing signed authority
remain required. For example:

```json
{
  "schemaVersion": "foundry.builder-auto-plan.v1",
  "sourcePaths": ["src/orders.py", "src/pricing.py"],
  "fileChecks": {
    "src/orders.py": ["invoices-check"],
    "src/pricing.py": ["pricing-check"]
  },
  "maxFilesPerUnit": 1,
  "maxRoundsPerUnit": 2,
  "moduleAliases": {}
}
```

The operator supplies the approved existing source manifest, fixed check IDs
from `sandbox.checks`, and limits. The compiler supplies unit identities, order,
dependencies and read-only dependency context. No model call, filesystem walk,
source execution, additional job or extra budget is used for planning.

Python AST and pinned Tree-sitter JavaScript/JSX/TypeScript/TSX grammars resolve
static imports, re-exports and literal JavaScript require/import calls against
that manifest only. Optional aliases map canonical directory prefixes, such as
`"@/": "src/"`. Bare third-party packages create no repository edges; Python
absolute names outside the manifest may be external packages. Computed or
unsupported imports need an explicit v2 plan. These bounded static edges are
scheduling data, not a proof of every possible runtime dependency.

Import cycles and files sharing a check remain atomic. Deterministic packing
preserves topological order and existing per-unit boundaries: at most eight
outputs, 16 context files, 32 KiB context, 12 checks, six units, and the root
approved model-call/budget ceiling. The aggregate planning input is at most 48
existing files and 192 KiB. Oversized atomic groups, ambiguous/missing local
imports, invalid syntax, denied paths and changed planning snapshots stop
before inference. A source digest check runs again after the Core claim and
before the attempt starts. Run on an isolated single-writer workspace.

A verified automatic run emits `foundry.builder-delivery.v3`: the original
source digests, static dependency graph, trusted check mapping, derived units
and canonical planning digest accompany all existing execution, usage and
independent delivery evidence. Explicit v1/v2 profiles retain their semantics.

Native acceptance `[live_auto]` derives the two billing units from the original
Python imports, runs the actual managed Qwen host through PostgreSQL-backed
paid gates and signed DOP execution, executes fixed Docker checks and seals one
v3 ZIP. This verifies the automatic existing-source repair path; it does not
prove autonomous discovery of an arbitrary repository, creation of arbitrary
new architectures, or permanent production hosting.
