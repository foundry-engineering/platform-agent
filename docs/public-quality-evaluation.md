# Agent 01: fixed public quality smoke evaluation

This is a first-attempt functional smoke subset, not an official HumanEval or
MultiPL-E score, contamination-resistant benchmark, broad platform-building
qualification, market ranking, or production release approval.

Before any model evaluation the selection was fixed: HumanEval tasks 0, 10 and
30, each in Python, JavaScript and Go (nine cases). The immutable suite file is
`tests/quality/multiple-smoke-v1.json`, SHA-256
`c9d19b6d0542872477639cc34adc3102d486b7eb1300edabb08bbbba9661d085`.
Every case retains its upstream source revision and file checksum. The BSD
notice and prohibition on using the dataset to train machine learning models
are retained in `tests/quality/LICENSE.MultiPL-E`. This is evaluation only;
no training or weight modification is implemented.

The managed, CPU-hosted Qwen2.5-Coder-7B-Instruct Q4 model receives only the
function specification and exact source snapshot, with 512 output tokens and
one attempt per case. The model profile and llama runtime identities must match
`/readyz` before dispatch. Each task uses a distinct claimed job and inference
identity. A single model load is shared across the nine isolated cases.

The actual signed worker, PostgreSQL issuance, six budget scopes, invocation
claim, economic settlement, tenant authority, deterministic DOP overwrite and
Docker verifier are composed. Core and object storage counterparts remain
controlled isolated test services; this does not attest a deployed customer
installation or production scanner. Every successful case must also create a
private source ZIP, agree with its manifest checksums and complete its Core
projection. Failed candidates must not publish a successful result.

Each language runner must first accept an explicit controlled reference and
reject the stub in actual Docker before CI dispatches any model request. These
controlled checks qualify measurement machinery and never count as model results.
Go uses typed public input literals and a small JSON emitter, preserving the
unchanged 64 MiB temporary limit without compiling encoding/json.

Only input argument vectors and fixed runner programs enter the network-denied,
read-only candidate container. Expected results remain in a private host file
outside that workspace. The host compares captured JSON values with these
results; it never imports or executes candidate code. A zero process exit without
correct values fails. Go nil and empty slices are treated as equivalent, matching
the selected upstream tests' semantics. Boolean/integer substitutions, partial
vectors, extra prints and invalid JSON fail. Host evidence v3 commits to the
expected vector; the host oracle vectors are absent from the model request and ZIP. Public
examples in the upstream function specifications remain visible as task data.

The private operator sandbox profile may add `oracleFile` per check. It must
name an absolute, private, regular, non-symlink file outside the candidate
workspace with exactly:

```json
{"schemaVersion":"foundry.functional-oracle.v1","expectedResults":[42],"nilEqualsEmpty":false}
```

The worker freezes those results before any model work. The model cannot select
an oracle, alter commands, add mounts, grant network access or approve itself.

CI preserves a JSON report with the predeclared selection checksum, observed
model/profile/runtime identities, candidate and oracle commitments, verification
references, per-case outcomes and actual accounted usage. `notRun` and failures
remain visible; missing, duplicate or mixed-model cases cannot imply a complete
passing report. An unknown model-spend or infrastructure failure aborts acceptance
rather than being silently counted as a candidate quality failure. There are no
automatic inference retries. The first-attempt evaluation records failures honestly; only `regressionGatePassed: true` means all nine observed cases
passed. `releaseApproved` and `marketRankClaim` always remain false.

The Engineering model-host profiles also prepare frozen larger GGUF candidates.
No larger model is downloaded, qualified or activated by the default CI evaluation.
On a separately approved sufficiently sized host, the same fixed nine-case
harness can evaluate pre-provisioned alternative weights by setting
`FOUNDRY_QUALITY_MODEL_PROFILE` to a private approved model profile and
`FOUNDRY_BUILDER_MODEL_ASSETS` to their verified cache. The harness fixes the
output ceiling at 512 and records that effective profile digest, derives its
input reservation from the selected profile and rejects mixed identities. An
approved sufficiently sized persistent host and complete deployment acceptance
remain necessary for production operation. No paid hosting is provisioned here.


## Bounded repair of actual recorded failures

The four failed cases from the qualified baseline run 44480681955 are preserved
with their exact actual generated source hashes in
`tests/quality/generated-7b-failures-v1.json`. The separate repair evaluation
starts with those recorded errors, not a fabricated successful response or a
golden solution. Every case retains its original public function contract in
the immutable Core objective throughout repair; a model replacement cannot
erase the requirements by removing source comments.

The actual Builder first diagnoses the failure with the independent host oracle,
then may make at most three new admitted model calls inside its existing total
budget. Compiler errors are bounded untrusted feedback. Private expected vectors
remain outside the model context and candidate mount. Each subsequent source
snapshot must match the exact preceding DOP bytes, every inference must have
one durable PostgreSQL claim and settlement, and the final private ZIP must
pass all functional/delivery checks. Unknown spend or infrastructure failure
aborts rather than silently retrying.

The JSON report retains the nine-case first-attempt score unchanged and adds a
separate `repairEvaluation`, with each actual round outcome, all model spend,
initial/final source hashes and baseline/final verification evidence. Failed,
missing, duplicate, unmetered, mixed-model or excess-call repairs cannot imply
a passing repair gate. A passing earlier round cannot be followed by another
paid attempt. These are focused regressions of known errors, not an unbiased
benchmark or an overall product release. Original source-generation calls remain
visible in the historical baseline report; repair costs count every new call.


The v2 private oracle profile can explicitly declare `publicInputs`. Mismatch
feedback includes only a public argument vector and the observed candidate
result; expected answers stay private. Both expected results and declared public
inputs are bound into the immutable oracle commitment. Legacy v1 remains strict
and unchanged. Known repeated model proposals are reported as `blocked`, not as
successful repairs or unknown infrastructure failures. All returned model calls,
including the duplicate rejected before mutation, retain usage evidence and
unique actual PostgreSQL settlement invocation IDs. An unexecuted duplicate has
`round_passed: null`, and cannot pass the repair gate.


CI requires every one of the four recorded repair cases to finish verified.
`FOUNDRY_REQUIRE_AGENT_REPAIR_GATE=1` fails the quality step after preserving the
full report if a repair remains blocked, incorrect, missing or incomplete. Honest
accounting of a failure does not turn it into a successful agent result. This
repair gate remains separate from the non-gating raw first-attempt measurement
and from overall product release approval.


The 7B qualified run 44520191177 remained below the required repair gate: five
of nine raw cases and one of four repairs passed. All nine new repair calls and
703 internal micro-USD of usage were retained, including one duplicate blocked
before mutation. The gate stayed red. No expected answer or solution was added
to make those cases pass.

A separate frozen candidate profile selects Qwen3-Coder-30B-A3B-Instruct,
Unsloth UD-Q2_K_XL GGUF, revision
`b17cb02dd882d5b6ab62fc777ad2995f19668350`, exact weight SHA-256
`3dee4686d756e8842aec638c5725666c76584edce76d71088732b52d2c5d7a45`.
The upstream model and quantization repository declare Apache-2.0. The 11,788,590,240
weight bytes plus explicit runtime/context reserves require an approximately
12.48 GiB software memory floor. This compressed candidate is chosen only to
fit existing CI capacity; quality is not assumed from model size or vendor
claims. It has to pass the same unchanged real functional and repair gates.
Preflight refuses insufficient RAM, disk or platform before downloading. No
new paid host is provisioned and the legacy 7B diagnostics remain separate.
Larger production quantizations still need their own capacity and qualification.
