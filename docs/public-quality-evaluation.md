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
automatic inference retries. The CI harness checks honest measurement even if a
candidate fails; only `regressionGatePassed: true` means all nine observed cases
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
