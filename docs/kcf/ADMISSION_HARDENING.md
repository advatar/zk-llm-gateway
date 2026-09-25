# KCF-08: gateway admission and conservative replay handling

Date: 25 September 2026. Status: **implemented source; native validation BLOCKED**.
This continuation extends draft PR #15 and issue #13. It changes production
handlers, unlike the first interoperability-harness-only commit. Do not merge or
deploy it until the native gates below pass on an approved development host.

## What changes

### No default unpaid alternative

`POST /v1/infer` is the inference route registered by default. `GET /v1/models`
and `POST /v1/chat/completions` are absent (404), including in a normal Docker
start. A defensive check inside `compat_proxy` also rejects internal calls while
compatibility is disabled.

The new `GATEWAY_ENABLE_COMPAT_LOCAL_DEMO=true` flag explicitly enables the old
unpaid routes **only** with the dummy verifier, explicit dummy opt-in and a
loopback listen address or the existing isolated Docker-demo bind override. It
is rejected with Actum and with Halo2. The flag is not an enterprise access mode
and must never be exposed publicly. Do not put it in production configurations.
Existing ZeroK local smoke scripts using compatibility routes need an explicit
isolated-demo configuration; the paid smoke should continue using `/v1/infer`.

`/healthz` remains liveness only, and `/v1/pubkey` publishes an encryption key.
Neither proves payment-service readiness, a real ZK verifier, attestation or
clinical/provider approval. Dynamic readiness remains open under issue #13.

### Checks before verification, reservation or provider I/O

The HTTP body is capped at 128 KiB. The encrypted ciphertext must have the exact
size for its declared class. Cryptographic transcript authentication is unchanged.
After decryption, request ID must match the authenticated envelope ID, model and
messages must be nonempty, class consistency is checked, and conflicting
structural/provider budget fields are rejected. Alternate completion-budget
knobs (`max_completion_tokens`, `max_output_tokens`), embedded credentials,
`n` other than integer 1, and `store` other than boolean false are refused.

Ordinary supported options such as `response_format` remain forwarded. This is
not full provider-option validation or a promise about a provider's default
retention. The exact request commitment and Actum verifier contract are unchanged.
The verifier's returned class must match the request before reservation.

Malformed *decrypted* requests receive encrypted, categorical errors bound to the
envelope request ID. Parser details and upstream body text are not reflected.
Malformed unauthenticated envelopes receive categorical HTTP errors; they cannot
be assumed to have an established response encryption context.

### No automatic reuse of ambiguous reservations

The previous implementation could release a reservation after a provider error
or replace a pending entry after a timeout. Neither establishes that inference
never happened. The new conservative behavior is:

1. Durably reserve an absent replay key before provider dispatch.
2. Refuse any existing record, including legacy pending, unknown or malformed data.
3. Preserve the reservation after failure, timeout, cancellation or lost response.
4. Mark spent only along the known successful provider-response path.

`NULLIFIER_PENDING_TTL_MS` is retained for configuration compatibility but is
**ignored**. Pending entries never become reusable by age. The legacy
`double_spend` error covers both reserved and consumed tickets; it is not evidence
that the user received a successful response.

This favors duplicate prevention over automatic credit recovery. A reservation
may remain even if no provider work actually occurred (for example, a crash just
before dispatch). There is no automatic refund, retry, status-reconciliation or
safe-reset API in this slice. Such a mechanism needs a separately qualified
payment/provider contract. Never delete the replay database to recover credits.

This is not an exactly-once guarantee. Storage loss, rollback, independently
configured replicas, provider/internal transport behavior and upstream side effects
need their own evidence. Acknowledged application-level dispatches are not retried
by a new gateway request after an ambiguous failure. Existing local Sled deployment
assumptions remain; distributed replay and power-loss qualification are still open.

### Bounded responses and fixed destination

The provider HTTP client does not follow redirects or inherit environment proxies.
It requests identity encoding. Responses are read incrementally under a byte cap;
non-identity content encoding and oversized bodies are rejected. Error bodies are
not copied into logs or client responses. Transport/network destination approval
and confidential execution remain separate workstreams.

If wrapping an otherwise bounded provider response would exceed the encrypted
response class, the gateway sends an encrypted `response_too_large` error and
retains its replay record. It does not truncate a clinical answer, refund the
ticket, retry the provider or expose a plaintext encryption-error trace.

## Native tests added, not executed here

`gateway/src/admission_tests.rs` contains 17 test functions. They use the actual
router/HTTP handler, real loopback servers, a synthetic verifier and observed
provider invocation counters. Cases cover default-off routes, direct internal
compatibility calls, explicit demo control, paid positive/replay, request-ID
substitution, encrypted parser errors, class sizes, reserved options, valid option
preservation, verifier failure/wrong class, upstream failures, wrapped-response
overflow, concurrent duplicate calls, redirects, body caps and corrupt replay
records. The existing stale-pending test now requires refusal and unchanged data.

The fixtures do not establish real Actum finality, TEE execution or healthcare
qualification. An authored test is not a passing test.

Run from the full gateway checkout on a host with Cargo:

```bash
cargo fmt --all --check
cargo test --locked -p zk_llm_gateway admission_tests:: -- --test-threads=1
cargo test --locked --workspace
python3 scripts/qualify_python_v2.py --sdk-dir ../zk-llm-gateway-python-sdk
```

Use the matching Python draft PR #2 revision. Do not substitute a mock binary for
the native bridge or mark missing Cargo as a skip/pass. The current container
returned `BLOCKED`, `cargo_unavailable`, zero native conformance cases and
`qualified=false`. No Rust compiler, rustfmt or gateway behavioral test was run.

## Python companion changes

The prepared Python API now rejects matching budget/credential/storage options
before issuance and treats injected HTTPX transports as caller-owned. Per-call
HTTP clients remain fresh to avoid cookie carry-over, but closing them no longer
closes a host-owned transport needed by later calls. The caller closes its transport
explicitly. The 79 focused tests pass locally (including the existing real loopback
round trips). That is Python/reference evidence, not native interoperability.
Legacy v1 APIs, the full current-main SDK suite and the supported-Python matrix
remain outside this continuation's verification boundary.

## Migration and rollback

Keep compatibility disabled in deployment manifests. Stop traffic before changing
binaries or replay-state handling. Preserve pending entries and backups; an older
binary can resume the old unsafe-expiry behavior. No rollback is claimed safe
merely because it is possible to run the older binary. Record the database/commit
pair and reconcile outstanding outcomes before any approved change.

Kline task ownership, source admission, real confidential payload termination,
enterprise blind issuance, full-model CFI and controller deployment approval are
not implemented here. No main branch, SDK pin, deployed service or CI policy was
changed by this draft continuation.
