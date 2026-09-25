# Local paid-path qualification

`cargo run --locked -p zk_llm_client --example local_paid_smoke` uses the existing
common envelope/commitment implementation and reference-client Actum development
ticket source. It requires explicit loopback `LOCAL_GATEWAY_URL`, `LOCAL_VIR_URL`,
`LOCAL_ACTUM_URL` plus disposable `LOCAL_VIR_API_KEY` and
`ACTUM_VERIFIER_BEARER_TOKEN`. It never generates production payment evidence.

The example decrypts a valid response, checks request binding and asks VIR to verify
its stored receipt; then re-encrypts the **same** request/ticket and requires
`double_spend`. Missing/malformed evidence, substituted content, wrong token class,
nonfinal evidence and wrong Actum audience are refused. The optional
`LOCAL_EXPECT_VERIFIER_UNAVAILABLE=true` mode requires encrypted `internal_error`
for a stopped verifier. No branch calls the compatibility route or a provider.

ZeroK's maintained `scripts/local-platform.sh smoke-paid` composes the local
services, faults/restarts its disposable verifier, and requires exactly one new
VIR file-store receipt across these requests. Run exclusively on an isolated local
stack; concurrent inference invalidates the count. Receipt counting observes
local execution; it is not a replacement for signature verification. No receipt
contents, tickets, private keys or prompts are persisted by this example.

Focused adapter tests also refuse malformed verifier replies, denied/nonfinal
replies, wrong echoed commitment/class, absent authorization ID and missing or
oversized evidence. Gateway behavior is unchanged. The existing #13 / draft #15
owns deeper route/spend/recovery/conformance changes; this harness neither merges
nor duplicates those implementations. Its current head restricts compatibility
to dummy-only demos; it does **not** supply a qualified authenticated compact
replacement for ZeroK's facade.

This proves local integration, not production finality, remote-model attestation,
SDK interoperability, cluster-wide replay, or power-loss/crash recovery. Historical
protocol constants, local Sled semantics and SDK pins are unchanged. Python's
cached-only pinned commit still prevents fresh remote SDK reproduction (#13).
