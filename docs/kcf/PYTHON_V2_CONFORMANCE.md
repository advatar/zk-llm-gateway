# KCF-08 first executable interoperability slice

**Status:** native qualification BLOCKED locally; not a production-ready release.

Gateway issue #13 covers route confinement, prepared requests, replay and SDK
qualification. This change implements the native interoperability harness only;
it does **not** close the compatibility-route bypass or other release blockers.

## Source finding and SDK change

Gateway main `e4b31b449211906f31f1d529c4257388627ba5aa` uses envelope v2, while
Python SDK main `30e3e7db316b02a934ad358a145676263e280130` emits v1. The new
[Python draft PR #2](https://github.com/advatar/zk-llm-gateway-python-sdk/pull/2)
adds an opt-in prepared-request and v2 transport API. Legacy helpers remain v1
and must not be used as an implicit fallback.

The Python implementation passes 60 focused tests, including sync/async HTTP on
actual loopback sockets. Those tests use a separately written Python reference
server, not native Rust. This harness exists to prevent confusing reference-model
success with cross-language compatibility.

## Native check

With Cargo and Python dependencies installed, and the SDK PR checked out separately:

```bash
python3 scripts/qualify_python_v2.py --sdk-dir ../zk-llm-gateway-python-sdk
```

The command builds `common/examples/prepared_v2_bridge.rs` with Cargo `--locked`
and a disposable target directory. For 30 positive cases it sends Python-generated
envelopes to the **actual Rust common crate**, verifies the decrypted payload and
native Actum request commitment, and decrypts the Rust-generated response in Python.
It covers five classes and six supported temperature forms. Four substitution
cases must terminate with ordinary rejection, not a crash. All 34 observations
are needed for the scope-specific `qualified` result.

The bridge is a stdin/stdout synthetic fixture tool, not a network inference
server. It performs no issuer, finality, provider, clinical or TEE verification.
Its request checks are harness assertions, not changes to the gateway HTTP handler.
No public endpoint, model credentials or patient data are needed. The test key is
public fixture material and must never be used in deployment.

## Evidence and limits

Locally executed on 25 September 2026:

- Python qualifier syntax compilation.
- Two unit tests of fail-closed missing-tool/source behavior.
- Running the qualifier returned exit code 2, `status=BLOCKED`,
  `reason=cargo_unavailable`, `native_cases_executed=0`, `qualified=false`.

Native Rust compilation, rustfmt, workspace tests and the 34-case native matrix
were **not run** in this container. No GitHub CI was enabled or dispatched. Run
those gates on the existing approved development host before relying on the result.
A future native pass qualifies this message/numeric subset only, not the entire
HTTP service, payment authority, all SDKs, full-model CFI or clinical deployment.

## Remaining issue #13 gates

Compatibility route confinement; honest readiness; HTTP request/envelope identity
validation; reserved provider-field policy; verifier response bounds; ambiguous
spend/retry/crash recovery; durable multi-replica replay; broader canonical numeric
support; all four SDKs; and deployment ingress/egress tests remain open. No current
production/privacy claim is widened by this change.
