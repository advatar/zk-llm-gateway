# Reference-client boundary evaluation

Tracking: [#16](https://github.com/advatar/zk-llm-gateway/issues/16),
[#17](https://github.com/advatar/zk-llm-gateway/issues/17), foundation PR #18.
Source review: `201feba722f9190c8685faa1473731627a47e8ac`, based on main
`e4b31b449211906f31f1d529c4257388627ba5aa`.

**REFERENCE_CLIENT_POLICY_BOUNDARY_ACCEPTABLE.** The current crate/module
separation is sufficient; no cross-repository extraction or new framework is
justified by this review. This is a dependency/ownership decision, not production
assurance or complete local integration qualification.

## Module inventory

| Module | Classification | Why it remains |
| --- | --- | --- |
| `common/src/{envelope,token,types,zk}.rs` | PROTOCOL_TEST_REQUIRED | Wire types, encryption/transcript binding, padding/classes, ticket and verifier contracts. Chat messages are bounded request input, not persistent personal-memory schema. |
| `client/src/agent.rs` protocol calls | PROTOCOL_TEST_REQUIRED | Constructs request, obtains authorization ticket, encrypts, calls configured gateway/relay and decrypts. Composition may use client policy but server never imports it. |
| `client/src/tickets.rs` | PROTOCOL_TEST_REQUIRED | File tickets plus explicit dummy and Actum development-ticket sources. Production authority remains Actum, not development ticket construction. |
| `client/src/session.rs` | PERSONAL_AGENT_POLICY | Local history, memory items, summary and redaction state persistence; not server replay storage. |
| `client/src/memory_store.rs` | PERSONAL_AGENT_POLICY | Local search/BM25-style retrieval; not required by envelopes, authorization or SDKs. |
| `client/src/local_ai.rs` | PERSONAL_AGENT_POLICY | Optional local summary update; caller chooses local AI endpoint. No gateway summary policy. |
| `client/src/prompt.rs` | PRIVACY_REFERENCE_USEFUL with PERSONAL_AGENT_POLICY selection | Demonstrates minimized context assembly; choice of history/summary/memory belongs to consumer. |
| `client/src/redaction.rs` | PRIVACY_REFERENCE_USEFUL | Local redaction and explicit terms demonstrate selective disclosure; retain independently of memory ownership. |
| `client/src/manager.rs` | PERSONAL_AGENT_POLICY | Local multi-session lifecycle/storage separation; not product accounts or wire requirements. |
| `client/src/api.rs` | PERSONAL_AGENT_POLICY operator interface | Optional local HTTP sessions/memory/chat API. Privacy-sensitive local interface; distinct from gateway API. SSE chunks are simulated after full response, not provider-token streaming. |
| `client/src/main.rs` REPL/CLI | PROTOCOL_TEST_REQUIRED entry point; PERSONAL_AGENT_POLICY conveniences | Small operator/protocol demonstration plus optional interactive context management. Neither is a dependency of server crates. |

No inventoried client module is proven LEGACY_DEAD. Retain behavior. OpenMind/BrIAn
or another context system may eventually supply bounded context, but no such
integration or extraction is implemented or required here.

## Dependency evidence

The five workspace manifests and source imports establish:

```text
application / SDK / reference client
                |
                v
          gateway protocol
                |
       +--------+--------+
       v                 v
  Actum adapter       VIR/provider
       |                 |
       v                 v
ActiveChain finality  model execution/evidence

client -> common
relay -> common
gateway -> common + verifier_halo2
common -> external protocol/crypto libraries
```

No `gateway -> client`, `relay -> client` or `common -> client` dependency exists.
No ZeroK account, UI, conversation database, LiveKit, memory/RAG or other consumer
package is imported by server/security crates. **PRODUCT_COUPLING = 0** in the
reviewed server dependency graph. Product composition may remain in ZeroK.

## ZeroK-reference search classification

- `common/src/types.rs`: `ACTIVECHAIN-ZEROK-INFERENCE-AUTHORIZATION-V1` is
  PROTOCOL_COMPATIBILITY, preserved byte-for-byte.
- `gateway/src/actum.rs`: `zerok:test` audiences are TEST fixtures, not runtime
  audience defaults. Production `ACTUM_AUDIENCE` is explicit configuration.
- `client/src/{main,tickets}.rs`: ZeroK Docker-local development fixture comments
  are LOCAL_DEMO, not production authorization.
- `relay/src/main.rs`: `proxy.zerok.cloud` appears in served documentation/OpenAPI
  examples (DOCUMENTATION), not a required forwarding destination or account
  dependency. Relay forwarding configuration remains independently usable.
- README and architecture references are DOCUMENTATION.

## SDK inspection and reproducibility

All four pins are unchanged:

| SDK | Pinned revision |
| --- | --- |
| Python | `20d08bb7af1853db4d6c31067750025c0909672c` |
| Rust | `19da2dcf658ba2b1f10e00ebf6f4960f1b678400` |
| TypeScript | `dc325471d96d3b89c005d2881db06835747899cf` |
| Swift | `555092ca1dd222803953b095d9a7f176f2743bc7` |

SDK source modules implement clients, crypto, padding, token classes, tickets,
redaction and application adapters. No persistent RAG/session/memory or ZeroK
account dependency was found. Swift `URLSession` is HTTP transport, not personal
session storage. Redaction is a protocol-independent privacy convenience.

Fresh `git submodule update --init --recursive` failed because the Python remote
would not serve its pinned commit (`not our ref`). The original local checkout
still had the exact object, so the audit populated the mission SDK worktrees from
that local object store, without changing any pin. This permits source inspection
but **does not resolve fresh-clone reproducibility**. Restore remote availability
or qualify a deliberate pin migration in the owning SDK workstream; do not silently
substitute current SDK main. SDK suites were not run: no SDK/API behavior changed.

## Authority and remaining qualification

- `gateway/src/actum.rs` requires explicit URL, credential and audience; rejects
  missing/oversized evidence, mismatched commitment/class, non-finalized replies,
  unavailable verifier and malformed replies. These are adapter contract checks,
  not independent blockchain finality verification. Normative contract unchanged.
- Dummy verifier remains explicit development opt-in with a loopback guard and
  explicit Docker-demo override. Halo2 remains unimplemented/fail-closed.
- VIR owns inference receipts. Gateway provider forwarding must not be advertised
  as independent cryptographic verification of remote model execution. No new
  receipt enforcement was added by this evaluation.
- Relay hides the direct client IP from gateway; content/timing and other
  correlations remain. Provider receives selected plaintext context.
- TEEs/confidential GPUs/zkML remain future possibilities, not qualified guarantees.

Workspace tests do not substitute for the required ZeroK + gateway smoke, replay
second-use refusal, negative authorization matrix or VIR receipt qualification.
The continuation retains a thin ZeroK authentication facade and retires compromised
historical deployment state. Local qualification now uses the dedicated
[paid-path example](LOCAL_QUALIFICATION.md); production/SDK assurance remains separate.

The existing [#13](https://github.com/advatar/zk-llm-gateway/issues/13) and
[draft PR #15](https://github.com/advatar/zk-llm-gateway/pull/15) already track
route confinement and prepared-request SDK conformance. Their unmerged behavior
is not part of this audit candidate. Coordinate ZeroK compatibility/auth migration
with that work; do not duplicate it or assume its API is on main.
