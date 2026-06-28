# Status

## Active Task: Extensive placeholder and mock code review

- [pending] Review placeholder, mock, stub, dummy verifier, fake data, TODO/FIXME/HACK, and demo-only code paths.
- [pending] Manually inspect high-risk gateway, relay, verifier, crypto, redaction, ticket, token, and SDK integration paths.
- [pending] Run feasible local verification and report findings with file/line references.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/7

## Completed Task: Remediate REVIEW.md security findings

- [completed] Fail closed on dummy/ZK verifier paths, align SDK padding, and bind request freshness into encrypted transcripts.
- [completed] Harden replay durability, CORS defaults, privacy timing defaults, and SDK redaction guarantees.
- [completed] Run workspace and SDK verification.
  - Verification:
    - `cargo fmt --all`
    - `cargo test --workspace`
    - `python3 -m pytest` in a temporary virtualenv for `zk-llm-gateway-python-sdk`
    - `cargo test` in `zk-llm-gateway-rust-sdk`
    - `npm test` and `npm run typecheck` in `zk-llm-gateway-typescript-sdk`
    - `swift test` in `zk-llm-gateway-swift-sdk`

## Active Task: Add client SDK repository links to README

- [completed] Add direct GitHub links for each client SDK repository in `README.md`.
- [completed] Refresh `VALIDATE.md` with docs validation steps.
- [completed] Run local verification and commit the docs update.

## Active Task: Persist Swift SDK ticket-file consumption

- [completed] Make `FileTicketSource` persist consumed tickets and support appending purchased tickets.
- [completed] Add Swift SDK tests for persisted consumption and append behavior.
- [completed] Run `swift test` in `zk-llm-gateway-swift-sdk` and commit the scoped SDK fix.
  - Verification:
    - `swift test` in `zk-llm-gateway-swift-sdk` passed 14 tests.
