# Status

## Active Task: Fix actionable placeholder review findings

- [pending] Remove dummy-by-omission behavior from the CLI ticket source.
- [pending] Keep Halo2 verification fail-closed and make non-production limits explicit.
- [pending] Add or update tests for explicit dummy-ticket opt-in where feasible.
- [pending] Run `cargo fmt --all` and `cargo test --workspace`.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/8

## Completed Task: Extensive placeholder and mock code review

- [completed] Review placeholder, mock, stub, dummy verifier, fake data, TODO/FIXME/HACK, and demo-only code paths.
- [completed] Manually inspect high-risk gateway, relay, verifier, crypto, redaction, ticket, token, and SDK integration paths.
- [completed] Run feasible local verification and report findings with file/line references.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/7
  - Findings posted: https://github.com/advatar/zk-llm-gateway/issues/7#issuecomment-4826507804
  - Verification:
    - `cargo test --workspace` passed.

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
