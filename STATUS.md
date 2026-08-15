# Status

## Active Task: Publish the ZeroK visual system guide

- [completed] Add a prominent README link to the canonical visual PDF in `advatar/ZeroK`.
- [completed] Describe the architecture, privacy, Actum authorization, replay, VIR receipt, and trust-boundary coverage.
- [completed] Validate the documentation-only change and consolidate it to `main`.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/12
  - Verification:
    - Root README relative links resolve.
    - `git diff --check` passes.
    - `cargo fmt --all --check` passes.
    - `cargo test --workspace` passes all 29 tests.

## Active Task: Align the Actum adapter with ActiveChain Digest384

- [completed] Replace the temporary 32-byte request commitment with ActiveChain's 48-byte
  Digest384 convention while preserving deterministic request binding.
- [completed] Update clients, verifier response validation, tests, and the published adapter contract.
- [completed] Qualify the gateway against the ActiveChain-owned verifier service and ZeroK Docker stack.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/11
  - Verification:
    - `cargo test --workspace`.
    - ZeroK Docker images build with the ActiveChain-owned verifier service.
    - Encrypted paid inference smoke completes through gateway -> ActiveChain -> VIR.

## Active Task: Integrate Actum payment authorization and settlement evidence

- [completed] Replace the production ZK-ticket assumption with a versioned Actum authorization verifier.
- [completed] Bind paid inference authorization to the exact request, merchant audience, model, token class, and replay identity.
- [completed] Add fail-closed HTTP verification, bounded evidence handling, and production-safe configuration.
- [completed] Add positive, malformed, substitution, replay, and verifier-unavailable coverage.
- [completed] Document and verify the Docker-local Actum-backed workflow.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/10
  - ActiveChain service dependency: https://github.com/advatar/ActiveChain/issues/786
  - Verification:
    - `cargo fmt --all --check`.
    - `cargo test --workspace`.
    - ZeroK Docker images for `actum-verifier-dev` and `zk-gateway` build successfully.
    - Encrypted client -> gateway -> Actum adapter -> VIR -> client smoke completes.

## Completed Task: Add container deployment support for local gateway demos

- [completed] Add a Dockerfile for the `zk_llm_gateway` binary.
- [completed] Add an explicit local-demo-only dummy verifier non-loopback guard for Docker bridge demos.
- [completed] Add unit tests for the bind-policy guard.
- [completed] Update README deployment notes.
- [completed] Run local verification.
  - GitHub issue: https://github.com/advatar/zk-llm-gateway/issues/9
  - Verification:
    - `cargo fmt --all`.
    - `cargo test --workspace`.
    - `docker build -f Dockerfile.gateway -t zk-llm-gateway:local .`.
    - ZeroK laptop stack `./scripts/local-platform.sh smoke` with `zk-gateway` routed to VIR.

## Completed Task: Fix actionable placeholder review findings

- [completed] Remove dummy-by-omission behavior from the CLI ticket source.
- [completed] Keep Halo2 verification fail-closed and make non-production limits explicit.
- [completed] Add or update tests for explicit dummy-ticket opt-in where feasible.
- [completed] Run `cargo fmt --all` and `cargo test --workspace`.
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
