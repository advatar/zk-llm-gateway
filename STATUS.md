# Status

## Active Task: Align gateway endpoints and payloads with zk-llm-gateway-rust-sdk

- [completed] Extract SDK contract (envelope schema, /v1/infer payload, expected decrypted response shape).
- [completed] Implement gateway compatibility for SDK envelope/request/response formats while preserving existing client flow.
- [completed] Add missing public metadata endpoint(s) required by SDK/docs.
- [completed] Update relay forwarding compatibility if needed for SDK envelope shape.
- [completed] Build/test workspace and verify gateway crate behavior.
- [completed] Document validation steps in VALIDATE.md (do not commit).
- [completed] Commit all work, including existing uncommitted relay edits, per user request.
