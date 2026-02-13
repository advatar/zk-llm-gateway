```md
# AGENTS

## Purpose

This repository uses Codex CLI as an autonomous coding agent. These instructions define the required workflow and safety rules for Codex and humans.

---

## Collaboration

- Other agents are working in the same repo. Mind your own business only.

---

## Tooling Notes

- When reading `.xcresult` files, use `xcrun xcresulttool get object --legacy` (plain `get` is deprecated).
- When running Vitest, always use `vitest run` (avoid watch mode hangs).
- Use `python3` instead of `python`.

---

## Agent skills and AI docs maintenance (required)

This repo uses repo-scoped Codex skills under `.codex/skills/` (checked into git). Skills are selected using their `name` + `description`, and detailed instructions are only loaded when invoked.

Always keep these files accurate when your change affects behavior, workflows, or structure:

- `docs/ai/system_map.yaml` (service ownership, ports/health, key dependencies)
- `docs/ai/dev_commands.yaml` (canonical run/test/smoke/stop commands)
- `.codex/skills/*-build/SKILL.md` (feature/build workflow)
- `.codex/skills/*-debug/SKILL.md` (incident/triage workflow)

Update triggers (non-exhaustive):

- You add/rename/remove a service under `services/`
- You change docker compose services, ports, health endpoints, or startup order
- You change how to run tests, smoke checks, migrations, or local dev
- You introduce new error conventions (error codes, retry rules, timeouts)
- You add new observability conventions (trace/log field names)

Usage guidance:

- For feature work/refactors, explicitly invoke the build skill (e.g. `$<repoPrefix>-build`).
- For failures/incidents (e.g. 503), invoke the debug skill (e.g. `$<repoPrefix>-debug`).

Safety:

- Never write secrets into skills or docs.
- Never run destructive Docker commands (`docker system prune`, `docker volume rm`, `docker compose down -v`, etc).
- Keep diffs minimal; prefer targeted fixes over broad refactors.

---

# Concurrency Rules for Code Generation

This project uses Swift 6–style strict concurrency (`Strict Concurrency = Complete`, `Approachable Concurrency = Yes`, `Default Actor Isolation = MainActor`).
All generated or modified code must follow these rules to avoid runtime crashes on older macOS versions and ensure forward-compatible behavior.

---

## Working Rules

- Always `git add` and commit after creating or editing files. Use clear, descriptive commit messages.
- Verify builds locally before claiming completion for any change.
- For infra-only changes, run a full service health check (`scripts/health-check-services.sh`) as the equivalent of a full build.
- Record user validation steps in `VALIDATE.md` so they can be handled async but never commit this file - it is transient and user specific.
- After assessing a request, add or update related tasks in `STATUS.md` before implementation.
- Keep going without pausing for confirmation; only ask when a decision is blocking progress.
- Never stage, commit, or alter files you did not edit for the task; leave unrelated changes for their owner.
- Other agents may be working in the same repo; mind your own business and avoid unrelated investigation or edits.

## Windows Port Preferences

- For Windows deliverables, plan to bundle Git + OpenSSH even if system Git is expected.

---

## 1. Do not assume which queue or actor system APIs use

System frameworks such as `ASWebAuthenticationSession`, `URLSession`, `NSXPCConnection`, notifications, delegates, and similar APIs do not guarantee the actor or queue they invoke callbacks on.

Never mark these callbacks or delegate methods as `@MainActor` or actor-isolated.

Rule: all system callbacks must be treated as non-isolated entry points.

---

## 2. Always hop to the correct actor explicitly

If a callback needs to perform main-actor or other actor-isolated work, explicitly hop inside the callback:

```swift
func callback(url: URL?) {
    Task { @MainActor in
        await handleCallback(url)
    }
}
```

or for actor-isolated types:

```swift
nonisolated func sessionDidComplete(url: URL?) {
    Task { [weak self] in
        guard let self else { return }
        await self.process(url)
    }
}
```

This avoids violating runtime actor preconditions across macOS versions.

---

## 3. Auth flows must not rely on the framework delivering callbacks on the main actor

The project uses `ASWebAuthenticationSession`. Its completion handler must:

- be non-isolated,
- do only synchronous error/URL extraction,
- then hop back to async/actor-isolated logic using `Task`.

Example pattern:

```swift
private func waitForAuthCallback() async throws -> URL {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.main.async {
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: scheme
            ) { callbackURL, error in
                if let url = callbackURL {
                    continuation.resume(returning: url)
                } else {
                    continuation.resume(throwing: error ?? AuthError.noCallback)
                }
            }

            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true

            guard session.start() else {
                continuation.resume(throwing: AuthError.unableToStart)
                return
            }
        }
    }
}
```

Do not wrap async work inside the session’s completion handler.

---

## 4. All UI work must occur on the main actor

When updating UI, use:

```swift
Task { @MainActor in
    // UI code
}
```

No generated code may assume implicit main-actor execution unless inside a function explicitly annotated with `@MainActor`.

---

## 5. No escaping closure may inherit `@MainActor` unintentionally

Never create an escaping closure inside a `@MainActor` function unless the closure is explicitly marked:

```swift
nonisolated(unsafe)
```

or moved into a non-isolated helper.

This prevents inadvertent main-actor isolation from propagating into system APIs that call the closure on background queues.

---

## 6. Actor-isolated properties and methods must not be accessed from callbacks without an explicit hop

Incorrect:

```swift
@MainActor
func handle(url: URL) { ... }

// session completion handler:
self.handle(url) // ❌ may crash on macOS 14.x
```

Correct:

```swift
// session completion handler:
Task { @MainActor in
    await self.handle(url)
}
```

---

## 7. All concurrency warnings are errors

Because Strict Concurrency Checking = Complete, any warning indicates code that may crash at runtime on some OS versions. Generated code must resolve all such diagnostics.

---

## 8. Always assume the minimum supported macOS behaves strictly

Behavior differences in Apple frameworks between macOS versions must be assumed. Generated code must rely only on actor hops and explicit queue control, never on OS-specific callback behavior.

## Debugging UI mutation warnings

- SwiftUI warning “Publishing changes from within view updates is not allowed” usually means state was mutated during the render pass (e.g., bindings that set shared state synchronously). Fix by deferring the write onto the main queue (`DispatchQueue.main.async { … }`) or moving the work into a `.task`/`.onAppear` that runs outside the view update. Custom bindings with async setters are a safe pattern for pickers/route changes.
```
