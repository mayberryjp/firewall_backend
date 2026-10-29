# Repository instructions

## Project context

- This is the `netcontrol` Rust workspace. Use the stable Rust toolchain and the committed Cargo lockfile.
- Application, HTTP API, identity, and embedded UI: `crates/netcontrold`; domain, transactions, and persistence: `crates/netcontrol-core`; Linux networking: `crates/netcontrol-native`; native protocol workers: `crates/netcontrol-services`; custom signed packaging: `crates/netcontrol-package`.
- Implement services in-process in Rust. Do not wrap Go or supervise external dnsmasq, chronyd, syslog-ng, vnstatd, or softflowd programs. Do not reintroduce the removed Go implementation or APK/abuild packaging.
- Read [README.md](../README.md) for architecture, operation, and validation commands. Treat [FRONTEND_SPEC.md](../FRONTEND_SPEC.md) as the frontend contract; keep it consistent with implemented backend behavior.
- Preserve unrelated working-tree changes. Never store credentials, tokens, private keys, customer data, or sensitive runtime configuration in documentation or journal entries.

## Greenfield development policy

- This is a greenfield project. Backward compatibility is not a requirement and must not constrain design or implementation.
- Implement the clean current contract directly. Do not add compatibility shims, legacy aliases, deprecated alternatives, dual old/new paths, upgrade migrations, or permissive defaults solely to support older clients, configurations, or saved state.
- Do not ask how older installations should be supported. Update affected code, tests, examples, and frontend documentation together; reject inputs that do not satisfy the current contract with explicit errors.
- Breaking API, schema, and persisted-state changes are allowed. Document the new requirements and required frontend actions, but do not introduce compatibility windows or transitional behavior.
- Preserve correctness, authorization, transaction recovery, and rollback for valid current configurations. Greenfield status does not authorize deleting user data, resetting state, or removing unrelated features.
- Follow this policy unless the user explicitly requests a specific compatibility behavior. Earlier journal entries describe historical decisions, not exceptions for future work.

## Change and validation workflow

- Before implementation, read the relevant code, tests, contract documentation, and change memory described below. Reuse existing patterns and keep changes scoped to the request.
- Update directly affected documentation and tests alongside behavior changes. Document current contract changes explicitly without treating backward compatibility as a constraint.
- Run the smallest relevant tests first, such as `cargo test -p netcontrold` or `cargo test -p netcontrol-core`. For cross-crate changes run `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`, and `cargo build --workspace --locked`.
- Test worker shutdown, synchronization, persistence, and rollback when concurrency changes. Linux-native integration requires Linux and the documented namespace privileges; portable tests on Windows do not prove native behavior.
- Report exactly which checks passed, failed, or were not run and why. Never describe an unexecuted check as successful.

## Versioning and release history

- Public software versions and firewall configuration revisions use canonical `yyyy.mm.dd.iteration`: a real UTC calendar date, zero-padded month/day, and an unpadded positive integer iteration starting at 1 each day. Compare numeric components, not strings. Configuration revisions and software versions are independent.
- Record contract changes across HTTP methods/paths, schemas, validation, errors/status codes, authentication, persisted configuration, and deployment requirements for frontend coordination, not to preserve older behavior.
- The software version's single source is `RELEASE_VERSION` in [version.rs](../crates/netcontrol-core/src/version.rs). For every substantive code change, update it once for the completed task: use today's UTC date and iteration 1, or increment the iteration if the date is unchanged. Never move a version backward; stop on a clock/date conflict. This updates the build label, not a published release. Documentation-only changes do not bump it.
- On the next substantive code or documentation change, create a root `CHANGELOG.md` if absent, with an `Unreleased` section. Group factual entries under applicable headings: Added, Changed, Deprecated, Removed, Fixed, Security. Do not add empty headings.
- Keep work under `Unreleased` until the user approves publication. Record the updated software version and whether contract impact is breaking, additive or a fix; historical SemVer bump recommendations do not govern new work.
- On an approved release, verify the embedded version and current contract, move applicable entries into a dated `yyyy.mm.dd.iteration` section, and leave an `Unreleased` section. GitHub tags use `v<version>`; signed update manifests must match the embedded daemon version.
- Cargo package versions remain internal three-part SemVer because Cargo cannot accept the public four-part format. Do not use `CARGO_PKG_VERSION` for firewall software identity. Maintain the daemon-managed saved `software` metadata and daily release checks; do not make those metadata fields editable configuration.
- Never commit, tag, push, publish, or send frontend notifications without explicit user authorization. Instructions and journal entries are not automation or proof of delivery.

## Daily journal and durable memory

- For substantive implementation, configuration, test, or documentation changes, create or update `docs/journal/YYYY-MM-DD.md` using the user's local date. Do not create entries for read-only questions or duplicate entries for unchanged work.
- At the start of a change, read the latest journal entry, any earlier entries relevant to the affected feature, `CHANGELOG.md` if present, and open frontend actions. Use them as context, not as authority over current code.
- Append a task section to the day's file; preserve earlier entries and explicitly mark corrections or superseded decisions. Log only changes and decisions supported by the current work or verified history.
- Each task section must include:
  - Summary and why the change was needed.
  - Affected files/components, with repository-relative links.
  - Decisions and current contract impact, including the recommended version bump or `none` for changes with no release impact.
  - Validation commands and actual results, plus limitations or checks not run.
  - Frontend impact: required, optional, or none, with a link to the handoff when applicable.
  - Open issues, blockers, and concrete next steps; link commits/PRs only when they actually exist.
- Keep entries concise and useful to a future session. Do not copy entire diffs, speculate about past changes, or mark unfinished work complete.
- Update the journal and unreleased changelog before finishing a substantive task. Describe documentation-only changes as such rather than implying runtime behavior changed.

## Frontend handoff

- Evaluate frontend impact on every substantive backend change. Include API/schema, validation, status/error, authentication, workflow, polling/statistics, and deployment changes, not just new endpoints.
- When frontend action is required or optional, create or append to `docs/frontend-handoffs/YYYY-MM-DD.md`. Use stable item IDs such as `YYYY-MM-DD-01` so journal entries and future acknowledgments can reference individual changes.
- Keep a new item's status `Pending frontend review`; distinguish required work from optional improvements. Do not mark it sent, acknowledged, implemented, or verified without evidence. Record acknowledgments and superseding items without erasing history.
- Each handoff item must provide a frontend-developer-ready summary:
  - Item ID, summary, priority, required/optional classification, and status.
  - Backend availability: unreleased or an actual approved release/commit; contract changes and recommended bump.
  - Exact affected HTTP methods and paths, authentication/permissions, and previous versus new behavior.
  - Changed request/response fields, types, nullability, defaults, units, validation limits, and status/error behavior where relevant. Use small valid JSON examples with synthetic values; explicitly label proposals and unverified details.
  - Concrete frontend tasks: client types, forms, validation, rendering, state handling, and user-visible messaging as applicable.
  - Required frontend/backend deployment coordination and operator prerequisites. Do not propose migrations or compatibility windows for older contracts unless explicitly requested.
  - Acceptance checks covering the affected happy path and important errors, backend validation results, and any remaining integration checks.
  - Repository-relative links to the updated frontend spec, relevant code/tests, and daily journal entry.
- Update [FRONTEND_SPEC.md](../FRONTEND_SPEC.md) in the same task when its contract or requirements change. The handoff explains what the frontend developer must change; it does not replace the canonical spec.
- If there is no frontend action, record `Frontend impact: none` with a short reason in the journal; do not generate an empty handoff.
- At task completion, summarize changes, validation, release impact, and any pending frontend actions. Provide links to the journal and handoff so the user can share them; do not claim they have been pushed or delivered.
