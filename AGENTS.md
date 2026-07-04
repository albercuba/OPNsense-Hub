# AGENTS.md

## How to work in this repo

When I ask for a change, implement it directly in the codebase.

## Default behavior

- Do not ask follow-up questions unless the task is blocked.
- Inspect the relevant files first.
- Do not invent file paths, APIs, command flags, or framework behavior. Inspect first.
- Make the smallest safe change.
- Prefer small, reviewable diffs. Avoid broad refactors unless explicitly requested or required to safely complete the change.
- Follow existing code style and patterns.
- Before introducing a new pattern, reuse the closest existing implementation in the repo when possible.
- Do not add new dependencies unless necessary.
- When changing dependency versions or adding pins, explain why and note any operational follow-up needed.
- Do not introduce deprecated APIs, packages, configuration patterns, or framework hooks. Prefer current supported patterns and remove deprecated usage when making related changes.
- When replacing deprecated APIs or config, prefer the current supported migration path with the smallest behavior change.
- Do not rewrite unrelated code.
- Do not explain while working unless needed.

## Security and networking

- In the established VPN tunnel, each firewall must only have access to the dashboard/control-plane service and must not be able to access any other device or service in the dashboard network.
- Do not weaken security defaults for convenience in production paths. If a less secure setting is needed for development, keep it explicit and documented.

## UI semantics

- For backup and restore actions, communicate intent clearly through color and emphasis.
- Use green or teal tones for Backup actions to signal safe, proactive preservation.
- Use amber or orange tones for Restore actions to signal intentional recovery.
- Avoid red for Restore unless the action is actually destructive.
- Keep these semantics consistent with the existing OPNsense Hub visual style rather than introducing a different design language.
- Match existing spacing, typography, component sizing, and interaction patterns unless a change is requested.

## Validation

Before finishing:

- Run the smallest relevant test, typecheck, lint, or build command first, then broader validation if needed.
- Fix any errors introduced by the change.
- If checks cannot be run, explain why.

## Final response format

When finished, respond only with:

1. Files changed
2. Commands run
3. Result of checks
4. Whether it is ready to commit
5. Anything I still need to do

## Debugging and maintenance

- When debugging, prefer fixing the root cause instead of adding cosmetic or defensive patches without evidence.
- When behavior, env vars, or setup expectations change, update README, docs, and example config files in the same task.

## Git

- Do not commit or push unless I explicitly ask.
- Prepare the repo so I can review, commit, and push to GitHub.
- Whenever code, documentation, configuration, templates, or assets are changed, include a suggested Conventional Commit message in the final response, such as `feat: add company management table`, `fix: restrict vpn tunnel access`, or `docs: update agent instructions`.
