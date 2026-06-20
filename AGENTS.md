# AGENTS.md

## How to work in this repo

When I ask for a change, implement it directly in the codebase.

## Default behavior

- Do not ask follow-up questions unless the task is blocked.
- Inspect the relevant files first.
- Make the smallest safe change.
- Follow existing code style and patterns.
- Do not add new dependencies unless necessary.
- Do not rewrite unrelated code.
- Do not explain while working unless needed.

## Security and networking

- In the established VPN tunnel, each firewall must only have access to the dashboard/control-plane service and must not be able to access any other device or service in the dashboard network.

## Validation

Before finishing:

- Run the relevant tests, typecheck, lint, or build command if available.
- Fix any errors introduced by the change.
- If checks cannot be run, explain why.

## Final response format

When finished, respond only with:

1. Files changed
2. Commands run
3. Result of checks
4. Whether it is ready to commit
5. Anything I still need to do

## Git

Do not commit or push unless I explicitly ask.
Prepare the repo so I can review, commit, and push to GitHub.
