# Development and Release Workflow

## AI-assisted loop
1. Read status and relevant specifications.
2. Inspect existing code/tests.
3. Identify dependencies and bounded scope.
4. State intended files and acceptance criteria.
5. Implement without unrelated refactoring.
6. Run focused tests, then broader tests where practical.
7. Report exact commands and actual outputs.
8. Update documentation/status.
9. Stop and report blockers instead of inventing success.

## Controls
Keep changes reviewable; preserve contracts; do not weaken/delete tests to pass; do not silently replace production services with in-memory/SQLite; never commit secrets/customer data; review migrations; justify dependency changes; require review for cloud mutation, auth, tenant, and AI/RAG security changes.

## Release evidence
Version/commit, changelog, test summary, migrations, configuration changes, known issues, rollback plan, deployment verification, and approver.
