
# Contributing Guide

Thank you for contributing to Aegivion!

## Core Principles & Engineering Standards
- **Review Specs First:** Read relevant specifications ([Docs Index](docs/README.md) and [Module Ownership](docs/11-module-ownership.md)) and current project status before editing.
- **Contract Integrity:** Preserve module ownership and API/data contracts ([API Contracts](docs/03-api-contracts.md), [Event & Data Contracts](docs/04-event-and-data-contracts.md)).
- **Rigorous Testing:** Add tests for behavior and failure paths. Record actual test commands and test outputs.
- **Documentation Hygiene:** Update docs whenever behavior, schema, or configuration changes.
- **Secret & Data Hygiene:** Never commit credentials, tokens, customer data, or generated secret files.
- **Claim Integrity:** Do not claim live cloud integration or production readiness without verified test evidence.
- **Auditable AI Changes:** Keep AI-assisted code changes scoped, modular, reviewable, and auditable.

## Workflow
1. Fork the repository and create your branch from `main`.
2. Follow code standards and formatting.
3. Test your changes locally:
   - Backend: run `pytest`
   - Frontend: run `npm run test` / `npm run build` (refer to [Node.js Setup](docs/NODE_SETUP.md) if needed)
4. Submit a Pull Request.

## Monorepo Structuring
* Maintain clean packages (`backend`, `frontend`, `security`, `ai`).
* Ensure shared schema definitions are updated across packages.

