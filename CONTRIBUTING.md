# Contributing Guide

Thank you for contributing to Aegivion!

## Workflow
1. Fork the repository and create your branch from `main`.
2. Follow code standards and formatting.
3. Test your changes locally:
   - Backend: run pytest
   - Frontend: run npm run test / build (refer to [Node.js Setup](docs/NODE_SETUP.md) if needed)
4. Submit a Pull Request.

## Monorepo Structuring
* Maintain clean packages (`backend`, `frontend`, `security`, `ai`).
* Ensure shared schema definitions are updated across packages.
