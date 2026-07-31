# Technical Decisions & Architecture

## 1. Authentication
* **Decision**: OAuth2 with JWT tokens.
* **Details**: Backend generates short-lived JWT access tokens for API requests. User credentials (email/password) are exchanged at the `/api/v1/auth/token` endpoint. Refresh tokens will be introduced in Day 2/3.

## 2. API Versioning
* **Decision**: URI path-based versioning (`/api/v1/...`).
* **Details**: This keeps API versioning explicit and straightforward, making it easy to route different versions through the gateway if needed later.

## 3. CI/CD Pipeline
* **Decision**: GitHub Actions.
* **Details**: Given the monorepo structure, GitHub Actions will trigger distinct workflows depending on which paths are modified (e.g., `packages/backend/**`, `packages/frontend/**`).

## 4. Testing Strategy
* **Decision**:
  * **Backend**: `pytest` for unit and integration testing.
  * **Frontend**: `Vitest` and `React Testing Library`.
  * **Integration/E2E**: Playwright (to be implemented later).

## 5. Documentation
* **Decision**: Swagger/OpenAPI (automatically served by FastAPI at `/docs`) and MkDocs for static developer guides.
