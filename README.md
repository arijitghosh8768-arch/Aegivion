# Aegivion

Aegivion is a comprehensive security analysis platform that monitors cloud infrastructure, detects vulnerabilities, evaluates risks using AI, and presents findings in a unified security dashboard.

## 📂 Repository Structure

```text
aegivion/
├── packages/
│   ├── backend/      # FastAPI REST API & Core Orchestration
│   ├── security/     # Static Analysis & Security Scanning Rules
│   ├── ai/           # LLM Integrations, Prompts, & Vector DB Client
│   └── frontend/     # Vite + React + TS Dashboard
├── docker/           # Shared Docker configuration & databases
├── docs/             # Architecture, contracts, & technical decisions
└── docker-compose.yml
```

## 🚀 Quick Start (Day 1)

### Prerequisites
- Docker & Docker Compose
- Node.js v18+ & Python 3.10+
- Environment variables configured in `.env` (copied from `.env.example`)

### Launch Services
To start all databases and services in the background:
```bash
docker-compose up -d
```

### Health Check (Backend)
Verify the FastAPI backend endpoint is up and running:
```bash
curl http://localhost:8000/health
```

### Development Mode

#### Frontend
If you don't have Node/npm installed on Windows, refer to the [Node.js Setup Guide](docs/NODE_SETUP.md) or use our standalone fallback by opening `packages/frontend/index.html` directly.

```bash
cd packages/frontend
npm install
npm run dev
```

#### Backend
```bash
cd packages/backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```
