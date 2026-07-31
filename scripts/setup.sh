#!/bin/bash
echo "Setting up development environment..."

# Backend setup
cd packages/backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cd ../..

# Security setup
cd packages/security && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cd ../..

# AI setup
cd packages/ai && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cd ../..

# Frontend setup
cd packages/frontend && npm install
cd ../..

echo "Setup complete!"
