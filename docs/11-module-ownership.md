# Module Ownership and Boundaries

## Member 1 — Cloud Management
Authentication/org foundations, cloud accounts, AWS/Azure/GCP adapters, collection, normalization, inventory, relationships, history/versioning, search/export, scheduler, cloud-side audit. Not detection, AI reasoning, or frontend.

## Member 2 — Security Analytics
Detection/rules, findings, severity/risk, MITRE mapping, attack paths, correlation/incidents, compliance, timelines, exceptions, lifecycle, notifications, response policy/state machine. Not provider implementation, LLM reasoning, or UI.

## Member 3 — Security Intelligence / AI
Context aggregation, RAG, prompts, AI explanations/recommendations/reports/chat, knowledge, caching, output validation, evaluation. Must not replace deterministic detection/risk or directly mutate cloud resources.

## Member 4 — Product / Integration
UI, API integration, dashboards, findings/incidents/attack graph/compliance/AI/reports/notifications/settings, accessibility, responsiveness, performance, product integration tests. Must not create conflicting backend business logic.

## Shared rules
Contract changes require coordination and tests. Document each module's owner, inputs, outputs, dependencies, failure behavior, tests, and consumers.
