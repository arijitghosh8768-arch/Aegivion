# Aegivion — Autonomous Explainable Cloud Security Copilot

A production-quality, fully connected cloud security platform frontend built with
Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS v4, Framer Motion,
GSAP, React Flow, Recharts, Zustand and Radix UI.

![stack](https://img.shields.io/badge/Next.js-16-black) ![stack](https://img.shields.io/badge/React-19-blue) ![stack](https://img.shields.io/badge/Tailwind-v4-38bdf8)

## Features

- **Authentication** — animated login, signup, forgot-password with SSO (Google / Microsoft), remember-me
- **Dashboard** — live interactive cloud topology (rotating, zoomable, draggable, animated data packets, orbiting resources, attack-path overlay, mini-map), animated metric cards, real-time risk / threat / compliance / asset charts, embedded AI copilot
- **Cloud Accounts** — account health cards, per-provider scan, guided connect flow
- **Cloud Topology** — full workspace with node filtering, resource-type filters, legend, mini-map
- **Assets** — searchable, filterable inventory with risk bars and detail dialog
- **Threats** — correlated alerts with evidence, MITRE ATT&CK mapping and containment actions
- **Detection Engine** — misconfigurations / vulnerabilities / compliance tabs with evidence + confidence
- **Threat Correlation** — React Flow kill-chain graphs with step-by-step evidence and timelines
- **Prediction** — 14-day forecast with confidence band, 7×24 likelihood heatmap, model factors
- **Remediation** — Terraform + CLI fixes with rollback plans, approve / reject / apply queue
- **Security Memory** — incidents, learned patterns, repeated mistakes, trend analysis
- **Reports** — executive / posture / compliance / threat-intel templates with CSV export and print
- **AI Copilot** — explainable chat with cited sources and canned intelligence
- **Settings** — profile, workspace, notifications, integrations, security, appearance
- Light/dark theme, command palette (⌘K), notifications center, workspace selector

## Getting started

```bash
npm install
npm run dev      # http://localhost:3000
```

Production build:

```bash
npm run build
npm start
```

## Demo

Use any email/password on the login page, or tap a Google/Microsoft SSO button —
auth is a client-side mock that persists in `localStorage`.

## Structure

```
app/                  # App Router: (auth) and (dashboard) route groups
components/
  ui/                 # shadcn-style primitives (Radix-based)
  layout/             # sidebar, topbar, command menu
  topology/           # interactive cloud topology engine
  dashboard/          # metric cards, charts, AI panel, feeds
  shared/             # badges, gauges, tooltips, providers
lib/
  data/               # realistic mock telemetry for the whole platform
  store.ts            # Zustand global state (auth, workspace, notifications)
  hooks.ts · utils.ts
```

## Design system

Modern enterprise: white/soft-lavender surfaces, glassmorphism, soft purple →
blue gradient, light shadows, rounded corners, Inter typography. Theme tokens in
`app/globals.css` (Tailwind v4 `@theme`).
