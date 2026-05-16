# Auth Doctor

Your agent writes broken auth. This catches it.

Auth Doctor is a framework-aware authentication and authorization scanner for TypeScript and JavaScript apps. It focuses on high-signal auth correctness issues rather than broad generic SAST findings.

## Current goal

This repository is being built against the MVP PRD in [docs/GOAL.md](docs/GOAL.md). The near-term target is a private-alpha CLI that can scan Next.js, Express, Auth.js, Clerk, Supabase, Firebase, and custom JWT patterns, then emit terminal, JSON, SARIF, GitHub annotation, and agent-rule outputs.

## Try it locally

```bash
npm install
npm run build
npm run auth-doctor -- packages/test-fixtures/express-jwt-vulnerable --json
```

## Package layout

```text
packages/
  auth-doctor/                 CLI
  core/                        project detection, scan orchestration, scoring
  types/                       shared report and diagnostic types
  rules/                       rule definitions
  analyzers-js/                JS/TS source analyzer
  agent-install/               agent rule writers
  sarif/                       SARIF output
  integration-github-action/   GitHub Action helpers
  test-fixtures/               vulnerable and safe sample apps
```

