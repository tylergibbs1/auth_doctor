# Auth Doctor

Your agent writes broken auth. This catches it.

Auth Doctor is a framework-aware authentication and authorization scanner for TypeScript and JavaScript apps. It looks for high-signal auth correctness bugs that generic linters and broad SAST tools often miss: missing server-side checks, client-only protection, broken authorization, JWT misuse, insecure cookies, middleware gaps, public secrets, and provider-specific footguns.

This is an MVP scanner. It is useful today, but it is not a replacement for penetration testing, threat modeling, or a security review.

## What It Scans

MVP coverage includes:

- Next.js App Router and Pages Router
- Express
- Auth.js / NextAuth
- Clerk
- Supabase
- Firebase Auth
- Custom JWT implementations
- Supabase SQL/RLS migration patterns

Auth Doctor emits:

- Human-readable terminal reports
- 0-100 auth health score
- JSON reports
- SARIF
- GitHub Actions annotations
- Project-specific agent rules for Claude, Cursor, Codex, and OpenCode

## Quick Start

From this repo:

```bash
npm install
npm run build
npm run auth-doctor -- packages/test-fixtures/express-jwt-vulnerable
```

Once published to npm, the intended public command is:

```bash
npx -y auth-doctor@latest .
```

## CLI

```bash
auth-doctor [directory] [options]
```

Useful options:

```bash
--score
--json
--sarif
--annotations
--staged
--diff [base]
--fail-on <critical|error|warning|none>
--explain <file:line>
--config <path>
--output <path>
```

Examples:

```bash
npm run auth-doctor -- . --score
npm run auth-doctor -- . --json --fail-on none --output auth-doctor.report.json
npm run auth-doctor -- . --sarif --output auth-doctor.sarif
npm run auth-doctor -- . --explain src/middleware.ts:25
```

## Agent Rules

Install project-specific auth guidance for coding agents:

```bash
npm run auth-doctor -- . install
```

This writes guidance for common agent conventions:

- `CLAUDE.md`
- `.cursor/rules/auth-doctor.mdc`
- `AGENTS.md`
- `.opencode/auth-doctor.md`

The generated rules tell agents to use server-side auth, avoid trusting client roles or IDs, verify resource ownership, keep service keys server-only, and run Auth Doctor before finishing auth-related work.

## Example Findings

JWT decoded without verification:

```ts
const user = jwt.decode(token);
```

Missing resource authorization:

```ts
const session = await auth();
if (!session?.user) return unauthorized();
return db.project.findUnique({ where: { id: params.id } });
```

Supabase service key exposed to the browser:

```ts
createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
```

Express middleware registered too late:

```ts
app.post("/admin/users/:id/delete", deleteUser);
app.use(requireAuth);
```

See [docs/RULES.md](docs/RULES.md) for rule documentation and unsafe/safe examples.

## GitHub Actions

The repo includes a composite action scaffold in `packages/integration-github-action`.

Example workflow:

```yaml
name: Auth Doctor

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  auth-doctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: auth-doctor/action@v1
        with:
          diff: main
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: critical
          sarif: true
```

## Validation Status

The MVP PRD validation gate has been completed for the current scope.

Latest recorded run:

- 23 real repositories scanned
- 23/23 completed
- 0 crashes
- 0 raw secret-output failures
- 0 critical findings after review
- 1 error finding, manually classified true positive
- 1 warning finding, manually classified true positive
- Critical false-positive rate: 0%
- Error false-positive rate: 0%

Evidence is recorded in [docs/VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md).

Run the validation harness:

```bash
AUTH_DOCTOR_VALIDATION_TIMEOUT_MS=180000 npm run validate:real-world
```

## Development

```bash
npm install
npm run build
npm test
npm run check
```

Run against fixtures:

```bash
npm run auth-doctor -- packages/test-fixtures/next-authjs-vulnerable
npm run auth-doctor -- packages/test-fixtures/supabase-vulnerable --json --fail-on none
npm run auth-doctor -- packages/test-fixtures/healthy-next
```

## Package Layout

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

## Limitations

Auth Doctor is intentionally conservative, but it is still a static heuristic scanner. It does not prove an app is secure. Authorization can be domain-specific, so some findings may require project config or manual review. Hosted reporting, dashboards, and deeper multi-language analysis are outside the current MVP.

## Roadmap

- Publish `auth-doctor` to npm.
- Add CI for this public repo.
- Add deeper AST/data-flow analysis.
- Add more provider-specific rules.
- Add PR comment integration tests.
- Expand the real-world validation set over time.

