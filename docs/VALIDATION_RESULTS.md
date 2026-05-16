# Validation Results

## 2026-05-16 Seed Real-World Run

Command:

```bash
AUTH_DOCTOR_VALIDATION_LIMIT=7 AUTH_DOCTOR_VALIDATION_TIMEOUT_MS=120000 npm run validate:real-world
```

Result:

| Repo | Scan | Critical | Error | Warning | Secret output check |
|---|---|---:|---:|---:|---|
| nextauthjs/next-auth-example | ok | 0 | 0 | 0 | pass |
| vercel/nextjs-subscription-payments | ok | 0 | 0 | 0 | pass |
| supabase/supabase/examples/auth/nextjs | ok | 0 | 0 | 0 | pass |
| clerk/nextjs-auth-starter-template | ok | 0 | 0 | 0 | pass |
| clerk/clerk-nextjs-starter | ok | 0 | 0 | 0 | pass |
| gothinkster/node-express-realworld-example-app | ok | 0 | 0 | 0 | pass |
| sahat/hackathon-starter | ok | 0 | 0 | 0 | pass |

The run completed without crashes and without likely raw secret output in JSON or SARIF reports.

This is a seed validation run, not the full PRD completion gate. The full gate remains at 20 real repositories with manual classification of critical/error findings.

## 2026-05-16 PRD Completion Validation

Command:

```bash
AUTH_DOCTOR_VALIDATION_TIMEOUT_MS=180000 npm run validate:real-world
```

Validation run directory:

```text
validation-runs/2026-05-16T05-18-08-093Z
```

Result:

| Metric | Result |
|---|---:|
| Repositories selected | 23 |
| Completed scans | 23 |
| Failed scans | 0 |
| Scan completion rate | 100% |
| Critical findings | 0 |
| Error findings | 1 |
| Warning findings | 1 |
| Secret output check failures | 0 |
| Critical false-positive rate | 0% |
| Error false-positive rate | 0% |

Repository outcomes:

| Repo | Scan | Critical | Error | Warning | Secret output check |
|---|---|---:|---:|---:|---|
| nextauthjs/next-auth-example | ok | 0 | 0 | 0 | pass |
| vercel/nextjs-subscription-payments | ok | 0 | 0 | 0 | pass |
| supabase/supabase/examples/auth/nextjs | ok | 0 | 0 | 0 | pass |
| clerk/nextjs-auth-starter-template | ok | 0 | 0 | 0 | pass |
| clerk/clerk-nextjs-starter | ok | 0 | 0 | 0 | pass |
| gothinkster/node-express-realworld-example-app | ok | 0 | 0 | 0 | pass |
| sahat/hackathon-starter | ok | 0 | 0 | 0 | pass |
| hiteshchoudhary/nextjs-fullstack-auth | ok | 0 | 1 | 0 | pass |
| vercel/nextjs-postgres-auth-starter | ok | 0 | 0 | 0 | pass |
| auth0-samples/auth0-nextjs-samples | ok | 0 | 0 | 0 | pass |
| rwieruch/nextjs-firebase-authentication | ok | 0 | 0 | 0 | pass |
| WebDevSimplified/custom-nextjs-authentication | ok | 0 | 0 | 0 | pass |
| weehongkoh/nextjs-app-router-authjs | ok | 0 | 0 | 0 | pass |
| mickasmt/next-auth-roles-template | ok | 0 | 0 | 0 | pass |
| mryechkin/nextjs-supabase-auth | ok | 0 | 0 | 0 | pass |
| dabit3/supabase-nextjs-auth | ok | 0 | 0 | 0 | pass |
| wpcodevo/nextjs14-supabase-ssr-authentication | ok | 0 | 0 | 0 | pass |
| gladly-team/next-firebase-auth | ok | 0 | 0 | 0 | pass |
| sairajchouhan/nextjs-firebase-auth | ok | 0 | 0 | 0 | pass |
| iamshaunjp/node-express-jwt-auth | ok | 0 | 0 | 0 | pass |
| zachgoll/express-jwt-authentication-starter | ok | 0 | 0 | 1 | pass |
| didinj/node-express-mongoose-passport-jwt-rest-api-auth | ok | 0 | 0 | 0 | pass |
| Louis3797/express-ts-auth-service | ok | 0 | 0 | 0 | pass |

Manual finding review:

| Repo | Rule | Severity | Classification | Notes |
|---|---|---|---|---|
| hiteshchoudhary/nextjs-fullstack-auth | `auth/next-middleware-matcher-gap` | error | True positive | Middleware matcher covers page routes but not protected-looking API routes; recommendation is route-local checks or `/api` matcher coverage. |
| zachgoll/express-jwt-authentication-starter | `auth/localstorage-token` | warning | True positive | Angular client interceptor reads an ID token from `localStorage`; warning severity matches the PRD. |

Additional smoke checks on `hiteshchoudhary/nextjs-fullstack-auth`:

| Capability | Result |
|---|---|
| `--score` | Passed, returned `94`. |
| `--annotations` | Passed, emitted a GitHub Actions annotation. |
| `--explain src/middleware.ts:25` | Passed, explained the matcher gap and remediation. |
| `--sarif` | Passed, emitted SARIF `2.1.0` with one result. |
| `--staged --json` | Passed, report metadata mode was `staged`. |
| `--diff HEAD --json` | Passed, report metadata mode was `diff`. |

Agent install was exercised on 5 real repository clones:

| Repo | Result |
|---|---|
| nextauthjs/next-auth-example | Wrote Claude, Cursor, Codex, and OpenCode rules. |
| vercel/nextjs-subscription-payments | Wrote Claude, Cursor, Codex, and OpenCode rules. |
| clerk/nextjs-auth-starter-template | Wrote Claude, Cursor, Codex, and OpenCode rules. |
| hiteshchoudhary/nextjs-fullstack-auth | Wrote Claude, Cursor, Codex, and OpenCode rules. |
| iamshaunjp/node-express-jwt-auth | Wrote Claude, Cursor, Codex, and OpenCode rules. |

Conclusion:

The PRD completion gate is satisfied for the current MVP scope: 23 real repositories scanned, 100% completion, no raw secret output detected, critical false-positive rate 0%, error false-positive rate 0%, required output modes smoke-tested, and agent install tested across 5 real repository clones.
