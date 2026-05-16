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

