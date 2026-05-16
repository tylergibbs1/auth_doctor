# Real-World Validation Protocol

## Purpose

Auth Doctor should not be declared PRD-complete just because it passes synthetic fixtures. It must be tested on real repositories where auth code is messy, framework conventions vary, and false positives are expensive.

## Repository set

Build a validation set of at least 20 repositories:

| Segment | Minimum count | Notes |
|---|---:|---|
| Next.js App Router | 4 | Include route handlers, middleware, server actions where possible. |
| Next.js Pages Router | 3 | Include API routes and `getServerSideProps` where possible. |
| Express | 4 | Include middleware-heavy apps and route modules. |
| Auth.js / NextAuth | 2 | Include callback and session customization. |
| Clerk | 2 | Include middleware matcher and server/client auth usage. |
| Supabase | 2 | Prefer repos with migrations or SQL policy files. |
| Firebase Auth | 2 | Include Admin SDK verification paths. |
| Custom JWT | 3 | Include `jsonwebtoken`, `jose`, and wrapper utilities if possible. |
| Expected-low-noise repos | 5 | Apps that appear well-structured and should not receive critical noise. |

Categories may overlap. Private or partner repos require explicit approval before scanning, storing reports, or sharing findings.

## Runbook

For each repository:

1. Record repository name, commit SHA, framework/profile, and whether it is public or partner-approved.
2. Run a full scan:

```bash
npx -y auth-doctor@latest . --json --fail-on none > auth-doctor.report.json
```

3. Run terminal and score smoke checks:

```bash
npx -y auth-doctor@latest . --score --fail-on none
npx -y auth-doctor@latest . --sarif --fail-on none > auth-doctor.sarif
```

4. If the repository is a git checkout with changes or a sample PR branch, run:

```bash
npx -y auth-doctor@latest . --staged --fail-on none
npx -y auth-doctor@latest . --diff main --fail-on none
```

5. For at least one finding per severity, run:

```bash
npx -y auth-doctor@latest . --explain path/to/file.ts:LINE --fail-on none
```

6. Review every critical and error finding manually.
7. Classify each reviewed finding as true positive, false positive, duplicate, needs config, or unclear.
8. Confirm no output includes raw secret values.
9. Record crashes, parse failures, confusing output, and missing framework context.

## Review rubric

Use this rubric when manually reviewing findings:

| Classification | Meaning |
|---|---|
| True positive | The finding identifies a real auth/authz risk or unsafe pattern. |
| False positive | The finding is wrong or misses nearby code that makes the pattern safe. |
| Duplicate | The finding is technically true but redundant with another finding. |
| Needs config | The scanner cannot know the intent without project-specific route/provider config. |
| Unclear | The reviewer cannot classify without more domain knowledge. |

Critical findings should be demoted or tightened if they are frequently `needs config` or `unclear`.

## Exit criteria

The real-world validation pass succeeds when:

1. At least 20 repositories have completed scans.
2. At least 95 percent of scans complete without crashing.
3. Critical-rule false-positive rate is below 10 percent.
4. Error-rule false-positive rate is below 20 percent.
5. No raw secret values are emitted.
6. Each MVP framework/provider has at least one validated real-world repo.
7. The top false-positive causes have follow-up issues or fixes.
8. Documentation has been updated for any rule behavior changed during validation.

## Validation report template

```md
# Auth Doctor Real-World Validation Report

Date:
Auth Doctor version:
Repository count:
Completed scans:
Crash count:

## Summary

- Critical findings:
- Error findings:
- Warning findings:
- Critical false-positive rate:
- Error false-positive rate:
- Secret leakage incidents:

## Repositories

| Repo | Commit | Profile | Scan result | Critical TP/FP | Error TP/FP | Notes |
|---|---|---|---|---:|---:|---|

## Top fixes made

1.
2.
3.

## Open risks

1.
2.
3.
```

