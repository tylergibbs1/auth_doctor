# Auth Doctor Build Goal

## Status

Completed for the current MVP PRD scope on 2026-05-16. Evidence is recorded in [VALIDATION_RESULTS.md](VALIDATION_RESULTS.md).

## Goal

Complete Auth Doctor from the product requirements draft into a usable private-alpha developer tool.

The definition of complete for this goal is the MVP acceptance criteria from the PRD:

1. CLI runs successfully on at least five benchmark apps.
2. Scanner supports Next.js App Router, Express, Auth.js, Clerk, Supabase, Firebase, and custom JWT patterns.
3. At least 15 high-confidence rules are implemented.
4. Critical-rule false-positive rate is below 10 percent on benchmark and design-partner repos.
5. Terminal output, JSON output, score output, config, suppressions, and `--explain` work.
6. Agent install writes useful auth guidance for Claude Code, Cursor, Codex, and OpenCode.
7. GitHub Action can scan a PR diff and post a useful comment.
8. Scanner never prints raw secret values.
9. Documentation includes unsafe and safe examples for every MVP rule.

## Top-level completion goal

The product goal is now broader than the private-alpha scaffold:

Complete the full Auth Doctor PRD and validate it against real-world repositories before considering the PRD done.

Auth Doctor is done when it can scan both benchmark fixtures and real application repositories with useful, explainable, low-noise findings. The tool must prove that it catches real auth footguns without overwhelming developers with generic static-analysis noise.

## Real-world validation requirement

Before marking the PRD complete, run Auth Doctor against a real-world validation set:

1. At least 20 public or partner-approved repositories.
2. At least 4 Next.js App Router apps.
3. At least 3 Next.js Pages Router apps.
4. At least 4 Express apps.
5. At least 2 Auth.js or NextAuth apps.
6. At least 2 Clerk apps.
7. At least 2 Supabase apps with migrations or RLS policies.
8. At least 2 Firebase Auth apps.
9. At least 3 custom JWT implementations.
10. At least 5 repositories that appear security-conscious and should produce few or no high-severity findings.

Validation repos may overlap categories. Do not upload private code or reports unless the owner explicitly approves it.

## Real-world completion metrics

The PRD is complete only when the validation run meets these thresholds:

1. CLI completes without crashing on 95 percent or more of selected repositories.
2. Critical-rule false-positive rate is below 10 percent after manual review.
3. Error-rule false-positive rate is below 20 percent after manual review.
4. At least 80 percent of real findings include a framework-specific fix recommendation.
5. Every critical finding has file, line, evidence, rationale, and a concrete remediation.
6. The scanner never prints raw secret values in terminal, JSON, SARIF, annotations, or PR comments.
7. `--json`, `--sarif`, `--score`, `--annotations`, `--explain`, `--diff`, and `--staged` work on representative real repos.
8. Agent install writes useful project-specific rules in at least 5 real repos with different agent conventions.
9. GitHub Action can scan a real PR diff and create or update a useful PR comment.
10. Documentation covers each implemented MVP rule with unsafe and safe examples.

Track the validation protocol in [REAL_WORLD_VALIDATION.md](REAL_WORLD_VALIDATION.md).

## Build order

1. Core CLI and project detection.
2. JS/TS analyzer and route map.
3. JWT rules.
4. Missing server auth rules for Next.js and Express.
5. Authenticated-not-authorized heuristics.
6. Supabase service key and RLS rules.
7. Cookie/session rules.
8. Config and suppressions.
9. JSON and score output.
10. Agent install.
11. GitHub Action and PR comments.
12. SARIF output.
13. Benchmark leaderboard or hosted report sharing.

## MVP rule target

The first implementation favors narrow, high-confidence checks. Critical findings should include concrete evidence, framework context when available, and a fix recommendation.

Implemented rule families should cover:

- Missing server-side auth.
- Broken authorization.
- JWT correctness.
- Sessions and cookies.
- CSRF and browser flows.
- Provider-specific misuse.
- Middleware ordering and coverage.
- Secrets and privileged keys.
