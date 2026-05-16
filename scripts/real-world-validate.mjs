#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const manifestPath = path.resolve(process.argv[2] ?? "validation/real-world-repos.json");
const outputRoot = path.resolve(process.argv[3] ?? `validation-runs/${new Date().toISOString().replace(/[:.]/g, "-")}`);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const limit = Number(process.env.AUTH_DOCTOR_VALIDATION_LIMIT ?? "0");
const commandTimeoutMs = Number(process.env.AUTH_DOCTOR_VALIDATION_TIMEOUT_MS ?? "180000");
const repos = limit > 0 ? (manifest.repositories ?? []).slice(0, limit) : manifest.repositories ?? [];

if (!repos.length) {
  throw new Error(`No repositories found in ${manifestPath}`);
}

fs.mkdirSync(outputRoot, { recursive: true });
run("npm", ["run", "build"], root);

const results = [];
for (const repo of repos) {
  const slug = repo.name.replace(/[^a-z0-9_.-]+/gi, "-");
  const repoDir = path.join(outputRoot, "repos", slug);
  const scanDir = path.join(repoDir, repo.scanPath ?? ".");
  const reportPath = path.join(outputRoot, "reports", `${slug}.json`);
  const sarifPath = path.join(outputRoot, "reports", `${slug}.sarif`);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.mkdirSync(path.dirname(repoDir), { recursive: true });

  const result = {
    name: repo.name,
    url: repo.url,
    commit: "",
    profile: repo.profile ?? [],
    scan: "not-run",
    critical: 0,
    error: 0,
    warning: 0,
    secretsCheck: "not-run",
    notes: ""
  };

  try {
    if (!fs.existsSync(repoDir)) {
      cloneRepo(repo, repoDir);
    }
    result.commit = runCapture("git", ["rev-parse", "HEAD"], repoDir).trim();
    run("node", [path.join(root, "packages/auth-doctor/dist/cli.js"), scanDir, "--json", "--fail-on", "none", "--output", reportPath], root);
    run("node", [path.join(root, "packages/auth-doctor/dist/cli.js"), scanDir, "--sarif", "--fail-on", "none", "--output", sarifPath], root);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    result.scan = "ok";
    result.critical = report.summary.critical;
    result.error = report.summary.error;
    result.warning = report.summary.warning;
    result.detected = {
      frameworks: report.project.frameworks,
      authProviders: report.project.authProviders,
      routers: report.project.routers
    };
    result.secretsCheck = containsLikelySecret(fs.readFileSync(reportPath, "utf8") + fs.readFileSync(sarifPath, "utf8"))
      ? "review"
      : "pass";
  } catch (error) {
    result.scan = "failed";
    result.notes = error instanceof Error ? error.message : String(error);
  }

  results.push(result);
  console.log(`${result.scan.toUpperCase()} ${repo.name} critical=${result.critical} error=${result.error} warning=${result.warning}`);
}

const summaryPath = path.join(outputRoot, "summary.json");
fs.writeFileSync(summaryPath, JSON.stringify({ generatedAt: new Date().toISOString(), manifest: manifestPath, results }, null, 2));
fs.writeFileSync(path.join(outputRoot, "summary.md"), renderMarkdown(results));
console.log(`\nWrote validation summary to ${summaryPath}`);

function cloneRepo(repo, repoDir) {
  fs.rmSync(repoDir, { recursive: true, force: true });
  if (repo.scanPath) {
    run("git", ["clone", "--depth", "1", "--filter=blob:none", "--sparse", repo.url, repoDir], root);
    run("git", ["sparse-checkout", "set", repo.scanPath], repoDir);
    return;
  }
  run("git", ["clone", "--depth", "1", "--filter=blob:none", repo.url, repoDir], root);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit", encoding: "utf8", timeout: commandTimeoutMs });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed with ${result.status}`);
  if (result.error) throw result.error;
}

function runCapture(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: commandTimeoutMs });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr}`);
  if (result.error) throw result.error;
  return result.stdout;
}

function containsLikelySecret(text) {
  return /(sk_live_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/.test(text);
}

function renderMarkdown(results) {
  const completed = results.filter((result) => result.scan === "ok").length;
  const failed = results.length - completed;
  const lines = [
    "# Auth Doctor Real-World Validation Summary",
    "",
    `Date: ${new Date().toISOString()}`,
    `Repository count: ${results.length}`,
    `Completed scans: ${completed}`,
    `Failed scans: ${failed}`,
    "",
    "| Repo | Scan | Critical | Error | Warning | Secret output check | Commit | Notes |",
    "|---|---|---:|---:|---:|---|---|---|"
  ];
  for (const result of results) {
    lines.push(
      `| ${result.name} | ${result.scan} | ${result.critical} | ${result.error} | ${result.warning} | ${result.secretsCheck} | ${result.commit.slice(0, 12)} | ${String(result.notes).replace(/\|/g, "\\|")} |`
    );
  }
  lines.push(
    "",
    "Manual review still required: classify critical and error findings as true positive, false positive, duplicate, needs config, or unclear before computing PRD exit metrics."
  );
  return `${lines.join("\n")}\n`;
}
