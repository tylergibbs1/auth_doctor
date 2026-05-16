#!/usr/bin/env node
import fs from "node:fs";

const reportPath = process.argv[2] ?? "auth-doctor.report.json";
const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const token = process.env.GITHUB_TOKEN;
const repository = process.env.GITHUB_REPOSITORY;
const eventPath = process.env.GITHUB_EVENT_PATH;

if (!token || !repository || !eventPath) {
  console.log("Auth Doctor PR comment skipped: missing GitHub token, repository, or event path.");
  process.exit(0);
}

const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
const issueNumber = event.pull_request?.number;
if (!issueNumber) {
  console.log("Auth Doctor PR comment skipped: event is not a pull request.");
  process.exit(0);
}

const marker = "<!-- auth-doctor:pr-comment -->";
const body = renderComment(report, marker);
const [owner, repo] = repository.split("/");
const api = `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`;
const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type": "application/json",
  "User-Agent": "auth-doctor-action"
};

const commentsResponse = await fetch(api, { headers });
if (!commentsResponse.ok) {
  throw new Error(`Failed to list PR comments: ${commentsResponse.status} ${await commentsResponse.text()}`);
}

const comments = await commentsResponse.json();
const existing = comments.find((comment) => typeof comment.body === "string" && comment.body.includes(marker));
const targetUrl = existing?.url ?? api;
const method = existing ? "PATCH" : "POST";
const response = await fetch(targetUrl, {
  method,
  headers,
  body: JSON.stringify({ body })
});

if (!response.ok) {
  throw new Error(`Failed to ${existing ? "update" : "create"} PR comment: ${response.status} ${await response.text()}`);
}

console.log(existing ? "Updated Auth Doctor PR comment." : "Created Auth Doctor PR comment.");

function renderComment(report, marker) {
  const score = report.score ? `${report.score.value}/100 (${report.score.label})` : "n/a";
  const lines = [
    marker,
    `## Auth Doctor: ${score}`,
    "",
    `Findings: ${report.summary.critical} critical, ${report.summary.error} error, ${report.summary.warning} warning.`,
    "",
    `Project: ${formatList(report.project.frameworks)} | Auth: ${formatList(report.project.authProviders)} | Routes analyzed: ${report.summary.routesAnalyzed}`,
    ""
  ];

  if (!report.diagnostics.length) {
    lines.push("No high-signal auth issues detected in this scan.");
    return lines.join("\n");
  }

  lines.push("| Severity | Rule | Location | Recommendation |", "|---|---|---|---|");
  for (const diagnostic of report.diagnostics.slice(0, 12)) {
    lines.push(
      `| ${diagnostic.severity} | \`${diagnostic.ruleId}\` | \`${diagnostic.file}:${diagnostic.line ?? 1}\` | ${escapeMarkdown(diagnostic.recommendation)} |`
    );
  }
  if (report.diagnostics.length > 12) {
    lines.push("", `Plus ${report.diagnostics.length - 12} more finding(s) in the full report artifact.`);
  }
  lines.push("", "Suppress only when intentional, using the narrow suppression hint shown in the CLI output.");
  return lines.join("\n");
}

function formatList(values) {
  return values?.length ? values.join(", ") : "unknown";
}

function escapeMarkdown(value) {
  return String(value).replace(/\|/g, "\\|");
}

