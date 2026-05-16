import type { AuthDoctorReport, Diagnostic } from "@auth-doctor/types";

export function toGithubAnnotations(report: AuthDoctorReport): string[] {
  return report.diagnostics.map((diagnostic) => {
    const level = diagnostic.severity === "warning" ? "warning" : diagnostic.severity === "info" ? "notice" : "error";
    const properties = [
      `file=${escapeProperty(diagnostic.file)}`,
      `line=${diagnostic.line ?? 1}`,
      `title=${escapeProperty(`${diagnostic.ruleId}: ${diagnostic.title}`)}`
    ].join(",");
    return `::${level} ${properties}::${escapeData(diagnostic.recommendation)}`;
  });
}

export function renderPullRequestComment(report: AuthDoctorReport): string {
  const top = report.diagnostics.slice(0, 10);
  const lines = [
    "<!-- auth-doctor:pr-comment -->",
    `## Auth Doctor: ${report.score?.value ?? "n/a"}/100 (${report.score?.label ?? "No score"})`,
    "",
    `Findings: ${report.summary.critical} critical, ${report.summary.error} error, ${report.summary.warning} warning.`,
    ""
  ];

  if (!top.length) {
    lines.push("No high-signal auth issues detected in this scan.");
    return lines.join("\n");
  }

  lines.push("| Severity | Rule | Location | Fix |", "|---|---|---|---|");
  for (const diagnostic of top) {
    lines.push(
      `| ${diagnostic.severity} | \`${diagnostic.ruleId}\` | \`${diagnostic.file}:${diagnostic.line ?? 1}\` | ${escapeMarkdown(diagnostic.recommendation)} |`
    );
  }
  if (report.diagnostics.length > top.length) {
    lines.push("", `Plus ${report.diagnostics.length - top.length} more finding(s) in the full report.`);
  }
  return lines.join("\n");
}

export function groupNewFindings(report: AuthDoctorReport): Diagnostic[] {
  return report.diagnostics.filter((diagnostic) => diagnostic.severity !== "info");
}

function escapeProperty(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeMarkdown(value: string): string {
  return value.replace(/\|/g, "\\|");
}

