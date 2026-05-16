import type { AuthDoctorReport, Diagnostic } from "@auth-doctor/types";

export function toSarif(report: AuthDoctorReport): Record<string, unknown> {
  const uniqueRules = [...new Map(report.diagnostics.map((diagnostic) => [diagnostic.ruleId, diagnostic])).values()];

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Auth Doctor",
            informationUri: "https://github.com/auth-doctor/auth-doctor",
            version: report.version,
            rules: uniqueRules.map(toSarifRule)
          }
        },
        results: report.diagnostics.map(toSarifResult)
      }
    ]
  };
}

function toSarifRule(diagnostic: Diagnostic): Record<string, unknown> {
  return {
    id: diagnostic.ruleId,
    name: diagnostic.title,
    shortDescription: { text: diagnostic.title },
    fullDescription: { text: diagnostic.whyItMatters },
    help: {
      text: diagnostic.recommendation
    },
    defaultConfiguration: {
      level: sarifLevel(diagnostic.severity)
    },
    properties: {
      category: diagnostic.category,
      confidence: diagnostic.confidence
    }
  };
}

function toSarifResult(diagnostic: Diagnostic): Record<string, unknown> {
  return {
    ruleId: diagnostic.ruleId,
    level: sarifLevel(diagnostic.severity),
    message: {
      text: `${diagnostic.title}: ${diagnostic.recommendation}`
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: diagnostic.file
          },
          region: {
            startLine: diagnostic.line ?? 1,
            startColumn: diagnostic.column ?? 1
          }
        }
      }
    ],
    properties: {
      evidence: diagnostic.evidence
    }
  };
}

function sarifLevel(severity: Diagnostic["severity"]): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "error") return "error";
  if (severity === "warning") return "warning";
  return "note";
}

