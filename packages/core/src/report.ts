import type { AuthDoctorReport, Diagnostic, ProjectProfile, ScanMode, Suppression } from "@auth-doctor/types";
import { scoreDiagnostics } from "./score.js";

export function createReport(input: {
  version: string;
  profile: ProjectProfile;
  diagnostics: Diagnostic[];
  suppressions: Suppression[];
  filesScanned: number;
  mode: ScanMode;
  offline: boolean;
  durationMs: number;
}): AuthDoctorReport {
  const diagnostics = sanitizeDiagnostics(input.diagnostics);
  const score = scoreDiagnostics(diagnostics);
  return {
    ok: diagnostics.every((diagnostic) => diagnostic.severity !== "critical" && diagnostic.severity !== "error"),
    version: input.version,
    score,
    project: input.profile,
    summary: {
      critical: count(diagnostics, "critical"),
      error: count(diagnostics, "error"),
      warning: count(diagnostics, "warning"),
      info: count(diagnostics, "info"),
      uniqueRules: new Set(diagnostics.map((diagnostic) => diagnostic.ruleId)).size,
      filesScanned: input.filesScanned,
      routesAnalyzed: input.profile.routeCount
    },
    diagnostics,
    suppressions: input.suppressions,
    metadata: {
      mode: input.mode,
      offline: input.offline,
      durationMs: input.durationMs
    }
  };
}

function count(diagnostics: Diagnostic[], severity: Diagnostic["severity"]): number {
  return diagnostics.filter((diagnostic) => diagnostic.severity === severity).length;
}

function sanitizeDiagnostics(diagnostics: Diagnostic[]): Diagnostic[] {
  return diagnostics.map((diagnostic) => ({
    ...diagnostic,
    evidence: diagnostic.evidence.map(redactSecretText),
    unsafePattern: diagnostic.unsafePattern ? redactSecretText(diagnostic.unsafePattern) : undefined,
    safePattern: diagnostic.safePattern ? redactSecretText(diagnostic.safePattern) : undefined
  }));
}

function redactSecretText(value: string): string {
  return value
    .replace(/((?:SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE|ADMIN_KEY|JWT|PASSWORD)[A-Z0-9_]*\s*[:=]\s*)["'`][^"'`]{8,}["'`]/gi, "$1\"[REDACTED]\"")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]{12,}/gi, "$1[REDACTED]")
    .replace(/(-----BEGIN [A-Z ]+-----)[\s\S]*?(-----END [A-Z ]+-----)/g, "$1[REDACTED]$2");
}
