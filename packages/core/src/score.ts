import type { AuthDoctorReport, Diagnostic, Severity, ScoreLabel } from "@auth-doctor/types";

export function scoreDiagnostics(diagnostics: Diagnostic[]): NonNullable<AuthDoctorReport["score"]> {
  const uniqueCritical = uniqueRulesBySeverity(diagnostics, "critical");
  const uniqueError = uniqueRulesBySeverity(diagnostics, "error");
  const uniqueWarning = uniqueRulesBySeverity(diagnostics, "warning");
  const cappedInstanceCount = Math.min(diagnostics.length, 80);

  const value = Math.max(
    0,
    Math.round(100 - 12 * uniqueCritical - 6 * uniqueError - 2 * uniqueWarning - 0.25 * cappedInstanceCount)
  );

  return { value, label: labelForScore(value) };
}

export function labelForScore(value: number): ScoreLabel {
  if (value >= 90) return "Strong";
  if (value >= 75) return "Good";
  if (value >= 50) return "Risky";
  return "Critical";
}

function uniqueRulesBySeverity(diagnostics: Diagnostic[], severity: Severity): number {
  return new Set(diagnostics.filter((diagnostic) => diagnostic.severity === severity).map((diagnostic) => diagnostic.ruleId)).size;
}

export function failForThreshold(diagnostics: Diagnostic[], threshold: "critical" | "error" | "warning" | "none"): boolean {
  if (threshold === "none") return false;
  const rank: Record<Severity, number> = { critical: 3, error: 2, warning: 1, info: 0 };
  return diagnostics.some((diagnostic) => rank[diagnostic.severity] >= rank[threshold]);
}

