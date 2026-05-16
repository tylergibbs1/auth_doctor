import type { AuthDoctorConfig, Diagnostic, ProjectProfile, RuleContext, SourceFile } from "@auth-doctor/types";
import { rules } from "@auth-doctor/rules";

export type AnalyzeInput = {
  rootDir: string;
  profile: ProjectProfile;
  config: AuthDoctorConfig;
  files: SourceFile[];
  routeFiles: SourceFile[];
};

export function analyzeJavaScript(input: AnalyzeInput): Diagnostic[] {
  const context: RuleContext = input;
  const diagnostics = rules
    .filter((rule) => rule.appliesTo(input.profile))
    .flatMap((rule) => rule.run(context));

  return dedupeDiagnostics(diagnostics).sort(compareDiagnostics);
}

function dedupeDiagnostics(diagnostics: Diagnostic[]): Diagnostic[] {
  const seen = new Set<string>();
  const out: Diagnostic[] = [];
  for (const diagnostic of diagnostics) {
    const key = `${diagnostic.ruleId}:${diagnostic.file}:${diagnostic.line}:${diagnostic.evidence.join("|")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(diagnostic);
  }
  return out;
}

function compareDiagnostics(a: Diagnostic, b: Diagnostic): number {
  const rank: Record<Diagnostic["severity"], number> = { critical: 0, error: 1, warning: 2, info: 3 };
  return (
    rank[a.severity] - rank[b.severity] ||
    a.file.localeCompare(b.file) ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

