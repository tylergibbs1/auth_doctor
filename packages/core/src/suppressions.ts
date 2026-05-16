import type { AuthDoctorConfig, Diagnostic, SourceFile, Suppression } from "@auth-doctor/types";
import { matchesAnyGlob } from "./path-utils.js";

const DISABLE_NEXT = /auth-doctor-disable-next-line\s+([a-z0-9-/,\s]+)/i;
const DISABLE_LINE = /auth-doctor-disable-line\s+([a-z0-9-/,\s]+)/i;

export function collectSuppressions(files: SourceFile[], config: AuthDoctorConfig): Suppression[] {
  const suppressions: Suppression[] = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((lineText, index) => {
      const line = index + 1;
      const next = DISABLE_NEXT.exec(lineText);
      const same = DISABLE_LINE.exec(lineText);
      if (next) {
        for (const ruleId of parseRuleList(next[1])) {
          suppressions.push({ ruleId, file: file.relativePath, line: line + 1, kind: "next-line", used: false });
        }
      }
      if (same) {
        for (const ruleId of parseRuleList(same[1])) {
          suppressions.push({ ruleId, file: file.relativePath, line, kind: "line", used: false });
        }
      }
    });
  }

  for (const ruleId of config.ignore?.rules ?? []) {
    suppressions.push({ ruleId, file: "*", line: 0, kind: "config", used: false });
  }
  return suppressions;
}

export function applySuppressions(
  diagnostics: Diagnostic[],
  suppressions: Suppression[],
  config: AuthDoctorConfig
): { diagnostics: Diagnostic[]; suppressions: Suppression[] } {
  const out: Diagnostic[] = [];
  const suppressionCopies = suppressions.map((suppression) => ({ ...suppression }));

  for (const diagnostic of diagnostics) {
    const configSuppressed =
      config.ignore?.rules?.includes(diagnostic.ruleId) ||
      matchesAnyGlob(diagnostic.file, config.ignore?.files) ||
      (config.ignore?.overrides ?? []).some(
        (override) => override.rules.includes(diagnostic.ruleId) && matchesAnyGlob(diagnostic.file, override.files)
      );

    if (configSuppressed) {
      markUsed(suppressionCopies, diagnostic);
      continue;
    }

    const inlineSuppression = suppressionCopies.find(
      (suppression) =>
        suppression.kind !== "config" &&
        suppression.file === diagnostic.file &&
        suppression.line === diagnostic.line &&
        suppression.ruleId === diagnostic.ruleId
    );

    if (config.respectInlineDisables !== false && inlineSuppression) {
      inlineSuppression.used = true;
      continue;
    }

    out.push(diagnostic);
  }

  return { diagnostics: out, suppressions: suppressionCopies };
}

export function explainSuppressionAt(file: string, line: number, suppressions: Suppression[]): Suppression[] {
  return suppressions.filter((suppression) => suppression.file === file && suppression.line === line);
}

function parseRuleList(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function markUsed(suppressions: Suppression[], diagnostic: Diagnostic): void {
  const match = suppressions.find(
    (suppression) =>
      (suppression.file === "*" || suppression.file === diagnostic.file) && suppression.ruleId === diagnostic.ruleId
  );
  if (match) match.used = true;
}

