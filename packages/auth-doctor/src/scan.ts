import { execFileSync } from "node:child_process";
import path from "node:path";
import { analyzeJavaScript } from "@auth-doctor/analyzers-js";
import {
  applySuppressions,
  collectSuppressions,
  createReport,
  detectProject,
  discoverFiles,
  loadConfig,
  mergeConfig,
  routeFiles
} from "@auth-doctor/core";
import type { AuthDoctorReport, ScanMode } from "@auth-doctor/types";

export const VERSION = "0.1.0";

export type ScanCliOptions = {
  directory: string;
  mode: ScanMode;
  diffBase?: string;
  offline?: boolean;
  configPath?: string;
};

export function runScan(options: ScanCliOptions): AuthDoctorReport {
  const start = Date.now();
  const rootDir = path.resolve(options.directory);
  const loadedConfig = loadConfig(rootDir, options.configPath);
  const config = mergeConfig(loadedConfig, { offline: options.offline });
  const changedFiles = options.mode === "full" ? undefined : getChangedFiles(rootDir, options.mode, options.diffBase);
  const files = discoverFiles(rootDir, changedFiles);
  const profile = detectProject(rootDir, files, config);
  const routes = routeFiles(files);
  const rawDiagnostics = analyzeJavaScript({ rootDir, profile, config, files, routeFiles: routes });
  const inlineSuppressions = collectSuppressions(files, config);
  const { diagnostics, suppressions } = applySuppressions(rawDiagnostics, inlineSuppressions, config);
  return createReport({
    version: VERSION,
    profile,
    diagnostics,
    suppressions,
    filesScanned: files.length,
    mode: options.mode,
    offline: config.offline ?? Boolean(process.env.CI),
    durationMs: Date.now() - start
  });
}

function getChangedFiles(rootDir: string, mode: ScanMode, diffBase = "main"): string[] | undefined {
  try {
    const args = mode === "staged" ? ["diff", "--name-only", "--cached"] : ["diff", "--name-only", `${diffBase}...HEAD`];
    const output = execFileSync("git", args, { cwd: rootDir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const files = output.split(/\r?\n/).filter(Boolean);
    return files.length ? files : undefined;
  } catch {
    return undefined;
  }
}
