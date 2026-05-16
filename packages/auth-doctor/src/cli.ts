#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { installAgentRules } from "@auth-doctor/agent-install";
import {
  explainSuppressionAt,
  failForThreshold,
  loadConfig
} from "@auth-doctor/core";
import { toGithubAnnotations } from "@auth-doctor/integration-github-action";
import { toSarif } from "@auth-doctor/sarif";
import type { AuthDoctorReport, Diagnostic, ScanMode } from "@auth-doctor/types";
import { runScan, VERSION } from "./scan.js";

type CliOptions = {
  command?: "scan" | "install";
  directory: string;
  verbose: boolean;
  score: boolean;
  json: boolean;
  sarif: boolean;
  annotations: boolean;
  explain?: string;
  output?: string;
  mode: ScanMode;
  diffBase?: string;
  offline?: boolean;
  failOn?: "critical" | "error" | "warning" | "none";
  configPath?: string;
  noAgentHints: boolean;
};

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (options.command === "install") {
    const report = runScan(options);
    const results = installAgentRules(path.resolve(options.directory), report.project);
    for (const result of results) {
      console.log(`${result.created ? "created" : "updated"} ${result.file} (${result.target})`);
    }
    return;
  }

  const report = runScan(options);
  if (options.explain) {
    printExplain(report, options.explain);
  } else if (options.json) {
    writeOrPrint(JSON.stringify(report, null, 2), options.output);
  } else if (options.sarif) {
    writeOrPrint(JSON.stringify(toSarif(report), null, 2), options.output);
  } else if (options.annotations) {
    writeOrPrint(toGithubAnnotations(report).join("\n"), options.output);
  } else if (options.score) {
    writeOrPrint(String(report.score?.value ?? "n/a"), options.output);
  } else {
    printTerminalReport(report, options);
  }

  const threshold = options.failOn ?? loadConfig(path.resolve(options.directory), options.configPath).failOn ?? "critical";
  if (failForThreshold(report.diagnostics, threshold)) process.exitCode = 1;
}

function parseArgs(args: string[]): CliOptions {
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  if (args.includes("--version")) {
    console.log(VERSION);
    process.exit(0);
  }

  const options: CliOptions = {
    command: "scan",
    directory: ".",
    verbose: false,
    score: false,
    json: false,
    sarif: false,
    annotations: false,
    mode: "full",
    noAgentHints: false
  };

  const positional: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "install":
        options.command = "install";
        break;
      case "--verbose":
        options.verbose = true;
        break;
      case "--score":
        options.score = true;
        break;
      case "--json":
        options.json = true;
        break;
      case "--sarif":
        options.sarif = true;
        break;
      case "--annotations":
        options.annotations = true;
        break;
      case "--staged":
        options.mode = "staged";
        break;
      case "--full":
        options.mode = "full";
        break;
      case "--offline":
        options.offline = true;
        break;
      case "--no-secrets":
        break;
      case "--no-agent-hints":
        options.noAgentHints = true;
        break;
      case "--diff":
        options.mode = "diff";
        if (args[index + 1] && !args[index + 1].startsWith("--")) {
          options.diffBase = args[++index];
        }
        break;
      case "--fail-on":
        options.failOn = readEnum(args[++index], ["critical", "error", "warning", "none"] as const, "--fail-on");
        break;
      case "--config":
        options.configPath = requiredValue(args[++index], "--config");
        break;
      case "--output":
      case "-o":
        options.output = requiredValue(args[++index], arg);
        break;
      case "--project":
        index += 1;
        break;
      case "--explain":
      case "--why":
        options.explain = requiredValue(args[++index], arg);
        break;
      default:
        if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
        positional.push(arg);
    }
  }

  const directory = positional.find((value) => value !== "install");
  if (directory) options.directory = directory;
  return options;
}

function readEnum<T extends string>(value: string | undefined, allowed: T[], flag: string): T {
  const next = requiredValue(value, flag);
  if (!allowed.includes(next as T)) throw new Error(`${flag} must be one of ${allowed.join(", ")}`);
  return next as T;
}

function requiredValue(value: string | undefined, flag: string): string {
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

function printTerminalReport(report: AuthDoctorReport, options: CliOptions): void {
  const score = report.score ? `${report.score.value}/100 ${report.score.label}` : "n/a";
  console.log(`Auth Doctor ${report.version}`);
  console.log(`Score: ${score}`);
  console.log(
    `Findings: ${report.summary.critical} critical, ${report.summary.error} error, ${report.summary.warning} warning, ${report.summary.info} info`
  );
  console.log(`Project: ${formatList(report.project.frameworks)} | Auth: ${formatList(report.project.authProviders)} | Routes: ${report.project.routeCount}`);
  console.log("");

  if (!report.diagnostics.length) {
    console.log("No high-signal auth issues detected.");
    return;
  }

  for (const diagnostic of report.diagnostics) {
    printDiagnostic(diagnostic, options);
  }
}

function writeOrPrint(content: string, output?: string): void {
  if (!output) {
    console.log(content);
    return;
  }
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, `${content}\n`);
}

function printDiagnostic(diagnostic: Diagnostic, options: CliOptions): void {
  console.log(`${diagnostic.severity.toUpperCase()} ${diagnostic.ruleId}`);
  console.log(`  ${diagnostic.file}:${diagnostic.line ?? 1}`);
  console.log(`  ${diagnostic.title}`);
  console.log(`  Why: ${diagnostic.whyItMatters}`);
  console.log(`  Fix: ${diagnostic.recommendation}`);
  if (diagnostic.evidence.length) console.log(`  Evidence: ${diagnostic.evidence.join("; ")}`);
  if (!options.noAgentHints && diagnostic.suppressionHint) console.log(`  Suppress narrowly: ${diagnostic.suppressionHint}`);
  if (options.verbose && diagnostic.docs?.length) console.log(`  Docs: ${diagnostic.docs.join(", ")}`);
  console.log("");
}

function printExplain(report: AuthDoctorReport, location: string): void {
  const [file, lineValue] = splitLocation(location);
  const line = Number(lineValue);
  const diagnostics = report.diagnostics.filter((diagnostic) => diagnostic.file === file && (!line || diagnostic.line === line));
  const suppressions = explainSuppressionAt(file, line, report.suppressions);
  if (!diagnostics.length && !suppressions.length) {
    console.log(`No Auth Doctor finding or suppression at ${location}.`);
    return;
  }
  for (const diagnostic of diagnostics) {
    printDiagnostic(diagnostic, { noAgentHints: false, verbose: true } as CliOptions);
  }
  for (const suppression of suppressions) {
    console.log(`Suppression recognized: ${suppression.ruleId} at ${suppression.file}:${suppression.line} (${suppression.kind}, used=${suppression.used})`);
  }
}

function splitLocation(location: string): [string, string] {
  const index = location.lastIndexOf(":");
  if (index === -1) return [location, ""];
  return [location.slice(0, index), location.slice(index + 1)];
}

function formatList(values: string[]): string {
  return values.length ? values.join(", ") : "unknown";
}

function printHelp(): void {
  console.log(`auth-doctor [directory] [options]

Commands:
  install                         Install project-specific auth rules for coding agents.

Options:
  --version
  --verbose
  --score
  --json
  --sarif
  --project <name>
  --diff [base]
  --staged
  --full
  --offline
  --fail-on <critical|error|warning|none>
  --annotations
  --explain <file:line>
  --why <file:line>
  --no-secrets
  --no-agent-hints
  --config <path>
  --output, -o <path>`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
