export type Severity = "critical" | "error" | "warning" | "info";

export type Category =
  | "authentication"
  | "authorization"
  | "session"
  | "oauth"
  | "jwt"
  | "secrets"
  | "csrf"
  | "cookies"
  | "middleware"
  | "provider"
  | "database";

export type Confidence = "high" | "medium" | "low";

export type Diagnostic = {
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  file: string;
  line?: number;
  column?: number;
  framework?: string;
  confidence: Confidence;
  evidence: string[];
  whyItMatters: string;
  recommendation: string;
  unsafePattern?: string;
  safePattern?: string;
  docs?: string[];
  suppressionHint?: string;
};

export type Suppression = {
  ruleId: string;
  file: string;
  line: number;
  kind: "next-line" | "line" | "block" | "config";
  reason?: string;
  used: boolean;
};

export type ProjectProfile = {
  languages: string[];
  frameworks: string[];
  authProviders: string[];
  routers: string[];
  packageManager?: "npm" | "pnpm" | "yarn" | "bun";
  monorepo?: boolean;
  routeCount: number;
  protectedRouteCandidates: string[];
  confidence: Confidence;
};

export type ScoreLabel = "Strong" | "Good" | "Risky" | "Critical";

export type AuthDoctorReport = {
  ok: boolean;
  version: string;
  score: {
    value: number;
    label: ScoreLabel;
  } | null;
  project: ProjectProfile;
  summary: {
    critical: number;
    error: number;
    warning: number;
    info: number;
    uniqueRules: number;
    filesScanned: number;
    routesAnalyzed: number;
  };
  diagnostics: Diagnostic[];
  suppressions: Suppression[];
  metadata: {
    mode: "full" | "diff" | "staged";
    offline: boolean;
    durationMs: number;
  };
};

export type AuthDoctorConfig = {
  ignore?: {
    rules?: string[];
    files?: string[];
    overrides?: Array<{ files: string[]; rules: string[] }>;
  };
  protectedRoutes?: string[];
  publicRoutes?: string[];
  adminRoutes?: string[];
  tenantKeys?: string[];
  authProviders?: string[];
  failOn?: "critical" | "error" | "warning" | "none";
  offline?: boolean;
  respectInlineDisables?: boolean;
};

export type ScanMode = "full" | "diff" | "staged";

export type ScanOptions = {
  rootDir: string;
  mode?: ScanMode;
  offline?: boolean;
  configPath?: string;
  changedFiles?: string[];
  noSecrets?: boolean;
};

export type SourceFile = {
  absolutePath: string;
  relativePath: string;
  text: string;
};

export type RuleContext = {
  rootDir: string;
  profile: ProjectProfile;
  config: AuthDoctorConfig;
  files: SourceFile[];
  routeFiles: SourceFile[];
};

export type Rule = {
  id: string;
  title: string;
  category: Category;
  defaultSeverity: Severity;
  appliesTo(profile: ProjectProfile): boolean;
  run(context: RuleContext): Diagnostic[];
};

