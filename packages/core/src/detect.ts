import fs from "node:fs";
import path from "node:path";
import type { AuthDoctorConfig, ProjectProfile, SourceFile } from "@auth-doctor/types";
import { countRouteFiles } from "./files.js";
import { uniqueSorted } from "./path-utils.js";

export function detectProject(rootDir: string, files: SourceFile[], config: AuthDoctorConfig): ProjectProfile {
  const pkg = readPackageJson(rootDir);
  const deps = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {})
  ]);
  const fileNames = files.map((file) => file.relativePath);
  const allText = files.map((file) => file.text).join("\n");

  const frameworks: string[] = [];
  const authProviders: string[] = [...(config.authProviders ?? [])];
  const routers: string[] = [];

  if (deps.has("next") || fileNames.some((file) => file.startsWith("app/") || file.startsWith("pages/"))) {
    frameworks.push("nextjs");
  }
  if (deps.has("express") || /\bfrom\s+["']express["']|\brequire\(["']express["']\)/.test(allText)) {
    frameworks.push("express");
  }
  if (deps.has("next-auth") || deps.has("@auth/core") || /from\s+["']next-auth/.test(allText)) {
    authProviders.push("authjs");
  }
  if (deps.has("@clerk/nextjs") || /\b@clerk\//.test(allText)) {
    authProviders.push("clerk");
  }
  if (deps.has("@supabase/supabase-js") || /SUPABASE|createClient\(/.test(allText)) {
    authProviders.push("supabase");
  }
  if (deps.has("firebase-admin") || deps.has("firebase") || /verifyIdToken|firebase-admin/.test(allText)) {
    authProviders.push("firebase");
  }
  if (deps.has("jsonwebtoken") || deps.has("jose") || /jwt\.decode|jwtDecode|jwtVerify|verify\(/.test(allText)) {
    authProviders.push("custom-jwt");
  }

  if (fileNames.some((file) => file.startsWith("app/"))) routers.push("next-app-router");
  if (fileNames.some((file) => file.startsWith("pages/"))) routers.push("next-pages-router");
  if (frameworks.includes("express")) routers.push("express");

  const languages = uniqueSorted(
    fileNames.flatMap((file) => {
      if (/\.[cm]?tsx?$/.test(file)) return ["typescript"];
      if (/\.[cm]?jsx?$/.test(file)) return ["javascript"];
      if (/\.sql$/.test(file)) return ["sql"];
      return [];
    })
  );

  const protectedRouteCandidates = inferProtectedRoutes(fileNames, config);

  return {
    languages,
    frameworks: uniqueSorted(frameworks),
    authProviders: uniqueSorted(authProviders),
    routers: uniqueSorted(routers),
    packageManager: detectPackageManager(rootDir),
    monorepo: Boolean(pkg.workspaces) || fs.existsSync(path.join(rootDir, "pnpm-workspace.yaml")),
    routeCount: countRouteFiles(files),
    protectedRouteCandidates,
    confidence: frameworks.length || authProviders.length ? "high" : "medium"
  };
}

function readPackageJson(rootDir: string): {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  workspaces?: unknown;
} {
  const file = path.join(rootDir, "package.json");
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function detectPackageManager(rootDir: string): ProjectProfile["packageManager"] {
  if (fs.existsSync(path.join(rootDir, "pnpm-lock.yaml"))) return "pnpm";
  if (fs.existsSync(path.join(rootDir, "yarn.lock"))) return "yarn";
  if (fs.existsSync(path.join(rootDir, "bun.lockb")) || fs.existsSync(path.join(rootDir, "bun.lock"))) return "bun";
  if (fs.existsSync(path.join(rootDir, "package-lock.json"))) return "npm";
  return undefined;
}

function inferProtectedRoutes(files: string[], config: AuthDoctorConfig): string[] {
  const configured = config.protectedRoutes ?? [];
  const inferred = files
    .filter((file) => /(^|\/)(admin|dashboard|settings|account|billing|teams|orgs|organizations|projects|api\/private)(\/|$)/i.test(file))
    .map((file) => file.replace(/\/(route|page)\.[cm]?[jt]sx?$/, ""));
  return uniqueSorted([...configured, ...inferred]);
}

