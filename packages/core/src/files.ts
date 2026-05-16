import fs from "node:fs";
import path from "node:path";
import type { SourceFile } from "@auth-doctor/types";
import { relativePosix } from "./path-utils.js";

const SOURCE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".sql"
]);

const SKIP_DIRS = new Set([
  ".git",
  ".next",
  ".turbo",
  ".vercel",
  "coverage",
  "dist",
  "build",
  "node_modules"
]);

export function discoverFiles(rootDir: string, changedFiles?: string[]): SourceFile[] {
  const absoluteRoot = path.resolve(rootDir);
  const files = changedFiles?.length
    ? changedFiles.map((file) => path.resolve(absoluteRoot, file))
    : walk(absoluteRoot);

  return files
    .filter((file) => SOURCE_EXTENSIONS.has(path.extname(file)))
    .filter((file) => !isDefaultIgnoredSource(relativePosix(absoluteRoot, file)))
    .filter((file) => fs.existsSync(file) && fs.statSync(file).isFile())
    .map((absolutePath) => ({
      absolutePath,
      relativePath: relativePosix(absoluteRoot, absolutePath),
      text: fs.readFileSync(absolutePath, "utf8")
    }));
}

function isDefaultIgnoredSource(relativePath: string): boolean {
  return /(^|\/)(__tests__|test|tests|fixtures?|mocks?)(\/|$)/i.test(relativePath) || /\.(test|spec)\.[cm]?[jt]sx?$/i.test(relativePath);
}

function walk(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) out.push(...walk(path.join(dir, entry.name)));
      continue;
    }
    if (entry.isFile()) out.push(path.join(dir, entry.name));
  }
  return out;
}

export function countRouteFiles(files: SourceFile[]): number {
  return files.filter((file) => isRouteLike(file.relativePath)).length;
}

export function routeFiles(files: SourceFile[]): SourceFile[] {
  return files.filter((file) => isRouteLike(file.relativePath));
}

export function isRouteLike(file: string): boolean {
  return (
    /(^|\/)(route|page|layout|middleware)\.[cm]?[jt]sx?$/.test(file) ||
    /(^|\/)(api|routes|controllers)\//.test(file) ||
    /(^|\/)server\.[cm]?[jt]s$/.test(file) ||
    /(^|\/)app\.[cm]?[jt]s$/.test(file)
  );
}
