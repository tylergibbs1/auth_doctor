import path from "node:path";

export function toPosix(value: string): string {
  return value.split(path.sep).join("/");
}

export function relativePosix(rootDir: string, file: string): string {
  return toPosix(path.relative(rootDir, file));
}

export function globToRegExp(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "<<<GLOBSTAR>>>")
    .replace(/\*/g, "[^/]*")
    .replace(/<<<GLOBSTAR>>>/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

export function matchesAnyGlob(file: string, globs: string[] | undefined): boolean {
  if (!globs?.length) return false;
  const normalized = toPosix(file);
  return globs.some((glob) => globToRegExp(toPosix(glob)).test(normalized));
}

export function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

