import fs from "node:fs";
import path from "node:path";
import type { ProjectProfile } from "@auth-doctor/types";

export type AgentTarget = "claude" | "cursor" | "codex" | "opencode";

export type InstallResult = {
  target: AgentTarget;
  file: string;
  created: boolean;
};

export function installAgentRules(rootDir: string, profile: ProjectProfile, targets = detectAgentTargets(rootDir)): InstallResult[] {
  if (!targets.length) targets = ["codex", "cursor", "claude", "opencode"];
  return targets.map((target) => writeTarget(rootDir, target, buildGuidance(profile)));
}

export function detectAgentTargets(rootDir: string): AgentTarget[] {
  const targets: AgentTarget[] = [];
  if (fs.existsSync(path.join(rootDir, "CLAUDE.md")) || fs.existsSync(path.join(rootDir, ".claude"))) targets.push("claude");
  if (fs.existsSync(path.join(rootDir, ".cursorrules")) || fs.existsSync(path.join(rootDir, ".cursor"))) targets.push("cursor");
  if (fs.existsSync(path.join(rootDir, "AGENTS.md")) || fs.existsSync(path.join(rootDir, ".codex"))) targets.push("codex");
  if (fs.existsSync(path.join(rootDir, "opencode.json")) || fs.existsSync(path.join(rootDir, ".opencode"))) targets.push("opencode");
  return targets;
}

function writeTarget(rootDir: string, target: AgentTarget, guidance: string): InstallResult {
  const relativeFile = fileForTarget(target);
  const absoluteFile = path.join(rootDir, relativeFile);
  fs.mkdirSync(path.dirname(absoluteFile), { recursive: true });
  const existing = fs.existsSync(absoluteFile) ? fs.readFileSync(absoluteFile, "utf8") : "";
  const markerStart = "<!-- auth-doctor:start -->";
  const markerEnd = "<!-- auth-doctor:end -->";
  const block = `${markerStart}\n${guidance.trim()}\n${markerEnd}\n`;
  const next = existing.includes(markerStart)
    ? existing.replace(new RegExp(`${escapeRegExp(markerStart)}[\\s\\S]*?${escapeRegExp(markerEnd)}\\n?`), block)
    : `${existing.trimEnd()}${existing.trim() ? "\n\n" : ""}${block}`;
  fs.writeFileSync(absoluteFile, next);
  return { target, file: relativeFile, created: !existing };
}

function fileForTarget(target: AgentTarget): string {
  switch (target) {
    case "claude":
      return "CLAUDE.md";
    case "cursor":
      return ".cursor/rules/auth-doctor.mdc";
    case "codex":
      return "AGENTS.md";
    case "opencode":
      return ".opencode/auth-doctor.md";
  }
}

export function buildGuidance(profile: ProjectProfile): string {
  const providers = profile.authProviders.length ? profile.authProviders.join(", ") : "custom or not yet detected";
  const frameworks = profile.frameworks.length ? profile.frameworks.join(", ") : "not yet detected";
  return `# Auth Doctor Rules

Project auth profile:
- Frameworks: ${frameworks}
- Auth providers: ${providers}
- Routers: ${profile.routers.join(", ") || "not yet detected"}

Never rely on client-side checks as the only protection for private data.

For every new route handler, server action, loader, API route, or RPC endpoint that reads or writes user data:

1. Identify the current user server-side.
2. Verify access to the resource by owner, tenant, role, or explicit permission.
3. Do not trust \`userId\`, \`role\`, \`orgId\`, \`tenantId\`, or \`isAdmin\` from the request body, query string, headers, local storage, or client session object.
4. Keep service role keys, admin keys, private keys, JWT secrets, and refresh tokens out of client-reachable code and public environment variables.
5. Verify JWT signatures and expected issuer/audience before using claims.
6. Use HttpOnly, Secure, SameSite cookies for session material.
7. Add CSRF, origin, webhook signature, or equivalent validation for cookie-authenticated state-changing routes.
8. Run \`npx -y auth-doctor@latest --staged\` before finishing auth-related changes.

Forbidden patterns:

- \`jwt.decode()\` or \`jwtDecode()\` used as authorization.
- Admin or tenant checks that exist only in UI components.
- Database queries by arbitrary \`params.id\` without owner, tenant, membership, role, or permission constraints.
- \`NEXT_PUBLIC_*\`, \`VITE_*\`, or public env names containing \`SECRET\`, \`SERVICE_ROLE\`, \`PRIVATE\`, \`TOKEN\`, or \`ADMIN_KEY\`.
- Express auth middleware registered after protected routes.
`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

