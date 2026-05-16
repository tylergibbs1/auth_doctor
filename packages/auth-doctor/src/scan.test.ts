import path from "node:path";
import { describe, expect, it } from "vitest";
import { runScan } from "./scan.js";
import { toSarif } from "@auth-doctor/sarif";

const fixtures = path.resolve(process.cwd(), "packages/test-fixtures");

function scanFixture(name: string) {
  return runScan({
    directory: path.join(fixtures, name),
    mode: "full",
    offline: true
  });
}

describe("Auth Doctor scan", () => {
  it("detects high-signal JWT and Express auth issues", () => {
    const report = scanFixture("express-jwt-vulnerable");
    const rules = new Set(report.diagnostics.map((diagnostic) => diagnostic.ruleId));

    expect(rules.has("auth/jwt-not-verified")).toBe(true);
    expect(rules.has("auth/middleware-after-route")).toBe(true);
    expect(rules.has("auth/insecure-direct-object-reference")).toBe(true);
    expect(report.score?.label).toBe("Risky");
  });

  it("detects Next.js Auth.js and authorization gaps", () => {
    const report = scanFixture("next-authjs-vulnerable");
    const rules = new Set(report.diagnostics.map((diagnostic) => diagnostic.ruleId));

    expect(rules.has("auth/authenticated-not-authorized")).toBe(true);
    expect(rules.has("auth/authjs-unsafe-callback-role")).toBe(true);
    expect(rules.has("auth/client-only-protection")).toBe(true);
    expect(rules.has("auth/next-middleware-matcher-gap")).toBe(true);
  });

  it("detects Supabase service key exposure and missing RLS", () => {
    const report = scanFixture("supabase-vulnerable");
    const rules = new Set(report.diagnostics.map((diagnostic) => diagnostic.ruleId));

    expect(rules.has("auth/supabase-service-key-exposed")).toBe(true);
    expect(rules.has("auth/public-env-secret-name")).toBe(true);
    expect(rules.has("auth/supabase-rls-disabled")).toBe(true);
  });

  it("detects Firebase token parsing without verification", () => {
    const report = scanFixture("firebase-vulnerable");
    const rules = new Set(report.diagnostics.map((diagnostic) => diagnostic.ruleId));

    expect(rules.has("auth/firebase-id-token-not-verified")).toBe(true);
  });

  it("keeps healthy fixture mostly quiet", () => {
    const report = scanFixture("healthy-next");
    expect(report.summary.critical).toBe(0);
    expect(report.summary.error).toBe(0);
    expect(report.score?.value).toBeGreaterThanOrEqual(90);
  });

  it("renders SARIF", () => {
    const report = scanFixture("express-jwt-vulnerable");
    const sarif = toSarif(report);
    expect(sarif.version).toBe("2.1.0");
  });
});
