import fs from "node:fs";
import path from "node:path";
import type { AuthDoctorConfig } from "@auth-doctor/types";

export function loadConfig(rootDir: string, configPath?: string): AuthDoctorConfig {
  const explicitPath = configPath ? path.resolve(rootDir, configPath) : undefined;
  if (explicitPath) return readJsonConfig(explicitPath);

  const jsonPath = path.join(rootDir, "auth-doctor.config.json");
  if (fs.existsSync(jsonPath)) return readJsonConfig(jsonPath);

  const packagePath = path.join(rootDir, "package.json");
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, "utf8")) as { authDoctor?: AuthDoctorConfig };
    if (pkg.authDoctor) return pkg.authDoctor;
  }

  return {};
}

function readJsonConfig(file: string): AuthDoctorConfig {
  if (!fs.existsSync(file)) {
    throw new Error(`Config file not found: ${file}`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8")) as AuthDoctorConfig;
}

export function mergeConfig(base: AuthDoctorConfig, overrides: Partial<AuthDoctorConfig>): AuthDoctorConfig {
  return {
    ...base,
    ...overrides,
    ignore: {
      ...base.ignore,
      ...overrides.ignore
    }
  };
}

