export type Config = {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  baseUrl: string;
  sessionSecret: string;
  apiScope: string;
  allowPurge: boolean;
  /** Seconds before a copied value is cleared from the clipboard. */
  clipboardClearSeconds: number;
  /** Seconds before a revealed value is hidden again. */
  revealSeconds: number;
};

class ConfigError extends Error {}

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new ConfigError(`Missing required setting ${name}. See .env.example.`);
  return value;
}

function seconds(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 5 && n <= 600 ? n : fallback;
}

export function parseConfig(env: Record<string, string | undefined>): Config {
  const clientId = required(env, "ENTRA_CLIENT_ID");
  const sessionSecret = required(env, "SESSION_SECRET");
  if (sessionSecret.length < 32) {
    throw new ConfigError("SESSION_SECRET must be at least 32 characters.");
  }
  const baseUrl = required(env, "APP_BASE_URL").replace(/\/+$/, "");
  try {
    new URL(baseUrl);
  } catch {
    throw new ConfigError(
      "APP_BASE_URL must be a full URL, for example https://keyring.example.com",
    );
  }
  return {
    tenantId: required(env, "ENTRA_TENANT_ID"),
    clientId,
    clientSecret: required(env, "ENTRA_CLIENT_SECRET"),
    baseUrl,
    sessionSecret,
    apiScope: env.ENTRA_API_SCOPE?.trim() || `api://${clientId}/access_as_user`,
    allowPurge: env.KEYRING_ALLOW_PURGE?.trim().toLowerCase() === "true",
    clipboardClearSeconds: seconds(env.KEYRING_CLIPBOARD_CLEAR_SECONDS, 30),
    revealSeconds: seconds(env.KEYRING_REVEAL_SECONDS, 60),
  };
}

let cached: Config | undefined;

/** Reads config from the environment once. Throws a clear error if anything is missing. */
export function getConfig(): Config {
  cached ??= parseConfig(process.env);
  return cached;
}
