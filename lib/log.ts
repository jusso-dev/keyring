import "server-only";

/**
 * The only logger the server should use. It writes structured lines and never
 * accepts free-form objects, so secret values and tokens can't slip in by
 * accident. Pass short, fixed messages and safe fields only (ids, names, status codes).
 */
type Level = "info" | "warn" | "error";
type SafeFields = Record<string, string | number | boolean | undefined>;

const TOKEN_LIKE = /\b(eyJ[\w-]+\.[\w-]+\.[\w-]+|[A-Za-z0-9+/_-]{40,}={0,2})\b/g;

export function scrub(value: string): string {
  return value.replace(TOKEN_LIKE, "[redacted]");
}

function write(level: Level, message: string, fields?: SafeFields) {
  const line: Record<string, unknown> = {
    level,
    time: new Date().toISOString(),
    message: scrub(message),
  };
  for (const [key, v] of Object.entries(fields ?? {})) {
    line[key] = typeof v === "string" ? scrub(v) : v;
  }
  // eslint-disable-next-line no-console
  (level === "error" ? console.error : level === "warn" ? console.warn : console.log)(
    JSON.stringify(line),
  );
}

export const log = {
  info: (message: string, fields?: SafeFields) => write("info", message, fields),
  warn: (message: string, fields?: SafeFields) => write("warn", message, fields),
  error: (message: string, fields?: SafeFields) => write("error", message, fields),
};
