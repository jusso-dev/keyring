import "server-only";
import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";
import type { Config } from "@/lib/config";
import { log } from "@/lib/log";

/**
 * One MSAL client per signed-in session. Its token cache lives in memory only
 * (no cache plugin), so tokens go away with the session or a restart.
 */
export function createMsalClient(config: Config): ConfidentialClientApplication {
  return new ConfidentialClientApplication({
    auth: {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      authority: `https://login.microsoftonline.com/${config.tenantId}`,
    },
    system: {
      loggerOptions: {
        piiLoggingEnabled: false,
        logLevel: LogLevel.Warning,
        loggerCallback: (level, message, containsPii) => {
          if (containsPii) return;
          if (level === LogLevel.Error) log.error("msal", { detail: message });
          else if (level === LogLevel.Warning) log.warn("msal", { detail: message });
        },
      },
    },
  });
}

export function signInScopes(config: Config): string[] {
  return [config.apiScope, "openid", "profile", "offline_access"];
}

export function redirectUri(config: Config): string {
  return `${config.baseUrl}/auth/callback`;
}

export function endSessionUrl(config: Config): string {
  const url = new URL(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/logout`);
  url.searchParams.set("post_logout_redirect_uri", `${config.baseUrl}/signed-out`);
  return url.toString();
}
