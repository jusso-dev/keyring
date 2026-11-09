/**
 * Turns errors from Azure into short, plain sentences. Safe to show in the UI:
 * it never includes the raw error text, which can carry ids or tokens.
 */

export type Area = "secrets" | "certificates" | "keys" | "vaults" | "audit";
export type Action = "read" | "write";

export type FriendlyError = {
  kind:
    | "signed-out"
    | "forbidden"
    | "not-found"
    | "conflict"
    | "soft-deleted"
    | "throttled"
    | "network"
    | "private-network"
    | "unknown";
  title: string;
  message: string;
  /** The RBAC role to ask for, when a 403 is the problem. */
  role?: string;
  retryable: boolean;
};

const ROLES: Record<Area, Record<Action, string>> = {
  secrets: { read: "Key Vault Secrets User", write: "Key Vault Secrets Officer" },
  certificates: { read: "Key Vault Certificate User", write: "Key Vault Certificates Officer" },
  keys: { read: "Key Vault Crypto User", write: "Key Vault Crypto Officer" },
  vaults: { read: "Reader", write: "Key Vault Contributor" },
  audit: { read: "Log Analytics Reader", write: "Log Analytics Reader" },
};

const NOUN: Record<Area, string> = {
  secrets: "secret",
  certificates: "certificate",
  keys: "key",
  vaults: "vault",
  audit: "audit log",
};

export function requiredRole(area: Area, action: Action): string {
  return ROLES[area][action];
}

type ErrorLike = {
  statusCode?: number;
  status?: number;
  code?: string;
  name?: string;
  message?: string;
};

const NETWORK_CODES = new Set([
  "ENOTFOUND",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "REQUEST_SEND_ERROR",
]);

export function toFriendlyError(
  err: unknown,
  context: { area: Area; action?: Action; name?: string } = { area: "secrets" },
): FriendlyError {
  const e = (err && typeof err === "object" ? err : {}) as ErrorLike;
  const status = e.statusCode ?? e.status;
  const code = e.code ?? "";
  const action = context.action ?? "read";
  const noun = NOUN[context.area];
  const item = context.name ? `"${context.name}"` : `this ${noun}`;

  if (status === 401) {
    return {
      kind: "signed-out",
      title: "Please sign in again",
      message: "Azure didn't accept your sign-in. Sign in again and retry.",
      retryable: true,
    };
  }
  if (status === 403) {
    if (code === "ForbiddenByConnection" || /public network access/i.test(e.message ?? "")) {
      return privateNetwork();
    }
    const role = requiredRole(context.area, action);
    const what = action === "write" ? `make changes to ${noun}s` : `see ${noun}s`;
    return {
      kind: "forbidden",
      title: "You don't have access",
      message: `You don't have permission to ${what} here. Ask your Azure admin for the ${role} role on this vault.`,
      role,
      retryable: false,
    };
  }
  if (status === 404) {
    return {
      kind: "not-found",
      title: "Not found",
      message: `We couldn't find ${item}. It may have been deleted or renamed.`,
      retryable: false,
    };
  }
  if (status === 409) {
    if (/deleted/i.test(code) || /deleted/i.test(e.message ?? "")) {
      return {
        kind: "soft-deleted",
        title: "That name is taken by a deleted item",
        message: `A deleted ${noun} called ${item} still exists. Recover it, or pick another name.`,
        retryable: false,
      };
    }
    return {
      kind: "conflict",
      title: "Someone else changed this",
      message: `${capitalise(item)} changed or is busy. Refresh and try again.`,
      retryable: true,
    };
  }
  if (status === 429) {
    return {
      kind: "throttled",
      title: "Azure is busy",
      message: "Too many requests in a short time. Wait a few seconds and try again.",
      retryable: true,
    };
  }
  if (NETWORK_CODES.has(code) || e.name === "AbortError" || /fetch failed/i.test(e.message ?? "")) {
    return {
      kind: "network",
      title: "Can't reach Azure",
      message:
        "We couldn't connect. If this vault only allows private network access, Keyring needs to run inside that network.",
      retryable: true,
    };
  }
  return {
    kind: "unknown",
    title: "Something went wrong",
    message: "Azure returned an error we didn't expect. Try again in a moment.",
    retryable: true,
  };
}

function privateNetwork(): FriendlyError {
  return {
    kind: "private-network",
    title: "This vault is private",
    message:
      "This vault blocks access from the public internet. Keyring needs to run inside the vault's network, or an admin needs to allow this network.",
    retryable: false,
  };
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
