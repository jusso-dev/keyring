import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** A new random identifier, 256 bits, base64url. */
export function newId(): string {
  return randomBytes(32).toString("base64url");
}

function mac(id: string, secret: string): string {
  return createHmac("sha256", secret).update(id).digest("base64url");
}

/** Signs an id so the cookie can't be forged or guessed. */
export function signId(id: string, secret: string): string {
  return `${id}.${mac(id, secret)}`;
}

/** Returns the id if the signature is valid, otherwise undefined. */
export function verifySignedId(value: string | undefined, secret: string): string | undefined {
  if (!value) return undefined;
  const dot = value.lastIndexOf(".");
  if (dot <= 0) return undefined;
  const id = value.slice(0, dot);
  const given = Buffer.from(value.slice(dot + 1));
  const expected = Buffer.from(mac(id, secret));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return undefined;
  return id;
}

export const SESSION_COOKIE = "keyring_session";
export const AUTH_FLOW_COOKIE = "keyring_auth";

export function cookieOptions(baseUrl: string, maxAgeSeconds?: number) {
  const url = new URL(baseUrl);
  const isLocalHttp = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname);
  return {
    httpOnly: true,
    secure: !isLocalHttp,
    sameSite: "lax" as const,
    path: "/",
    ...(maxAgeSeconds === undefined ? {} : { maxAge: maxAgeSeconds }),
  };
}
