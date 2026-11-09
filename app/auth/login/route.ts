import type { NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { handleLogin } from "@/lib/auth/handlers";
import { createMsalClient } from "@/lib/auth/msal";

export const dynamic = "force-dynamic";

export function GET(req: NextRequest) {
  return handleLogin(req, getConfig(), createMsalClient);
}
