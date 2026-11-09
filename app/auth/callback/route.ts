import type { NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { handleCallback } from "@/lib/auth/handlers";
import { createMsalClient } from "@/lib/auth/msal";

export const dynamic = "force-dynamic";

export function GET(req: NextRequest) {
  return handleCallback(req, getConfig(), createMsalClient);
}
