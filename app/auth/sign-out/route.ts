import type { NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { handleSignOut } from "@/lib/auth/handlers";

export const dynamic = "force-dynamic";

export function POST(req: NextRequest) {
  return handleSignOut(req, getConfig());
}
