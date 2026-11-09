import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function AuditPage() {
  await requireSession();
  return (
    <Page title="Audit">
      <ComingSoon title="Audit" />
    </Page>
  );
}
