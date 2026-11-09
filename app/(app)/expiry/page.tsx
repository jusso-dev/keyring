import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function ExpiryPage() {
  await requireSession();
  return (
    <Page title="Expiry">
      <ComingSoon title="Expiry" />
    </Page>
  );
}
