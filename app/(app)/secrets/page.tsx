import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function SecretsPage() {
  await requireSession();
  return (
    <Page title="Secrets">
      <ComingSoon title="Secrets" />
    </Page>
  );
}
