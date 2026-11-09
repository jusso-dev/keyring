import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function VaultsPage() {
  await requireSession();
  return (
    <Page title="Vaults">
      <ComingSoon title="Vaults" />
    </Page>
  );
}
