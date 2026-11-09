import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function KeysPage() {
  await requireSession();
  return (
    <Page title="Keys">
      <ComingSoon title="Keys" />
    </Page>
  );
}
