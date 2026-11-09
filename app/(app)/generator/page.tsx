import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function GeneratorPage() {
  await requireSession();
  return (
    <Page title="Generator">
      <ComingSoon title="Generator" />
    </Page>
  );
}
