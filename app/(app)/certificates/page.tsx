import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { requireSession } from "@/lib/auth/session";

export default async function CertificatesPage() {
  await requireSession();
  return (
    <Page title="Certificates">
      <ComingSoon title="Certificates" />
    </Page>
  );
}
