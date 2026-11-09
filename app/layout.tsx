import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Keyring",
  description: "Find and manage Azure Key Vault secrets, certificates and keys in plain English.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en-AU" className="h-full antialiased">
      <body className="flex min-h-full flex-col">{children}</body>
    </html>
  );
}
