/** Short, friendly messages shown on the sign-in page. */
export function signInMessage(params: { reason?: string; error?: string }): string | undefined {
  if (params.reason === "expired") return "Your session ended. Sign in again to carry on.";
  switch (params.error) {
    case "cancelled":
      return "Sign-in was cancelled. You can try again when you're ready.";
    case "state":
      return "That sign-in link had expired. Please try again.";
    case "consent":
      return "Your organisation needs to approve Keyring before you can use it. Ask your Entra ID admin to grant consent.";
    case "failed":
      return "Sign-in didn't work. Please try again.";
    default:
      return undefined;
  }
}
