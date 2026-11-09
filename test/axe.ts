import axe from "axe-core";

/** Runs axe on a rendered container and returns serious or critical violations. */
export async function seriousViolations(container: Element) {
  const result = await axe.run(container, {
    // jsdom can't compute colours, so contrast is checked by eye and in the browser.
    rules: { "color-contrast": { enabled: false } },
  });
  return result.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id}: ${v.help}`);
}
