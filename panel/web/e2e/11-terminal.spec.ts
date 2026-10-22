import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { goTo, signIn } from "./helpers";

// The panel's own server allows the terminal in the e2e settings (terminal = true): a shell opens on the Logs
// page, echoes what is typed, and closes.
test("the Logs page opens a terminal to a server that allows it", async ({ page }) => {
  await signIn(page);
  await goTo(page, "logs");
  const card = page.locator(".term-card");
  await expect(card).toBeVisible();
  await card.locator("#term-server").selectOption({ index: 0 });
  await card.getByRole("button", { name: /^Open$/ }).click();
  await expect(card.locator(".term-state")).toHaveText(/Connected/, { timeout: 20_000 });
  await page.keyboard.type("echo kariz-$((40+2))\n");
  await expect(card.locator(".xterm-rows")).toContainText("kariz-42", { timeout: 20_000 });

  const results = await new AxeBuilder({ page }).include(".term-card").disableRules(["scrollable-region-focusable"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);

  await card.getByRole("button", { name: /^Close$/ }).click();
  await expect(card.locator(".term-state")).toHaveText(/Closed/);
});
