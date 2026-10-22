import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { goTo, signIn } from "./helpers";
import { readStack } from "./stack";

// Settings > Metrics switches the Prometheus endpoint on; it answers with the token, and not without.
test("the Metrics section switches the Prometheus endpoint on and shows its token", async ({ page, request }) => {
  await signIn(page);
  await goTo(page, "settings");
  const card = page.locator("#set-met");
  await expect(card).toBeVisible();
  const url = `${readStack().base}metrics`;

  // Off: a 404, like any unknown address.
  expect((await request.get(url, { ignoreHTTPSErrors: true })).status()).toBe(404);

  await card.getByRole("button", { name: "On", exact: true }).click();
  await expect(card).toContainText(/Token/);
  const token = (await card.locator(".copy-val-text").nth(1).textContent())?.trim() ?? "";
  expect(token.length).toBeGreaterThan(20);

  // On: the token reads it; nothing else does.
  const without = await request.get(url, { ignoreHTTPSErrors: true });
  expect(without.status()).toBe(401);
  const wrong = await request.get(url, { ignoreHTTPSErrors: true, headers: { Authorization: "Bearer not-it" } });
  expect(wrong.status()).toBe(401);
  const ok = await request.get(url, { ignoreHTTPSErrors: true, headers: { Authorization: `Bearer ${token}` } });
  expect(ok.status()).toBe(200);
  const text = await ok.text();
  expect(text).toContain("kariz_panel_info{version=");
  expect(text).toContain("kariz_server_online{server=");

  // A new token: the old one stops.
  await card.getByRole("button", { name: /New token/ }).click();
  await expect(page.locator(".toast, [role=status]").filter({ hasText: /new token/i }).first()).toBeVisible();
  const stale = await request.get(url, { ignoreHTTPSErrors: true, headers: { Authorization: `Bearer ${token}` } });
  expect(stale.status()).toBe(401);

  const results = await new AxeBuilder({ page }).include("#set-met").analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);

  await card.getByRole("button", { name: "Off", exact: true }).click();
  await expect(card).not.toContainText(/Token/);
  expect((await request.get(url, { ignoreHTTPSErrors: true })).status()).toBe(404);
});
