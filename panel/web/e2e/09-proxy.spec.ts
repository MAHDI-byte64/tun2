import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { goTo, signIn } from "./helpers";

// Nothing here dials a proxy: the panel keeps the setting, never shows the password again, and
// the Add-server form offers the per-server switch once a proxy is on. Dialing through one is
// covered by panel/tests/reverse.rs against a SOCKS5 server in the test.
test("the Proxy section keeps a SOCKS5 proxy and the servers can be switched to it", async ({ page }) => {
  await signIn(page);
  await goTo(page, "settings");
  const card = page.locator("#set-px");
  await expect(card).toBeVisible();

  // Off: only the switch. On: the address, the sign-in and the internet switch.
  await expect(card.getByLabel("Proxy address")).toHaveCount(0);
  await card.getByRole("button", { name: "On", exact: true }).click();
  await card.getByLabel("Proxy address").fill("not an address");
  await card.getByRole("button", { name: /^Save$/ }).click();
  await expect(page.locator(".toast, [role=status]").filter({ hasText: /host:port/i }).first()).toBeVisible();

  await card.getByLabel("Proxy address").fill("127.0.0.1:1080");
  await card.getByLabel("Username").fill("panel");
  await card.getByLabel("Password").fill("s3cret-pass");
  await card.getByRole("button", { name: /^Save$/ }).click();
  await expect(page.locator(".toast, [role=status]").filter({ hasText: /saved/i }).first()).toBeVisible();
  await expect(card.getByLabel("Password")).toHaveValue("");
  await expect(card).toContainText(/No server goes through it yet/i);

  // The page's own answer never carries the password.
  const body = await page.evaluate(async () => (await fetch("./api/proxy", { credentials: "same-origin" })).text());
  expect(body).toContain('"has_password":true');
  expect(body).not.toContain("s3cret-pass");

  // The section passes axe.
  const results = await new AxeBuilder({ page }).include("#set-px").analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);

  // Add server, the panel connects to it: the switch is there, and through the proxy only the
  // TCP transports are offered.
  await goTo(page, "servers");
  await page.locator(".page-band .btn-primary").click();
  await page.getByRole("button", { name: /The panel connects to it/ }).click();
  const proxySwitch = page.locator("#add-proxy");
  await expect(proxySwitch).toBeEnabled();
  await expect(page.getByRole("button", { name: "QUIC", exact: true })).toBeVisible();
  await proxySwitch.check();
  await expect(page.getByRole("button", { name: "QUIC", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "WSS", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  // Off again: the switch in the form is greyed out and says why.
  await goTo(page, "settings");
  await card.getByRole("button", { name: "Off", exact: true }).click();
  await card.getByRole("button", { name: /^Save$/ }).click();
  await expect(page.locator(".toast, [role=status]").filter({ hasText: /saved/i }).first()).toBeVisible();
  await goTo(page, "servers");
  await page.locator(".page-band .btn-primary").click();
  await page.getByRole("button", { name: /The panel connects to it/ }).click();
  await expect(page.locator("#add-proxy")).toBeDisabled();
  await expect(page.getByText(/Set one in Settings/)).toBeVisible();
});
