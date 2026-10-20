import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { newLink } from "./stack";

/** English, the low-power look (no long animations), and a fresh one-time link. */
export async function signIn(page: Page, opts: { lang?: "en" | "fa"; theme?: "night" | "dawn" } = {}) {
  await page.addInitScript(
    ([lang, theme]) => {
      // Only what the person has not chosen yet: a reload must keep their choice.
      const put = (k: string, v: string) => localStorage.getItem(k) === null && localStorage.setItem(k, v);
      put("kariz.lang", lang);
      put("kariz.theme", theme);
      put("kariz.low", "1");
    },
    [opts.lang ?? "en", opts.theme ?? "night"],
  );
  await page.goto(newLink());
  await expect(page.locator("#app .rail")).toBeVisible({ timeout: 30_000 });
}

/** The pages by the order of the rail: map, servers, tunnels, networks, iptester, logs, settings. */
export const PAGES = ["map", "servers", "tunnels", "networks", "iptester", "logs", "settings"] as const;

export async function goTo(page: Page, name: (typeof PAGES)[number]) {
  const items = page.locator(".rail-item:not(.rail-extra)");
  await items.nth(PAGES.indexOf(name)).click();
  await expect(page.locator(".page.is-on").first()).toBeVisible();
}
