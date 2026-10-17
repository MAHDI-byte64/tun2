import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const B = "/tun2";
const PAGES = [
  "/",
  "/docs/",
  "/docs/how-it-works/",
  "/docs/transports/",
  "/docs/troubleshooting/",
  "/try/",
  "/fa/",
  "/fa/docs/",
  "/fa/docs/how-it-works/",
  "/fa/docs/getting-started/",
  "/fa/docs/transports/",
  "/docs/tour/",
  "/fa/docs/tour/",
  "/docs/video/",
  "/fa/docs/video/",
  "/fa/docs/using-the-panel/",
];

async function open(page: Page, path: string, theme: "night" | "dawn" = "night") {
  await page.addInitScript((t) => localStorage.setItem("kariz-site-theme", t), theme);
  await page.goto(`${B}${path}`);
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
}

for (const theme of ["night", "dawn"] as const) {
  for (const path of PAGES) {
    test(`${path} passes axe (${theme})`, async ({ page }) => {
      await open(page, path, theme);
      // The hero and its scroll are pictures with no words in them; the demo has its own tests.
      const r = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .exclude("iframe")
        .exclude("[data-hero-canvas]")
        .analyze();
      expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
    });
  }
}

test("no page scrolls sideways on a phone", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  for (const path of PAGES) {
    await page.goto(`${B}${path}`);
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(over, `${path} is wider than the phone by ${over}px`).toBeLessThanOrEqual(1);
  }
});

test("the language switch keeps the page and turns it around", async ({ page }) => {
  await open(page, "/docs/transports/");
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
  await page.getByRole("link", { name: "Read this page in Persian" }).click();
  await expect(page).toHaveURL(`${B}/fa/docs/transports/`);
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  // Every page is translated: the Persian text, right to left, with no notice.
  await expect(page.locator(".notice")).toHaveCount(0);
  await expect(page.locator("article.prose")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("article.prose h1")).toHaveText("ترنسپورت‌ها");
  await page.getByRole("link", { name: "خواندن این صفحه به انگلیسی" }).click();
  await expect(page).toHaveURL(`${B}/docs/transports/`);
});

test("a translated page is Persian all the way, code stays left to right", async ({ page }) => {
  await open(page, "/fa/docs/getting-started/");
  await expect(page.locator("article.prose")).toHaveAttribute("dir", "rtl");
  await expect(page.locator(".notice")).toHaveCount(0);
  await expect(page.locator(".prose .code").first()).toBeVisible(); // wrapped by the page script
  // A block the page script wrapped: the first <pre> of the page is a mermaid diagram that is
  // replaced by its drawing once it is ready, and an element that went away has no direction.
  const dir = await page.locator("article.prose .code pre").first().evaluate((el) => getComputedStyle(el).direction);
  expect(dir).toBe("ltr");
});

test("search finds a page, from the keyboard", async ({ page }) => {
  await open(page, "/docs/");
  await page.keyboard.press("Control+k");
  await expect(page.locator("dialog.search")).toBeVisible();
  await page.keyboard.type("early data");
  await expect(page.locator("[data-search-results] li").first()).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`${B}/docs/[a-z0-9-]+/`));
  await expect(page).not.toHaveURL(`${B}/docs/`);
});

test("search in Persian looks only at the Persian pages", async ({ page }) => {
  await open(page, "/fa/docs/");
  await page.keyboard.press("Control+k");
  await page.keyboard.type("عیب");
  const first = page.locator("[data-search-results] li a").first();
  await expect(first).toBeVisible();
  expect(await first.getAttribute("href")).toContain("/fa/");
});

test("the transport chooser gives one answer at a time", async ({ page }) => {
  await open(page, "/docs/how-it-works/");
  const box = page.locator("[data-chooser]");
  await expect(box.locator(".verdict:visible")).toHaveCount(1);
  await box.getByLabel("Yes").first().check(); // a CDN in between
  await expect(box.locator(".verdict:visible")).toHaveCount(1);
  await expect(box.locator(".verdict:visible code").first()).toHaveText("wss");
  await box.getByLabel("No").first().check(); // no CDN, UDP works, lossy, no games
  await expect(box.locator(".verdict:visible code").first()).toHaveText("kcp");
});

test("the tunnel diagram turns around", async ({ page }) => {
  await open(page, "/docs/how-it-works/");
  const fig = page.locator(".tunnel-dia");
  await expect(fig.locator("svg").getByText("the exit dials the entry")).toBeVisible();
  await fig.getByRole("button", { name: "Direct" }).click();
  await expect(fig.locator("svg").getByText("the entry dials the exit")).toBeVisible();
  await expect(fig.getByRole("button", { name: "Direct" })).toHaveAttribute("aria-pressed", "true");
});

test("a code block copies, and the reader is told", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await open(page, "/docs/getting-started/");
  const block = page.locator(".prose .code").first();
  await block.hover();
  await block.getByRole("button", { name: "Copy" }).click();
  await expect(block.getByRole("button")).toHaveText("Copied");
  const text = await page.evaluate(() => navigator.clipboard.readText());
  expect(text.length).toBeGreaterThan(5);
});

test("the low-power switch stops every animation and is kept", async ({ page }) => {
  await open(page, "/docs/how-it-works/");
  const flow = page.locator(".dia-flow").first();
  expect(await flow.evaluate((el) => getComputedStyle(el).animationName)).not.toBe("none");
  await page.getByRole("button", { name: "Low power: stop animation" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-low", "1");
  expect(await flow.evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-low", "1");
});

test("the low-power button brings motion back when the system asks for less", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await open(page, "/docs/how-it-works/");
  const flow = page.locator(".dia-flow").first();
  const button = page.getByRole("button", { name: "Low power: stop animation" });
  await expect(button).toHaveAttribute("aria-pressed", "true");
  expect(await flow.evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  await button.click();
  await expect(page.locator("html")).toHaveAttribute("data-low", "0");
  await expect(button).toHaveAttribute("aria-pressed", "false");
  expect(await flow.evaluate((el) => getComputedStyle(el).animationName)).not.toBe("none");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-low", "0");
});

test("the video page has a player and chapters that move it", async ({ page }) => {
  await open(page, "/docs/video/");
  const video = page.locator("video[data-video]");
  await expect(video).toHaveAttribute("poster", /poster\.jpg$/);
  await expect(video.locator("source")).toHaveAttribute("src", /kariz-panel-tutorial\.mp4$/);
  await page.locator("[data-seek]").nth(3).click();
  await expect.poll(() => video.evaluate((v: HTMLVideoElement) => Math.round(v.currentTime))).toBeGreaterThanOrEqual(30);
});

test("reduced motion holds the hero still and one screen tall", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await open(page, "/");
  const hero = page.locator(".hero");
  await expect(hero).toHaveClass(/ready/);
  const [h, vh] = await hero.evaluate((el) => [el.getBoundingClientRect().height, window.innerHeight]);
  expect(h).toBeLessThanOrEqual(vh + 1);
});

test("the hero goes down the well as the page scrolls, and its words leave", async ({ page }) => {
  await open(page, "/");
  await expect(page.locator(".hero")).toHaveClass(/ready/);
  const text = page.locator(".hero-text");
  await expect(text).toHaveCSS("opacity", "1");
  await page.evaluate(() => window.scrollTo({ top: window.innerHeight * 0.9, behavior: "instant" }));
  await expect(text).not.toHaveCSS("opacity", "1");
  await expect(text).toHaveAttribute("inert", "");
});

for (const theme of ["night", "dawn"] as const) {
  test(`the journey ends in the page's own colour, with no seam (${theme})`, async ({ page }) => {
    await open(page, "/", theme);
    await expect(page.locator(".hero")).toHaveClass(/ready/);
    await page.evaluate(() => {
      const s = document.querySelector<HTMLElement>(".hero")!;
      window.scrollTo({ top: s.offsetTop + s.offsetHeight - window.innerHeight, behavior: "instant" });
    });
    // The first frame builds the underground, so wait for the picture rather than a fixed time.
    await expect
      .poll(
        () =>
          page.evaluate(() => {
            const c = document.querySelector<HTMLCanvasElement>("[data-hero-canvas]")!;
            const d = c.getContext("2d")!.getImageData(Math.round(c.width / 2), c.height - 2, 1, 1).data;
            const probe = document.createElement("i");
            probe.style.color = "var(--bg)";
            document.body.append(probe);
            const m = getComputedStyle(probe).color.match(/\d+/g)!.map(Number);
            probe.remove();
            return Math.max(...[0, 1, 2].map((i) => Math.abs(d[i] - m[i])));
          }),
        { message: "the bottom of the last frame is the page's background" },
      )
      .toBeLessThanOrEqual(3);
  });
}

test("the panel demo runs in the page, in the page's language", async ({ page }) => {
  await open(page, "/fa/try/");
  const demo = page.frameLocator("iframe");
  await expect(demo.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(demo.getByRole("button", { name: /kariz|ورود/i }).first()).toBeVisible();
});

test("a page that is not there says so, with a way out", async ({ page }) => {
  const r = await page.goto(`${B}/docs/no-such-page/`);
  expect(r?.status()).toBe(404);
  await expect(page.getByRole("heading", { name: "This page is not here." })).toBeVisible();
});

test("the guided tour signs in and takes the demo to each screen", async ({ page }) => {
  await open(page, "/docs/tour/");
  const demo = page.frameLocator("iframe");
  await expect(demo.locator("#login.is-on")).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "Next" }).click(); // the map: signs in first
  await expect(demo.locator("#app.is-on")).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "Next" }).click(); // servers
  await expect(demo.locator(".tour-hi")).toHaveId("srv-add");
  await expect(page.getByRole("status")).toContainText("3 of 9");
});
