import net from "node:net";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { goTo, signIn } from "./helpers";
import { freePort, startAgent } from "./stack";
import type { Agent } from "./stack";

// One panel, one real agent joined through the page, and a tunnel between them made with the
// wizard: the browser does what a person does. The tunnel's own status comes over a Unix
// socket, so the tunnel tests run on Linux (the CI); the page part runs anywhere.
test.describe.configure({ mode: "serial" });

let agent: Agent | undefined;
let echo: net.Server;
let echoPort = 0;

test.beforeAll(async () => {
  echo = net.createServer((s) => s.pipe(s));
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", r));
  echoPort = (echo.address() as net.AddressInfo).port;
});

test.afterAll(() => {
  echo.close();
  agent?.stop();
});

/** Sends something through a port and reads it back (or gives up). */
async function echoes(port: number, what: string): Promise<boolean> {
  for (let i = 0; i < 20; i++) {
    const ok = await new Promise<boolean>((resolve) => {
      const s = net.connect(port, "127.0.0.1");
      const timer = setTimeout(() => (s.destroy(), resolve(false)), 2000);
      s.once("error", () => (clearTimeout(timer), resolve(false)));
      s.once("data", (d) => (clearTimeout(timer), s.destroy(), resolve(d.toString() === what)));
      s.once("connect", () => s.write(what));
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function refuses(port: number): Promise<boolean> {
  for (let i = 0; i < 10; i++) {
    const refused = await new Promise<boolean>((resolve) => {
      const s = net.connect(port, "127.0.0.1");
      s.once("error", () => resolve(true));
      s.once("connect", () => (s.destroy(), resolve(false)));
    });
    if (refused) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

/** The Close button of the wizard's footer or of a dialog (the corner cross has the same name). */
async function closeDialog(page: Page) {
  const footer = page.locator(".wz-foot, .dialog footer").getByRole("button", { name: "Close" });
  await footer.click();
}

async function next(page: Page) {
  await page.locator(".wz-foot .btn-primary").click();
}

/** The wizard for a reverse tcpmux tunnel from this server to the agent. */
async function fillWizard(page: Page, opts: { name: string; front: number; dial?: string }) {
  await page.locator(".page-band .btn-primary").click();
  await page.locator("#wz-name").fill(opts.name);
  await page.locator(".pick-list").nth(0).locator("button").nth(0).click();
  await page.locator(".pick-list").nth(1).locator("button").nth(1).click();
  await next(page); // kind: reverse, tcpmux, balanced
  await next(page);
  await page.locator("#wz-port").fill(String(await freePort()));
  if (opts.dial) await page.locator("#wz-dial").fill(opts.dial);
  await next(page);
  // listen on `front`, reach the echo server's port
  await page.locator("#wz-ports").fill(`${opts.front}=${echoPort}`);
  await next(page); // review
}

test("a server is added with a join code and comes online", async ({ page }) => {
  await signIn(page);
  await goTo(page, "servers");
  await page.locator(".page-band .btn-primary").click();
  await page.locator("#add-name").fill("far-away");
  await page.getByRole("button", { name: /Make a join code/i }).click();
  const shown = await page.locator("pre.code").first().innerText();
  const code = /kz1_[A-Za-z0-9_-]+/.exec(shown)?.[0];
  expect(code, "a join code is shown").toBeTruthy();
  agent = startAgent(code!);
  await expect(page.locator(".waiting.done")).toBeVisible({ timeout: 45_000 });
  await page.getByRole("button", { name: /Done/i }).click();
  await expect(page.locator(".srv", { hasText: "far-away" })).toContainText(/online/i);
});

test("the wizard asks for UDP clients per port only when the tunnel forwards UDP", async ({ page }) => {
  await signIn(page);
  await goTo(page, "tunnels");
  await page.locator(".page-band .btn-primary").click();
  await page.locator("#wz-name").fill("udp-check");
  await page.locator(".pick-list").nth(0).locator("button").nth(0).click();
  await page.locator(".pick-list").nth(1).locator("button").nth(1).click();
  await next(page);
  await next(page);
  await page.locator("#wz-port").fill(String(await freePort()));
  await next(page);
  await page.locator("#wz-ports").fill("4433");
  // TCP: nothing about UDP
  await expect(page.locator("#wz-udpflows")).toHaveCount(0);
  await page.getByRole("button", { name: "TCP+UDP", exact: true }).click();
  const flows = page.locator("#wz-udpflows");
  await expect(flows).toBeVisible();
  await expect(flows).toHaveAttribute("placeholder", "4096 (default)");
  await flows.fill("70000");
  await next(page);
  await expect(page.getByText(/UDP clients per port: a whole number from 1 to 65536/).first()).toBeVisible();
  await flows.fill("8192");
  await page.getByRole("button", { name: "TCP", exact: true }).click();
  await expect(page.locator("#wz-udpflows")).toHaveCount(0);
  await page.keyboard.press("Escape");
});

test.describe("the tunnel", () => {
  test.skip(process.platform === "win32", "the tunnels' status comes over a Unix socket");

  let front = 0;

  test("is made with the wizard, carries traffic, and is edited", async ({ page }) => {
    front = await freePort();
    await signIn(page);
    await goTo(page, "tunnels");
    await fillWizard(page, { name: "demo", front });
    await page.locator(".wz-foot .btn-primary").click(); // Build
    await expect(page.locator(".wz-step p.ok")).toContainText(/Done/i, { timeout: 60_000 });
    for (const li of await page.locator(".checklist li").all()) await expect(li).toHaveClass(/ok/);
    await closeDialog(page);
    expect(await echoes(front, "through the wizard's tunnel")).toBe(true);

    // it shows up as up, and its page opens
    const row = page.locator(".tunnels tr", { hasText: "demo" });
    await expect(row).toContainText(/flowing/i, { timeout: 30_000 });
    // both sides are reported (the entry's name and the agent's), so it can be edited as a pair
    await expect(row).toContainText("far-away", { timeout: 30_000 });
    await row.click();
    await page.getByRole("button", { name: "Edit" }).click();
    // one page, filled in from the servers: the ports field shows what is there now
    await expect(page.locator("#te-ports")).toHaveValue(`${front}=${echoPort}`);
    const newFront = await freePort();
    await page.locator("#te-ports").fill(`${newFront}=${echoPort}`);
    await page.locator(".edit-bar .btn-primary").click(); // Save
    await expect(page.locator(".tunnel-edit p.ok")).toContainText(/Done/i, { timeout: 60_000 });
    await page.locator(".edit-bar").getByRole("button", { name: "Close" }).click();
    expect(await echoes(newFront, "after the edit")).toBe(true);
    expect(await refuses(front), "the old port is closed").toBe(true);
    front = newFront;
  });

  test("takes a traffic limit, shows the usage, and lets it go again", async ({ page }) => {
    await signIn(page);
    await goTo(page, "tunnels");
    const row = page.locator(".tunnels tr", { hasText: "demo" });
    await row.click();
    await page.locator("#td-tab-quota").click();
    const panel = page.locator("#td-panel-quota");
    await expect(panel).toContainText(/No limit/i);
    // A bad amount is refused by the page itself.
    await panel.locator("#qt-amount").fill("0");
    await panel.getByRole("button", { name: /^Save$/ }).click();
    await expect(panel.getByRole("alert")).toContainText(/at least 1 MB/i);
    // A limit of one gigabyte, reset on the 5th of every month.
    await panel.locator("#qt-amount").fill("1");
    await panel.getByRole("button", { name: "Monthly", exact: true }).click();
    await panel.locator("#qt-day").fill("5");
    await panel.getByRole("button", { name: /^Save$/ }).click();
    await expect(page.locator(".toast, [role=status]").filter({ hasText: /limit saved/i }).first()).toBeVisible();
    await expect(panel.locator(".qt-bar")).toContainText(/of 1\.0 GB/);
    await expect(panel).toContainText(/Next reset/i);
    // The usage is also in the list, and on the page's overview.
    await page.locator(".td-back").click();
    await expect(row.locator(".qt-bar")).toContainText(/of 1\.0 GB/, { timeout: 15_000 });
    await row.click();
    await expect(page.locator(".stat-card .qt-bar")).toBeVisible();
    // Reset, then remove: the usage goes, then the limit.
    await page.locator("#td-tab-quota").click();
    await panel.getByRole("button", { name: /Reset the usage/i }).click();
    await expect(page.locator(".toast, [role=status]").filter({ hasText: /usage was reset/i }).first()).toBeVisible();
    await panel.getByRole("button", { name: /Remove the limit/i }).click();
    await expect(page.locator(".toast, [role=status]").filter({ hasText: /limit was removed/i }).first()).toBeVisible();
    await expect(panel).toContainText(/No limit/i);
    await page.locator(".td-back").click();
    await expect(row.locator(".qt-bar")).toHaveCount(0, { timeout: 15_000 });
  });

  test("is stopped, started again and deleted, from its page", async ({ page }) => {
    await signIn(page);
    await goTo(page, "tunnels");
    // The tunnel's page opens once. After each action its dialog closes and the tunnel's page
    // is there again, showing what the servers say now.
    await page.locator(".tunnels tr", { hasText: "demo" }).click();
    // the actions in the page's head (a stopped tunnel also offers Start in its notice)
    const head = page.locator(".hero-route .head");
    await head.getByRole("button", { name: "Stop", exact: true }).click();
    await page.locator(".dialog .btn-primary").click();
    await expect(page.locator(".dialog p.ok")).toContainText(/Done/i, { timeout: 60_000 });
    await closeDialog(page);
    expect(await refuses(front), "a stopped tunnel listens nowhere").toBe(true);

    await head.getByRole("button", { name: "Start", exact: true }).click();
    await page.locator(".dialog .btn-primary").click();
    await expect(page.locator(".dialog p.ok")).toContainText(/Done/i, { timeout: 60_000 });
    await closeDialog(page);
    expect(await echoes(front, "after starting again")).toBe(true);

    // deleting is in the menu of the less used actions
    await head.getByRole("button", { name: "More actions" }).click();
    await head.getByRole("menuitem", { name: "Delete" }).click();
    // deleting waits for the tunnel's name to be typed
    await expect(page.locator(".dialog .btn-danger")).toBeDisabled();
    await page.locator("#run-confirm").fill("demo");
    await page.locator(".dialog .btn-danger").click();
    await expect(page.locator(".dialog p.ok")).toContainText(/Done/i, { timeout: 60_000 });
    // the dialog of a finished delete closes by itself
    await expect(page.locator(".dialog")).toHaveCount(0, { timeout: 10_000 });
    await expect(page.locator(".tunnels tr", { hasText: "demo" })).toHaveCount(0, { timeout: 30_000 });
    expect(await refuses(front), "a deleted tunnel listens nowhere").toBe(true);
  });

  test("that cannot connect is undone on both servers and says why", async ({ page }) => {
    const front2 = await freePort();
    await signIn(page);
    await goTo(page, "tunnels");
    // the other side is told an address nothing answers at
    await fillWizard(page, { name: "lost", front: front2, dial: "192.0.2.1" });
    await page.locator(".wz-foot .btn-primary").click();
    await expect(page.locator(".wz-step p.err").first()).toBeVisible({ timeout: 80_000 });
    await expect(page.locator(".wz-step")).toContainText(/removed/i);
    expect(await refuses(front2), "nothing was left listening").toBe(true);
    await closeDialog(page);
    await expect(page.locator(".tunnels tr", { hasText: "lost" })).toHaveCount(0, { timeout: 30_000 });
  });
});
