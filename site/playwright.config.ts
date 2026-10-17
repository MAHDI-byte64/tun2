import { defineConfig } from "@playwright/test";

// The tests read the built site (npm run build) through `astro preview`.
// PW_CHANNEL=msedge uses the Edge that is installed (no download); CI uses Chromium.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  webServer: {
    command: "npx astro preview --port 4321",
    url: "http://localhost:4321/tun2/",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  use: {
    baseURL: "http://localhost:4321",
    channel: process.env.PW_CHANNEL || undefined,
    trace: "retain-on-failure",
    viewport: { width: 1280, height: 800 },
  },
  outputDir: "./e2e-results",
});
