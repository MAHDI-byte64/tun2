import fs from "node:fs";
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import { unified } from "@astrojs/markdown-remark";
import { remarkDocLinks } from "./src/plugins/remark-doc-links.mjs";

const base = "/tun2";
// The version on the site is the program's, from the workspace manifest.
const version = /^version = "([^"]+)"/m.exec(fs.readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8"))?.[1] ?? "";

export default defineConfig({
  site: "https://mahdi-byte64.github.io",
  base,
  trailingSlash: "always",
  build: { format: "directory" },
  integrations: [sitemap()],
  markdown: {
    // The text stays as written: no curly quotes or dashes made from the docs' plain ones.
    processor: unified({
      remarkPlugins: [[remarkDocLinks, { base, repo: "https://github.com/MAHDI-byte64/tun2" }]],
      smartypants: false,
    }),
    shikiConfig: {
      themes: { night: "github-dark-high-contrast", dawn: "github-light-high-contrast" },
      defaultColor: false,
    },
  },
  vite: { server: { fs: { allow: [".."] } }, define: { __KARIZ_VERSION__: JSON.stringify(version) } },
});
