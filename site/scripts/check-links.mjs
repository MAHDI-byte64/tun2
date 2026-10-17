// Every link that stays on the site must land: the page exists, and so does the #anchor.
// External links are counted, not fetched (a check that needs the network fails for the
// wrong reasons).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(site, "dist");
const BASE = "/tun2";
if (!fs.existsSync(dist)) {
  console.error("error: dist/ is missing: run `npm run build` first");
  process.exit(1);
}

const walk = (dir) =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === "_pagefind" || e.name === "demo" ? [] : walk(p);
    return e.name.endsWith(".html") ? [p] : [];
  });

const pages = walk(dist);
const ids = new Map();
const idsOf = (file) => {
  if (!ids.has(file)) {
    const html = fs.readFileSync(file, "utf8");
    ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return ids.get(file);
};

const resolve = (from, url) => {
  const [rawPath, hash = ""] = url.split("#");
  let p = rawPath.split("?")[0];
  if (!p) return { file: from, hash };
  if (p.startsWith(BASE + "/") || p === BASE) p = p.slice(BASE.length) || "/";
  else if (p.startsWith("/")) return { error: `absolute link outside ${BASE}: ${url}` };
  else p = path.posix.join("/" + path.relative(dist, path.dirname(from)).split(path.sep).join("/"), p);
  let file = path.join(dist, p);
  if (p.endsWith("/")) file = path.join(file, "index.html");
  if (!fs.existsSync(file) && fs.existsSync(file + "/index.html")) file = path.join(file, "index.html");
  return { file, hash };
};

let bad = 0;
let internal = 0;
let external = 0;
for (const page of pages) {
  const html = fs.readFileSync(page, "utf8");
  const rel = path.relative(dist, page);
  for (const m of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    const url = m[1].replace(/&amp;/g, "&");
    if (!url || /^(mailto:|tel:|data:|javascript:)/.test(url)) continue;
    if (/^(https?:)?\/\//.test(url)) {
      external++;
      continue;
    }
    internal++;
    const r = resolve(page, url);
    if (r.error) {
      console.error(`${rel}: ${r.error}`);
      bad++;
    } else if (!fs.existsSync(r.file)) {
      console.error(`${rel}: broken link ${url}`);
      bad++;
    } else if (r.hash && r.file.endsWith(".html") && !idsOf(r.file).has(decodeURIComponent(r.hash))) {
      console.error(`${rel}: ${url} points at an anchor that is not there`);
      bad++;
    }
  }
}
console.log(`links: ${pages.length} pages, ${internal} internal links checked, ${external} external not fetched, ${bad} broken`);
process.exit(bad ? 1 : 0);
