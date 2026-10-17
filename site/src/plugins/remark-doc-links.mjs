// The docs link to each other as files (`transports.md`, `../README.md`, `fa/security.md`).
// On the site those become routes; anything else that points into the repository becomes a
// link to GitHub, so no page of `docs/` needs a second, site-only version.
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

/** Repository-relative, forward slashes. */
const rel = (abs) => path.relative(repoRoot, abs).split(path.sep).join("/");

export function routeFor(file, base) {
  // file is repository-relative: docs/x.md, docs/fa/x.md, README.md, ...
  const fa = file.startsWith("docs/fa/");
  const pre = `${base}${fa ? "/fa" : ""}`;
  if (file === "README.md") return `${base}/`;
  if (file === "README_FA.md") return `${base}/fa/`;
  if (file === "CHANGELOG.md") return `${base}/docs/changelog/`;
  if (file === "docs/README.md" || file === "docs/fa/README.md") return `${pre}/docs/`;
  const m = /^docs\/(?:fa\/)?([^/]+)\.md$/.exec(file);
  if (m) return `${pre}/docs/${m[1].toLowerCase()}/`;
  return null;
}

export function remarkDocLinks({ base, repo }) {
  return (tree, vfile) => {
    const from = vfile.path ? path.dirname(vfile.path) : null;
    if (!from) return;
    const walk = (node) => {
      if ((node.type === "link" || node.type === "image" || node.type === "definition") && typeof node.url === "string") {
        node.url = fix(node.url, node.type === "image");
      }
      if (node.children) node.children.forEach(walk);
    };
    const fix = (url, image) => {
      if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(url)) return url;
      const [target, hash = ""] = url.split(/(?=#)/);
      if (!target) return url;
      const abs = path.resolve(from, target);
      const file = rel(abs);
      if (file.startsWith("..")) return url;
      // The pictures of the docs (docs/images/) are copied into the site, so a page shows them
      // from the site and not from GitHub.
      if (image && file.startsWith("docs/images/")) return `${base}/docs-images/${file.slice("docs/images/".length)}`;
      const route = routeFor(file, base);
      if (route) return route + hash;
      const kind = image ? "raw" : /\.[a-z0-9]+$/i.test(file) ? "blob" : "tree";
      return image
        ? `https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/${file}`
        : `${repo}/${kind}/main/${file.replace(/\/$/, "")}${hash}`;
    };
    walk(tree);
  };
}
