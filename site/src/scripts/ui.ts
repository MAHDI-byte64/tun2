// The site's small behaviours: theme, low power, menu, search, copy buttons, reading progress,
// the outline, and diagrams drawn from mermaid blocks. Every one is optional: the pages
// read fine without any of it.
const root = document.documentElement;
const $ = <T extends Element>(sel: string, from: ParentNode = document) => from.querySelector<T>(sel);
const $$ = <T extends Element>(sel: string, from: ParentNode = document) => [...from.querySelectorAll<T>(sel)];
const store = {
  get: (k: string) => {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set: (k: string, v: string) => {
    try {
      localStorage.setItem(k, v);
    } catch {
      /* private window */
    }
  },
};
const reduced = matchMedia("(prefers-reduced-motion: reduce)");

// ---- Theme and low power ----
$("[data-theme-toggle]")?.addEventListener("click", () => {
  const next = root.dataset.theme === "dawn" ? "night" : "dawn";
  root.dataset.theme = next;
  store.set("kariz-site-theme", next);
});
const lowBtn = $<HTMLButtonElement>("[data-low-toggle]");
// "1" is low power on, "0" is motion on even when the system asks for less; no value follows the system.
const isLow = () => root.dataset.low === "1" || (root.dataset.low !== "0" && reduced.matches);
const syncLow = () => lowBtn?.setAttribute("aria-pressed", String(isLow()));
syncLow();
lowBtn?.addEventListener("click", () => {
  if (isLow()) {
    root.dataset.low = "0";
    store.set("kariz-site-low", "0");
  } else {
    root.dataset.low = "1";
    store.set("kariz-site-low", "1");
  }
  syncLow();
});
reduced.addEventListener("change", syncLow);

// ---- The demo opens in the theme the reader is in ----
if (root.dataset.theme === "dawn") {
  for (const f of $$<HTMLIFrameElement>("iframe[src*='/demo/']")) {
    const u = new URL(f.src, location.href);
    u.searchParams.set("theme", "dawn");
    f.src = u.href;
  }
}

// ---- Sidebar on a phone ----
const menu = $<HTMLButtonElement>("[data-menu]");
const side = $<HTMLElement>("#side");
if (menu && side) {
  const set = (open: boolean) => {
    side.classList.toggle("open", open);
    menu.setAttribute("aria-expanded", String(open));
  };
  menu.addEventListener("click", () => set(!side.classList.contains("open")));
  side.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).closest("a")) set(false);
  });
  addEventListener("keydown", (e) => {
    if (e.key === "Escape" && side.classList.contains("open")) {
      set(false);
      menu.focus();
    }
  });
} else if (menu) {
  menu.hidden = true;
}

// ---- Search (Pagefind, in the browser; the index is a static folder of the site) ----
const dlg = $<HTMLDialogElement>("[data-search]");
if (dlg) {
  const input = $<HTMLInputElement>("[data-search-input]", dlg)!;
  const msg = $<HTMLElement>("[data-search-msg]", dlg)!;
  const list = $<HTMLUListElement>("[data-search-results]", dlg)!;
  const base = dlg.dataset.base ?? "";
  let pf: any = null;
  let failed = false;
  let seq = 0;
  const load = async () => {
    if (pf || failed) return;
    try {
      pf = await import(/* @vite-ignore */ `${base}/_pagefind/pagefind.js`);
      await pf.options({ baseUrl: `${base}/` });
    } catch {
      failed = true;
      msg.textContent = dlg.dataset.off ?? "";
    }
  };
  const open = () => {
    if (!dlg.open) dlg.showModal();
    input.select();
    void load();
  };
  $$("[data-search-open]").forEach((b) => b.addEventListener("click", open));
  addEventListener("keydown", (e) => {
    const typing = /^(input|textarea|select)$/i.test((e.target as HTMLElement)?.tagName ?? "");
    if (((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") || (e.key === "/" && !typing && !dlg.open)) {
      e.preventDefault();
      open();
    }
  });
  dlg.addEventListener("click", (e) => {
    if (e.target === dlg) dlg.close();
  });
  const show = async () => {
    const q = input.value.trim();
    const mine = ++seq;
    list.replaceChildren();
    if (!q) {
      msg.textContent = dlg.dataset.hint ?? "";
      return;
    }
    await load();
    if (!pf) return;
    const found = await pf.search(q);
    if (mine !== seq) return;
    const hits = await Promise.all(found.results.slice(0, 8).map((r: any) => r.data()));
    if (mine !== seq) return;
    msg.textContent = hits.length ? "" : `${dlg.dataset.none} “${q}”`;
    for (const h of hits) {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = h.url;
      const b = document.createElement("b");
      b.textContent = h.meta?.title ?? h.url;
      const s = document.createElement("small");
      s.innerHTML = h.excerpt; // Pagefind escapes the text and adds only <mark>
      a.append(b, s);
      li.append(a);
      list.append(li);
    }
  };
  input.addEventListener("input", () => void show());
  input.addEventListener("keydown", (e) => {
    const links = $$<HTMLAnchorElement>("a", list);
    if (!links.length) return;
    const at = links.findIndex((a) => a === document.activeElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      links[Math.min(at + 1, links.length - 1)].focus();
    } else if (e.key === "Enter" && at < 0) {
      links[0].click();
    }
  });
  list.addEventListener("keydown", (e) => {
    const links = $$<HTMLAnchorElement>("a", list);
    const at = links.findIndex((a) => a === document.activeElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      links[Math.min(at + 1, links.length - 1)]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (at <= 0) input.focus();
      else links[at - 1].focus();
    }
  });
}

// ---- Code blocks: wrap, a copy button with a small splash; wide tables scroll on their own ----
const prose = $(".prose");
if (prose) {
  const lang = root.lang;
  const label = { copy: lang === "fa" ? "کپی" : "Copy", done: lang === "fa" ? "کپی شد" : "Copied" };
  for (const pre of $$<HTMLPreElement>("pre", prose)) {
    if (pre.dataset.language === "mermaid") continue;
    const box = document.createElement("div");
    box.className = "code";
    pre.tabIndex = 0; // a wide block scrolls, so the keyboard must reach it
    pre.replaceWith(box);
    box.append(pre);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "copy";
    b.textContent = label.copy;
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.innerText.replace(/\n$/, ""));
      } catch {
        const r = document.createRange();
        r.selectNodeContents(pre);
        getSelection()?.removeAllRanges();
        getSelection()?.addRange(r);
        return;
      }
      b.textContent = label.done;
      b.classList.add("done");
      if (!isLow()) {
        const rect = b.getBoundingClientRect();
        const host = box.getBoundingClientRect();
        for (let i = 0; i < 7; i++) {
          const d = document.createElement("i");
          d.className = "splash";
          d.style.left = `${rect.left - host.left + rect.width / 2}px`;
          d.style.top = `${rect.top - host.top + rect.height / 2}px`;
          const a = -Math.PI * (0.15 + 0.7 * (i / 6));
          d.style.setProperty("--dx", `${Math.cos(a) * (18 + i * 3)}px`);
          d.style.setProperty("--dy", `${Math.sin(a) * (18 + i * 3)}px`);
          box.append(d);
          setTimeout(() => d.remove(), 700);
        }
      }
      setTimeout(() => {
        b.textContent = label.copy;
        b.classList.remove("done");
      }, 1600);
    });
    box.append(b);
  }
  for (const t of $$<HTMLTableElement>("table", prose)) {
    const w = document.createElement("div");
    w.className = "tablewrap";
    t.replaceWith(w);
    w.append(t);
  }

  // Diagrams written as mermaid blocks in the docs: drawn in the browser, on those pages only.
  const blocks = $$<HTMLPreElement>('pre[data-language="mermaid"]', prose);
  if (blocks.length) void drawMermaid(blocks);
}

async function drawMermaid(blocks: HTMLPreElement[]) {
  const cs = getComputedStyle(root);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  try {
    const { default: mermaid } = await import("mermaid");
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: {
        fontFamily: v("--font-ui"),
        primaryColor: v("--stratum-2"),
        primaryTextColor: v("--text"),
        primaryBorderColor: v("--water"),
        lineColor: v("--water"),
        secondaryColor: v("--stratum-1"),
        tertiaryColor: v("--bg"),
        clusterBkg: v("--stratum-1"),
        edgeLabelBackground: v("--bg"),
        textColor: v("--text"),
      },
    });
    let n = 0;
    for (const pre of blocks) {
      const src = pre.textContent ?? "";
      const host = document.createElement("div");
      host.className = "mermaid-box";
      try {
        const { svg } = await mermaid.render(`mmd-${n++}`, src);
        host.innerHTML = svg;
        host.setAttribute("role", "img");
        host.setAttribute("aria-label", "Diagram");
        pre.replaceWith(host);
      } catch {
        /* the source stays readable */
      }
    }
  } catch {
    /* offline: the source stays readable */
  }
}

// ---- Reading progress: a drop that draws the line ----
const flow = $<HTMLElement>(".flow");
if (flow) {
  const bar = $<HTMLElement>("i", flow)!;
  const drop = $<HTMLElement>("b", flow)!;
  const rtl = root.dir === "rtl";
  let queued = false;
  const tick = () => {
    queued = false;
    const max = document.documentElement.scrollHeight - innerHeight;
    const k = max > 0 ? Math.min(1, Math.max(0, scrollY / max)) : 0;
    bar.style.width = `${k * 100}%`;
    drop.style.transform = `translateX(${(rtl ? -1 : 1) * k * (flow.clientWidth - 9)}px) ${rtl ? "rotate(45deg) scaleX(-1)" : "rotate(-45deg)"}`;
    drop.style.opacity = k > 0.005 && k < 0.995 ? "1" : "0";
  };
  addEventListener(
    "scroll",
    () => {
      if (!queued) {
        queued = true;
        requestAnimationFrame(tick);
      }
    },
    { passive: true },
  );
  addEventListener("resize", tick);
  tick();
}

// ---- The outline follows the reader ----
const toc = $$<HTMLAnchorElement>(".toc a");
if (toc.length && "IntersectionObserver" in window) {
  const map = new Map(toc.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
  const heads = [...map.keys()].map((id) => document.getElementById(id)).filter((h): h is HTMLElement => !!h);
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          toc.forEach((a) => a.classList.remove("on"));
          map.get(e.target.id)?.classList.add("on");
        }
      }
    },
    { rootMargin: "-80px 0px -70% 0px" },
  );
  heads.forEach((h) => io.observe(h));
}
