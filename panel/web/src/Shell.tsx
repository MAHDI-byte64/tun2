import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { Route } from "./App";
import { useApp } from "./store";
import { CHANNEL_URL, ChannelLink, Copyright, Icon, useFocusTrap } from "./ui";
import logo from "./logo.svg";

export type PageId = "map" | "servers" | "tunnels" | "networks" | "iptester" | "logs" | "settings";
export const PAGES: PageId[] = ["map", "servers", "tunnels", "networks", "iptester", "logs", "settings"];

/** Whether the panel answers: `at` is when it last did. */
export interface Live {
  state: "ok" | "lost";
  at: number;
}

export interface Command {
  label: string;
  run: () => void;
  hint?: string;
  icon?: string;
}

export function Shell({
  route,
  navigate,
  subtitle,
  rising,
  live,
  onLogout,
  notice,
  items = [],
  children,
}: {
  route: Route;
  navigate: (to: Route) => void;
  subtitle: string;
  rising: boolean;
  live: Live;
  onLogout: () => void;
  /** Something for the top bar, such as the notice of a newer release. */
  notice?: ReactNode;
  /** More commands for the palette (the tunnels, the servers). */
  items?: Command[];
  children: ReactNode;
}) {
  const { t, lang, setLang, theme, setTheme, low, setLow, toasts, dismiss, num } = useApp();
  const [palette, setPalette] = useState(false);
  const [now, setNow] = useState(Date.now());
  const main = useRef<HTMLElement>(null);
  const page = route.page;

  useEffect(() => {
    main.current?.scrollTo({ top: 0 });
  }, [page, route.tunnel]);

  // The tab (and a screen reader) says which page this is: "iran-eu — Tunnels — Kariz".
  useEffect(() => {
    document.title = [route.tunnel, t(`page.${page}`), "Kariz"].filter(Boolean).join(" — ");
    return () => {
      document.title = "Kariz";
    };
  }, [page, route.tunnel, lang]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
      }
    };
    addEventListener("keydown", key);
    return () => removeEventListener("keydown", key);
  }, []);

  const go = (p: PageId) => navigate({ page: p });
  const commands = useMemo<Command[]>(
    () => [
      ...PAGES.map((p) => ({ label: `${t("pal.goto")} ${t(`page.${p}`)}`, icon: p, run: () => navigate({ page: p }) })),
      ...items,
      { label: t("pal.link"), icon: "key", run: () => navigate({ page: "settings" }) },
      { label: t("pal.channel"), icon: "telegram", run: () => window.open(CHANNEL_URL, "_blank", "noopener,noreferrer") },
      { label: t("pal.theme"), icon: theme === "night" ? "sun" : "moon", run: () => setTheme(theme === "night" ? "dawn" : "night") },
      { label: t("pal.lang"), icon: "palette", run: () => setLang(lang === "fa" ? "en" : "fa") },
      { label: t("pal.low"), icon: "leaf", hint: low ? "✓" : "", run: () => setLow(!low, true) },
      { label: t("pal.logout"), icon: "exit", run: onLogout },
    ],
    [t, theme, lang, low, navigate, setTheme, setLang, setLow, onLogout, items],
  );

  const secs = live.at ? Math.max(0, Math.round((now - live.at) / 1000)) : 0;
  const lost = live.state === "lost";

  const item = (p: PageId, extra = "") => (
    <button key={p} className={`rail-item ${extra}`} type="button" aria-current={page === p ? "page" : undefined} onClick={() => go(p)}>
      <Icon name={p} size={22} />
      <span>{t(`nav.${p}`)}</span>
    </button>
  );

  return (
    <section id="app" className={`screen is-on ${rising ? "is-rising" : ""}`} aria-label={t("a11y.panel")}>
      <nav className="rail" aria-label={t("a11y.nav")}>
        <div className="brand">
          <img src={logo} alt="Kariz" />
          <span className="brand-word">
            Kariz<small>{t("boot.sub")}</small>
          </span>
        </div>
        <div className="rail-group">{PAGES.filter((p) => p !== "settings").map((p) => item(p))}</div>
        <div className="rail-spacer" />
        {item("settings")}
        <button className="rail-item rail-extra" type="button" onClick={onLogout}>
          <Icon name="exit" size={22} />
          <span>{t("nav.logout")}</span>
        </button>
      </nav>

      <header className="sky">
        <h1 className="page-title">
          {route.tunnel ? (
            <span className="crumbs">
              <button type="button" className="crumb" onClick={() => go("tunnels")}>
                {t("page.tunnels")}
              </button>
              <Icon name="chevron" size={16} />
              <span className="mono">{route.tunnel}</span>
            </span>
          ) : (
            <span>{t(`page.${page}`)}</span>
          )}
          <small>{subtitle}</small>
        </h1>
        <div className="sky-spacer" />
        <span className={`live ${lost ? "is-lost" : ""}`} role="status" title={live.at ? t("live.updated", { n: num(secs) }) : undefined}>
          <i aria-hidden="true" />
          <span className="live-text">{lost ? t("live.lost") : t("live.on")}</span>
        </span>
        {notice}
        <button className="search-btn" type="button" onClick={() => setPalette(true)} aria-label={t("search")}>
          <Icon name="search" size={18} />
          <span className="label">{t("search")}</span>
          <kbd>Ctrl K</kbd>
        </button>
        <div className="sky-actions">
          <button className="square-btn" type="button" onClick={() => setLang(lang === "fa" ? "en" : "fa")} aria-label={lang === "fa" ? "English (change the language)" : "فارسی (تغییر زبان)"} title={lang === "fa" ? "English" : "فارسی"}>
            {lang === "fa" ? "EN" : "فا"}
          </button>
          <button className="square-btn" type="button" onClick={() => setTheme(theme === "night" ? "dawn" : "night")} aria-label={t("a11y.theme", { theme: theme === "night" ? t("theme.dawn") : t("theme.night") })} title={t("a11y.theme", { theme: theme === "night" ? t("theme.dawn") : t("theme.night") })}>
            <Icon name={theme === "night" ? "sun" : "moon"} />
          </button>
          <ChannelLink variant="square" />
        </div>
      </header>

      <main className="main" ref={main} tabIndex={0} aria-label={t(`page.${page}`)}>
        {lost && (
          <div className="banner warn" role="alert">
            <Icon name="alert" size={18} />
            <span>{t("live.lostText", { n: num(secs) })}</span>
          </div>
        )}
        <div className="content">{children}</div>
        <footer className="app-foot">
          <Copyright />
        </footer>
      </main>

      {palette && <Palette commands={commands} onClose={() => setPalette(false)} />}
      <div className="toasts" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className={`toast ${x.kind} ${x.leaving ? "is-leaving" : ""}`}>
            <Icon name={x.kind === "err" ? "alert" : x.kind === "ok" ? "check" : "info"} size={18} />
            <span>{x.text}</span>
            <button type="button" className="toast-x" aria-label={t("close")} onClick={() => dismiss(x.id)}>
              <Icon name="x" size={14} />
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}

function Palette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const { t } = useApp();
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const [on, setOn] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);
  useFocusTrap(box);
  const q = query.trim().toLowerCase();
  const items = commands.filter((c) => c.label.toLowerCase().includes(q));

  useEffect(() => {
    const id = requestAnimationFrame(() => setOn(true));
    input.current?.focus();
    return () => cancelAnimationFrame(id);
  }, []);

  useEffect(() => {
    list.current?.querySelector(`#pal-${sel}`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const run = (c: Command | undefined) => {
    onClose();
    c?.run();
  };

  return (
    <div ref={box} className={`palette-backdrop ${on ? "is-on" : ""}`} role="dialog" aria-modal="true" aria-label={t("pal.title")} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette">
        <div className="palette-input">
          <Icon name="search" size={18} />
          <input
            ref={input}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls="pal-list"
            aria-autocomplete="list"
            aria-activedescendant={items.length ? `pal-${sel}` : undefined}
            aria-label={t("pal.title")}
            autoComplete="off"
            placeholder={t("pal.placeholder")}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSel(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((sel + 1) % Math.max(1, items.length));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((sel - 1 + items.length) % Math.max(1, items.length));
              } else if (e.key === "Enter") run(items[sel]);
              else if (e.key === "Escape") onClose();
            }}
          />
          <kbd>Esc</kbd>
        </div>
        {items.length === 0 && <p className="pal-none">{t("pal.none")}</p>}
        <ul role="listbox" id="pal-list" ref={list} aria-label={t("pal.title")} tabIndex={-1}>
          {items.map((c, i) => (
            <li key={c.label} id={`pal-${i}`} role="option" aria-selected={i === sel} onMouseMove={() => setSel(i)} onClick={() => run(c)}>
              {c.icon && <Icon name={c.icon} size={18} />}
              <span>{c.label}</span>
              <span className="hint">{c.hint}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
