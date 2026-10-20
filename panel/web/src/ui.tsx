import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { ReactNode, RefObject } from "react";
import { FA_DIGITS } from "./i18n";
import { useApp } from "./store";
import { copyText } from "./clipboard";

const ICONS: Record<string, ReactNode> = {
  map: (
    <>
      <path d="M2 9h20" />
      <path d="M6 9v6M12 9v8M18 9v6" />
      <path d="M4 15.5c4 1.2 12 2.4 16 2" opacity=".6" />
      <path d="M4.5 9a1.5 1.2 0 0 1 3 0M10.5 9a1.5 1.2 0 0 1 3 0M16.5 9a1.5 1.2 0 0 1 3 0" />
    </>
  ),
  servers: (
    <>
      <rect x="3.5" y="4" width="17" height="6.5" rx="1.5" />
      <rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5" />
      <path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6" />
    </>
  ),
  tunnels: (
    <>
      <path d="M3 17c3-6 15-6 18 0" />
      <path d="M6.5 17c2-3.2 9-3.2 11 0" />
      <path d="M3 17h3.5M17.5 17H21" />
    </>
  ),
  logs: <path d="M5 5h14M5 9.5h9M5 14h14M5 18.5h7" />,
  networks: (
    <>
      <path d="M2.5 8h19" />
      <path d="M6 8v6M18 8v6" />
      <path d="M4.5 8a1.5 1.2 0 0 1 3 0M16.5 8a1.5 1.2 0 0 1 3 0" />
      <path d="M6 16.5c4 3.2 8 3.2 12 0" strokeDasharray="2.2 2.2" />
    </>
  ),
  iptester: (
    <>
      <circle cx="12" cy="12" r="7.5" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3" />
    </>
  ),
  settings: (
    <>
      <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4 4" />
    </>
  ),
  moon: <path d="M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10Z" />,
  sun: (
    <>
      <path d="M3 16h18" />
      <path d="M7 16a5 5 0 0 1 10 0" />
      <path d="M12 5v2.5M5.5 8.5l1.6 1.6M18.5 8.5l-1.6 1.6" />
    </>
  ),
  leaf: <path d="M13 3 5 13.5h6L10 21l8-10.5h-6L13 3Z" />,
  bolt: <path d="M13 3 5 13.5h6L10 21l8-10.5h-6L13 3Z" />,
  play: <path d="M8 5.5v13l10.5-6.5L8 5.5Z" />,
  pause: <path d="M8.5 5.5v13M15.5 5.5v13" />,
  restart: (
    <>
      <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
      <path d="M19.5 4.5v4h-4" />
    </>
  ),
  edit: <path d="M4.5 19.5h4l10-10a2.1 2.1 0 0 0-4-4l-10 10v4ZM13 7l4 4" />,
  trash: <path d="M5 7h14M10 7V5h4v2M7 7l1 12.5h8L17 7M10.5 11v5M13.5 11v5" />,
  back: <path d="M20 12H5M10 7l-5 5 5 5" />,
  eye: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  arrow: <path d="M4 12h15M14 7l5 5-5 5" />,
  exit: (
    <>
      <path d="M14 4h4.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H14" />
      <path d="M10 8l-4 4 4 4M6 12h10" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  copy: (
    <>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8" />
    </>
  ),
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m11 12 8-8M16 7l2.5 2.5M14 9l2 2" />
    </>
  ),
  link: (
    <>
      <path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1.2 1.2" />
      <path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M4 4l16 16" />
      <path d="M9.9 5.7A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-3 3.8M6.3 7.4A15.6 15.6 0 0 0 2.5 12S6 18.5 12 18.5a9 9 0 0 0 4-.9" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4 2.8 19.5h18.4L12 4Z" />
      <path d="M12 10v4.5M12 17.2h.01" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5.5M12 7.8h.01" />
    </>
  ),
  chevron: <path d="m9 6 6 6-6 6" />,
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" strokeWidth="3" />,
  grip: <path d="M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01" strokeWidth="3" />,
  arrange: <path d="M7 4v16M4 7l3-3 3 3M17 20V4M14 17l3 3 3-3" />,
  cpu: (
    <>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3" />
    </>
  ),
  pulse: <path d="M3 12h4l2.5-6 5 12 2.5-6H21" />,
  gauge: (
    <>
      <path d="M4.5 17a8 8 0 1 1 15 0" />
      <path d="m12 16.5 3.6-4.6" />
      <circle cx="12" cy="16.5" r="1.3" />
    </>
  ),
  down: <path d="M12 5v14M6 13l6 6 6-6" />,
  up: <path d="M12 19V5M6 11l6-6 6 6" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  shield: <path d="M12 3.5 5 6v5.5c0 4.3 3 7.6 7 9 4-1.4 7-4.7 7-9V6l-7-2.5Z" />,
  refresh: (
    <>
      <path d="M19.5 12a7.5 7.5 0 0 1-13.1 5M4.5 12a7.5 7.5 0 0 1 13.1-5" />
      <path d="M17.6 3v4h-4M6.4 21v-4h4" />
    </>
  ),
  download: <path d="M12 4v11M7 10.5l5 5 5-5M5 19.5h14" />,
  upload: <path d="M12 16V5M7 9.5l5-5 5 5M5 19.5h14" />,
  palette: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 3.5a8.5 8.5 0 0 0 0 17" fill="currentColor" stroke="none" opacity=".35" />
    </>
  ),
  telegram: (
    <>
      <path d="M21 4 3 10.8l6 2.2 2.2 6.2 2.9-4 4.4 3.2L21 4Z" />
      <path d="m9 13 12-9" />
    </>
  ),
  bell: (
    <>
      <path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 1.5h-15L6 16.5Z" />
      <path d="M10 20.5a2 2 0 0 0 4 0" />
    </>
  ),
  update: (
    <>
      <path d="M12 3.5v10M8 9.5l4 4 4-4" />
      <path d="M4.5 14.5v3a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-3" />
    </>
  ),
};

export function Icon({ name, size = 20 }: { name: keyof typeof ICONS | string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICONS[name]}
    </svg>
  );
}

/** A number whose digits roll to their value, like an odometer. `value` is a ready string. */
export function Odo({ value }: { value: string }) {
  const { digitsOf } = useApp();
  const [shown, setShown] = useState<string | null>(null);
  // Starts at zero and rolls on the next frame; later changes roll at once.
  useEffect(() => {
    const id = requestAnimationFrame(() => requestAnimationFrame(() => setShown(value)));
    return () => cancelAnimationFrame(id);
  }, [value]);
  const digitAt = (ch: string) => {
    const fa = FA_DIGITS.indexOf(ch);
    return fa >= 0 ? fa : /[0-9]/.test(ch) ? Number(ch) : -1;
  };
  const glyphs = Array.from({ length: 10 }, (_, d) => digitsOf(String(d)));
  const target = shown ?? value;
  return (
    <span className="odo" aria-label={value}>
      {[...value].map((ch, i) => {
        const d = digitAt(ch);
        if (d < 0) return <span key={i}>{ch}</span>;
        const at = shown === null ? 0 : digitAt(target[i] ?? ch);
        return (
          <span className="odo-d" key={i}>
            <span className="odo-c" style={{ transform: `translateY(${-Math.max(0, at) * 10}%)` }}>
              {glyphs.map((g, k) => (
                <span key={k}>{g}</span>
              ))}
            </span>
          </span>
        );
      })}
    </span>
  );
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Keeps the keyboard inside a modal: Tab and Shift+Tab go round its controls instead of out
 * into the page behind it, and when it closes focus goes back to what opened it.
 */
export function useFocusTrap(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const box = ref.current;
    if (!box) return;
    const opener = document.activeElement as HTMLElement | null;
    const controls = () => [...box.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((n) => n.getClientRects().length > 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const list = controls();
      if (list.length === 0) return e.preventDefault();
      const first = list[0];
      const last = list[list.length - 1];
      const at = document.activeElement;
      const outside = !at || !box.contains(at);
      if (e.shiftKey && (at === first || outside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (at === last || outside)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      opener?.focus?.();
    };
  }, [ref]);
}

export function Dialog({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const { t, low } = useApp();
  const ref = useRef<HTMLDivElement>(null);
  const backdrop = useRef<HTMLDivElement>(null);
  const [on, setOn] = useState(false);
  useFocusTrap(ref);
  const lowNow = useRef(low);
  lowNow.current = low;
  // However it closes (its own button, a footer button, a finished operation), the parent
  // just stops drawing it. A still copy is left on the page for a moment to fade out, so a
  // dialog does not vanish in one frame while it came in with a movement.
  useLayoutEffect(() => {
    const node = backdrop.current;
    return () => {
      if (!node?.classList.contains("is-on") || lowNow.current || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const ghost = node.cloneNode(true) as HTMLElement;
      ghost.removeAttribute("role");
      ghost.setAttribute("aria-hidden", "true");
      ghost.inert = true;
      ghost.style.pointerEvents = "none";
      document.body.appendChild(ghost);
      requestAnimationFrame(() => ghost.classList.remove("is-on"));
      setTimeout(() => ghost.remove(), 400);
    };
  }, []);
  // The parent passes a new function every time it renders (the panel refreshes every 2 s):
  // the latest one is kept here, and the effect runs once. Run on every render, it moved
  // the focus to the first field while a person was typing in another.
  const closing = useRef(onClose);
  closing.current = onClose;
  useEffect(() => {
    const id = requestAnimationFrame(() => setOn(true));
    const key = (e: KeyboardEvent) => e.key === "Escape" && closing.current();
    addEventListener("keydown", key);
    ref.current?.querySelector<HTMLElement>("input, button:not(.x-btn)")?.focus();
    return () => {
      cancelAnimationFrame(id);
      removeEventListener("keydown", key);
    };
  }, []);
  // On the page's body, so no moving parent can clip or shift it.
  return createPortal(
    <div ref={backdrop} className={`dialog-backdrop ${on ? "is-on" : ""}`} role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog" ref={ref}>
        <header>
          <h2>{title}</h2>
          <button className="x-btn" type="button" onClick={onClose} aria-label={t("close")}>
            <Icon name="x" />
          </button>
        </header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

/** The credit line: shown at the foot of every page and under the sign-in form. */
export function Copyright() {
  return (
    <p className="copyright" dir="ltr">
      <span>©</span>
      <a href={CHANNEL_URL} target="_blank" rel="noopener noreferrer">
        Erfan_Xray
      </a>
      <span aria-hidden="true">·</span>
      <a href="https://github.com/Erfan-XRay/Kariz" target="_blank" rel="noopener noreferrer">
        Kariz
      </a>
    </p>
  );
}

export const CHANNEL_URL = "https://t.me/Erfan_Xray";
export const CHANNEL_HANDLE = "@Erfan_Xray";

/** The link to the author's Telegram channel: a small icon, beside the other top-bar controls. */
export function ChannelLink({ variant }: { variant: "square" | "chip" }) {
  const { t } = useApp();
  return (
    <a className={variant === "square" ? "square-btn" : "chip"} href={CHANNEL_URL} target="_blank" rel="noopener noreferrer" title={`${t("chan.name")} ${CHANNEL_HANDLE}`} aria-label={t("chan.label")}>
      <Icon name="telegram" size={variant === "square" ? 20 : 16} />
    </a>
  );
}

/** A row of choices, one pressed. */
/** Buttons of which one is on. An option can carry a count, shown as a badge beside its label. */
export function Seg<T extends string>({ value, options, onChange }: { value: T; options: [T, string, string?][]; onChange: (v: T) => void }) {
  return (
    <div className="seg" role="group">
      {options.map(([v, label, count]) => (
        <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>
          {label}
          {count !== undefined && <span className="seg-count">{count}</span>}
        </button>
      ))}
    </div>
  );
}

/**
 * Tabs over one page's parts. The panels stay mounted (a running speed test keeps running on
 * another tab); the caller hides the ones not chosen. A bar under the chosen tab slides to it.
 */
export function Tabs<T extends string>({ id, value, options, onChange, label }: { id: string; value: T; options: [T, string][]; onChange: (v: T) => void; label: string }) {
  const { lang } = useApp();
  const list = useRef<HTMLDivElement>(null);
  const [bar, setBar] = useState<{ x: number; w: number } | null>(null);
  useLayoutEffect(() => {
    const box = list.current;
    if (!box) return;
    const place = () => {
      const on = box.querySelector<HTMLElement>('[aria-selected="true"]');
      if (on) setBar({ x: on.offsetLeft, w: on.offsetWidth });
    };
    place();
    const watch = new ResizeObserver(place);
    watch.observe(box);
    return () => watch.disconnect();
  }, [value, lang]);
  const move = (step: number) => {
    const at = options.findIndex(([v]) => v === value);
    const next = options[(at + step + options.length) % options.length][0];
    onChange(next);
    list.current?.querySelector<HTMLElement>(`#${id}-tab-${next}`)?.focus();
  };
  return (
    <div
      className="tabs"
      role="tablist"
      aria-label={label}
      ref={list}
      onKeyDown={(e) => {
        // Arrows follow the reading direction: in Persian the next tab is on the left.
        const rtl = document.documentElement.dir === "rtl";
        if (e.key === "ArrowRight") move(rtl ? -1 : 1);
        else if (e.key === "ArrowLeft") move(rtl ? 1 : -1);
        else return;
        e.preventDefault();
      }}
    >
      {options.map(([v, text]) => (
        <button
          key={v}
          id={`${id}-tab-${v}`}
          type="button"
          role="tab"
          aria-selected={value === v}
          aria-controls={`${id}-panel-${v}`}
          tabIndex={value === v ? 0 : -1}
          onClick={() => onChange(v)}
        >
          {text}
        </button>
      ))}
      {bar && <span className="tabs-bar" aria-hidden="true" style={{ width: bar.w, transform: `translateX(${bar.x}px)` }} />}
    </div>
  );
}

export interface MenuItem {
  label: string;
  icon: string;
  run: () => void;
  danger?: boolean;
  disabled?: boolean;
}

/** A button that opens a short list of the less used actions. */
export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const entries = () => [...(box.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled)') ?? [])];
  useEffect(() => {
    if (!open) return;
    entries()[0]?.focus();
    const away = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  const close = () => {
    setOpen(false);
    button.current?.focus();
  };
  return (
    <div className="menu" ref={box}>
      <button
        ref={button}
        className="icon-square"
        type="button"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <Icon name="more" size={18} />
      </button>
      {open && (
        <div
          className="menu-list"
          role="menu"
          aria-label={label}
          onKeyDown={(e) => {
            const list = entries();
            const at = list.indexOf(document.activeElement as HTMLElement);
            if (e.key === "Escape") close();
            else if (e.key === "ArrowDown") list[(at + 1) % list.length]?.focus();
            else if (e.key === "ArrowUp") list[(at - 1 + list.length) % list.length]?.focus();
            else if (e.key === "Tab") setOpen(false);
            else return;
            if (e.key !== "Tab") e.preventDefault();
          }}
        >
          {items.map((x) => (
            <button
              key={x.label}
              type="button"
              role="menuitem"
              className={x.danger ? "danger" : undefined}
              disabled={x.disabled}
              onClick={() => {
                setOpen(false);
                x.run();
              }}
            >
              <Icon name={x.icon} size={18} />
              {x.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * A separator between two bits of a line. Not "·": next to Persian digits it reads as a zero
 * ("·۱" looks like "۱۰"), so it is a short line drawn in CSS.
 */
export const Sep = () => <span className="sep" aria-hidden="true" />;

/** A block of code with a copy button. */
export function CodeBlock({ text }: { text: string }) {
  const { t, toast } = useApp();
  const [done, setDone] = useState(false);
  return (
    <pre className="code">
      {text}
      <button
        className={`copy-btn ${done ? "done" : ""}`}
        type="button"
        aria-label={done ? t("copied") : t("copy")}
        title={done ? t("copied") : t("copy")}
        onClick={() => {
          void copyText(text).then((ok) => {
            if (!ok) return toast(t("copy.failed", { value: text }), "err");
            setDone(true);
            setTimeout(() => setDone(false), 1600);
          });
        }}
      >
        <Icon name={done ? "check" : "copy"} size={18} />
      </button>
    </pre>
  );
}

/**
 * A value (an IP address) that copies itself when it is clicked or tapped. The chip shows a
 * check for a moment and a toast says what was copied; if the browser refuses, the toast says
 * so and shows the value, which can still be selected by hand.
 */
export function CopyValue({ what, value, label }: { what: string; value: string; label?: string }) {
  const { t, toast } = useApp();
  const [done, setDone] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    if (!(await copyText(value))) {
      toast(t("copy.failed", { value }), "err");
      return;
    }
    setDone(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setDone(false), 1600);
    toast(t("copy.done", { what }), "ok");
  };
  return (
    <button type="button" className={`copy-val ${done ? "done" : ""}`} dir="ltr" aria-label={t("copy.label", { what, value })} onClick={() => void copy()}>
      {label && <b>{label}</b>}
      <span className="copy-val-text">{value}</span>
      <Icon name={done ? "check" : "copy"} size={14} />
    </button>
  );
}

/** A surface with an optional heading row. */
export function Card({
  title,
  sub,
  actions,
  className = "",
  children,
  id,
  flush,
}: {
  title?: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
  className?: string;
  children?: ReactNode;
  id?: string;
  /** No inner padding: for tables and canvases that run to the edges. */
  flush?: boolean;
}) {
  return (
    <section className={`card ${flush ? "flush" : ""} ${className}`} id={id}>
      {(title || actions) && (
        <header className="card-head">
          <div className="card-titles">
            {title && <h2>{title}</h2>}
            {sub && <p>{sub}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

/** A tunnel's or server's state as a small pill with a dot. */
export function StatePill({ state, label }: { state: "up" | "down" | "off" | "warn"; label: string }) {
  return (
    <span className={`pill ${state}`}>
      <i className={`dot ${state}`} aria-hidden="true" />
      {label}
    </span>
  );
}

/** A small line of recent values, drawn as water. */
export function Sparkline({ values, className = "" }: { values: number[]; className?: string }) {
  if (values.length < 2) return <svg className={`spark ${className}`} aria-hidden="true" />;
  const W = 120;
  const H = 32;
  const top = Math.max(...values, 0.0001);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * W, H - 2 - (v / top) * (H - 6)]);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  return (
    <svg className={`spark ${className}`} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      <path d={`${line} L${W} ${H} L0 ${H} Z`} className="spark-area" />
      <path d={line} className="spark-line" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** A friendly empty state: what is missing, and the button that makes it. */
export function Empty({ icon, title, text, action }: { icon: string; title: string; text?: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        <Icon name={icon} size={26} />
      </span>
      <h3>{title}</h3>
      {text && <p>{text}</p>}
      {action}
    </div>
  );
}

/** Grey shapes where content is about to be. */
export function Skeleton({ rows = 3, height = 56 }: { rows?: number; height?: number }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <i key={i} style={{ height }} />
      ))}
    </div>
  );
}

/** A number and its unit, the way the key numbers are shown. */
export function Stat({
  label,
  value,
  unit,
  note,
  icon,
  tone,
  children,
}: {
  label: string;
  value: ReactNode;
  unit?: ReactNode;
  note?: ReactNode;
  icon?: string;
  tone?: "water" | "accent" | "danger" | "warn";
  children?: ReactNode;
}) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-label">
        {icon && <Icon name={icon} size={16} />}
        <span>{label}</span>
      </div>
      <div className="stat-value num">
        {value}
        {unit && <span className="unit">{unit}</span>}
      </div>
      {note && <div className="stat-note">{note}</div>}
      {children}
    </div>
  );
}

/** "12 s ago", "3 h ago". */
export function useAgo() {
  const { t, num } = useApp();
  return (secs: number) => {
    if (secs < 60) return t("ago.s", { n: num(Math.max(0, Math.round(secs))) });
    if (secs < 3600) return t("ago.m", { n: num(Math.floor(secs / 60)) });
    if (secs < 86400) return t("ago.h", { n: num(Math.floor(secs / 3600)) });
    return t("ago.d", { n: num(Math.floor(secs / 86400)) });
  };
}
