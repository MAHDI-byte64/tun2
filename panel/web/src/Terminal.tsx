import { useEffect, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal as Xterm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { csrfToken } from "./api";
import type { ServerInfo } from "./api";
import { useApp } from "./store";
import { Card, Icon } from "./ui";

type State = "closed" | "opening" | "open";

/** The Logs page's terminal: a shell on the server you pick, over its agent's link, for servers whose agent allows
 * it (`terminal = true`). One at a time; closed when you leave the page. */
export function TerminalSection({ servers }: { servers: ServerInfo[] }) {
  const { t, lang } = useApp();
  const online = servers.filter((s) => s.online);
  const [server, setServer] = useState("");
  const [state, setState] = useState<State>("closed");
  const [error, setError] = useState("");
  const box = useRef<HTMLDivElement>(null);
  const term = useRef<Xterm | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const sock = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!server && online[0]) setServer(online.find((s) => s.local)?.id ?? online[0].id);
  }, [online.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const close = () => {
    sock.current?.close();
    sock.current = null;
    term.current?.dispose();
    term.current = null;
    fit.current = null;
    setState("closed");
  };

  useEffect(() => {
    const onResize = () => fit.current?.fit();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      close();
    };
  }, []);

  const open = () => {
    if (!box.current || !server) return;
    close();
    setError("");
    const x = new Xterm({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      scrollback: 2000,
      theme: { background: "#0b0f17", foreground: "#e6e9ef", cursor: "#e6e9ef" },
    });
    const f = new FitAddon();
    x.loadAddon(f);
    x.open(box.current);
    f.fit();
    const url = new URL("api/terminal", location.href);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("server", server);
    url.searchParams.set("csrf", csrfToken());
    url.searchParams.set("cols", String(x.cols));
    url.searchParams.set("rows", String(x.rows));
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    setState("opening");
    const encoder = new TextEncoder();
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        let m: { ok?: boolean; error?: string; exit?: number } = {};
        try {
          m = JSON.parse(ev.data);
        } catch {
          return;
        }
        if (m.ok) {
          setState("open");
          x.focus();
        } else if (m.error) {
          setError(errorText(m.error));
        } else if (m.exit !== undefined) {
          x.write(`\r\n[${t("term.exited", { code: m.exit })}]\r\n`);
        }
      } else {
        x.write(new Uint8Array(ev.data as ArrayBuffer));
      }
    };
    ws.onclose = () => {
      setState("closed");
      if (term.current === x) x.options.disableStdin = true;
    };
    ws.onerror = () => setError((e) => e || t("term.failed"));
    x.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(d));
    });
    x.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ resize: [cols, rows] }));
    });
    term.current = x;
    fit.current = f;
    sock.current = ws;
  };

  const errorText = (code: string) => {
    if (code === "terminal_off") return t("term.off");
    if (code === "unknown request") return t("term.old");
    if (code === "busy") return t("term.busy");
    if (code === "not connected") return t("term.offline");
    return t("term.failedWhy", { why: code });
  };

  const chip = state === "open" ? t("term.connected") : state === "opening" ? t("term.connecting") : t("term.closed");

  return (
    <Card title={t("term.title")} sub={t("term.sub")} className="term-card">
      <div className="ar-row term-bar" style={{ flexWrap: "wrap" }}>
        <select id="term-server" className="select" aria-label={t("term.server")} value={server} disabled={state !== "closed"} onChange={(e) => setServer(e.target.value)}>
          {online.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        {state === "closed" ? (
          <button className="btn btn-primary btn-sm" type="button" disabled={!server} onClick={open}>
            <Icon name="link" size={16} />
            {t("term.open")}
          </button>
        ) : (
          <button className="btn btn-ghost btn-sm" type="button" onClick={close}>
            <Icon name="exit" size={16} />
            {t("term.close")}
          </button>
        )}
        <span className={`tag term-state is-${state}`} aria-live="polite">
          {chip}
        </span>
      </div>
      {error && (
        <p className="banner info small" role="alert">
          {error}
        </p>
      )}
      <div ref={box} className="term-box" role="region" dir="ltr" lang={lang === "fa" ? "en" : undefined} aria-label={t("term.title")} />
    </Card>
  );
}
