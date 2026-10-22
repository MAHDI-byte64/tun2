import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type { EventRow, LogLine, ServerInfo } from "./api";
import { pairTunnels } from "./derive";
import { useApp } from "./store";
import { TerminalSection } from "./Terminal";
import { Card, Empty, Icon, Seg, useAgo } from "./ui";

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;

interface Parsed {
  time: string;
  level: string;
  text: string;
  server: string;
  role: string;
}

/** A journal line ("2026-09-29T21:17:46+0000 host kariz[12]: INFO ...") as its parts. */
function parse(l: LogLine): Parsed {
  const clean = l.text.replace(ANSI, "");
  const time = clean.slice(11, 19);
  const body = clean.replace(/^\S+\s+\S+\s+\S+?\[\d+\]:\s*/, "");
  const level = body.match(/\b(ERROR|WARN|INFO|DEBUG|TRACE)\b/)?.[1] ?? "INFO";
  // The level has its own badge and the time its own column: the line starts after them.
  const text = body.replace(/^(\S+\s+)?(ERROR|WARN|INFO|DEBUG|TRACE)\s+/, "");
  return { time, level, text, server: l.server, role: l.role };
}

export function LogsPage({ servers }: { servers: ServerInfo[] }) {
  const { t } = useApp();
  const tunnels = pairTunnels(servers);
  const [name, setName] = useState("");
  const [tab, setTab] = useState<"logs" | "events">("logs");
  const [level, setLevel] = useState("ALL");
  const [query, setQuery] = useState("");
  const [follow, setFollow] = useState(true);
  const [lines, setLines] = useState<Parsed[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [error, setError] = useState("");
  const view = useRef<HTMLDivElement>(null);
  const ago = useAgo();
  const names = new Map(servers.map((s) => [s.id, s.name]));

  useEffect(() => {
    if (!name && tunnels[0]) setName(tunnels[0].name);
  }, [tunnels.length]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (tab !== "logs" || !name) return;
    let alive = true;
    const load = () =>
      api
        .logs(name, 300)
        .then((r) => {
          if (!alive) return;
          setError("");
          setLines(r.lines.map(parse));
        })
        .catch(() => alive && setError(t("logs.none")));
    void load();
    const id = follow ? setInterval(load, 2500) : 0;
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [name, tab, follow]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (tab !== "events") return;
    let alive = true;
    const load = () =>
      api
        .events(100)
        .then((r) => alive && setEvents(r.events))
        .catch(() => {});
    void load();
    const id = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [tab]);

  const shown = useMemo(
    () => lines.filter((l) => (level === "ALL" || l.level === level) && (!query || l.text.toLowerCase().includes(query.toLowerCase()))),
    [lines, level, query],
  );

  useEffect(() => {
    if (follow && view.current) view.current.scrollTop = view.current.scrollHeight;
  }, [shown, follow]);

  const eventText = (e: EventRow) => t(`ev.${e.kind}`, { who: names.get(e.subject) ?? e.subject });

  return (
    <div className="page is-on">
      <TerminalSection servers={servers} />
      <div className="page-band log-bar">
        <Seg
          value={tab}
          options={[
            ["logs", t("logs.tab")],
            ["events", t("logs.events")],
          ]}
          onChange={setTab}
        />
        {tab === "logs" && (
          <>
            <select className="select" aria-label={t("t.name")} value={name} onChange={(e) => setName(e.target.value)}>
              {tunnels.map((x) => (
                <option key={x.name} value={x.name}>
                  {x.name}
                </option>
              ))}
            </select>
            <select className="select" aria-label={t("logs.level")} value={level} onChange={(e) => setLevel(e.target.value)}>
              {["ALL", "ERROR", "WARN", "INFO", "DEBUG"].map((l) => (
                <option key={l} value={l}>
                  {l === "ALL" ? t("logs.allLevels") : l}
                </option>
              ))}
            </select>
            <label className="search">
              <Icon name="search" size={18} />
              <input type="search" dir="ltr" placeholder={t("logs.search")} aria-label={t("logs.search")} value={query} onChange={(e) => setQuery(e.target.value)} />
            </label>
            <span className="grow" />
            <button className={`btn btn-sm ${follow ? "btn-primary" : "btn-ghost"}`} type="button" aria-pressed={follow} title={t(follow ? "logs.followOn" : "logs.followOff")} onClick={() => setFollow(!follow)}>
              <Icon name={follow ? "pause" : "play"} size={16} />
              {t("logs.follow")}
            </button>
          </>
        )}
      </div>
      {tab === "logs" && (
        <div className="card flush log-card">
        <div className="log-view" ref={view} tabIndex={0} aria-label={t("logs.tab")}>
          {tunnels.length === 0 && <div className="log-empty">{t("tun.empty")}</div>}
          {tunnels.length > 0 && shown.length === 0 && <div className="log-empty">{error || t("logs.empty")}</div>}
          {shown.map((l, i) => (
            <div className={`log-line ${l.level}`} key={`${i}-${l.time}`}>
              <time>{l.time}</time>
              <span className={`lv ${l.level}`}>{l.level}</span>
              <span className="who">
                {names.get(l.server) ?? l.server} · {t(`tun.side.${l.role}`)}
              </span>
              <span>{l.text}</span>
            </div>
          ))}
        </div>
        </div>
      )}
      {tab === "events" && (
        <Card title={t("logs.events")}>
          {events.length === 0 ? (
            <Empty icon="logs" title={t("logs.noEvents")} />
          ) : (
            <ul className="timeline">
              {events.map((e) => (
                <li key={e.id} className={e.kind.endsWith("down") || e.kind === "quota_stop" ? "bad" : e.kind === "change" ? "info" : ""}>
                  <span>{eventText(e)}</span>
                  <time>{ago(Math.max(0, Date.now() / 1000 - e.at))}</time>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
