import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api, kindLabel } from "./api";
import type { GreJoin, LinkKind, LinkTransport, PanelAddresses, ServerInfo, SessionRow } from "./api";
import { bytesPerSec, pairTunnels, rateParts } from "./derive";
import type { TunnelState } from "./derive";
import type { Route } from "./App";
import { paletteNow } from "./draw";
import { startMap } from "./scene-map";
import type { MapData, MapHit } from "./scene-map";
import { useApp } from "./store";
import { BackupDialog, RestoreDialog } from "./Extras";
import { TelegramSection } from "./Telegram";
import { AutoRestartDialog } from "./AutoRestart";
import { ServerFixDialog } from "./ServerFix";
import { useNetworks } from "./Networks";
import { NewGreLinkFields, greJoinError, ipv4Ok, networkOfKind } from "./GreLink";
import { AgentPortField, agentPortError, agentPortOf, agentPortOk } from "./AgentPort";
import { ArrangeServers, arranged } from "./Arrange";
import { hostPort, linkPorts, reverseOk, transportLabel } from "./transport";
import { Card, CodeBlock, CopyValue, Dialog, Empty, Icon, Odo, Seg, Sep, Skeleton, Sparkline, Stat, StatePill, useAgo } from "./ui";

// ---------------------------------------------------------------- the map

const stateKey = { up: "st.up", down: "st.down", off: "st.off" } as const;

// The total throughput of the last few minutes, kept while the panel is open (every reading
// of the servers adds one), for the small line under the big number.
const throughput: number[] = [];
let lastReading: ServerInfo[] | null = null;

export function MapPage({
  servers,
  loaded,
  navigate,
  outdated,
  onUpdateServers,
}: {
  servers: ServerInfo[];
  loaded: boolean;
  navigate: (to: Route) => void;
  outdated: number;
  onUpdateServers: () => void;
}) {
  const { t, num, low } = useApp();
  const ago = useAgo();
  const canvas = useRef<HTMLCanvasElement>(null);
  const band = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<MapHit | null>(null);
  const tunnels = useMemo(() => pairTunnels(servers), [servers]);
  // The scene reads the latest data and settings without restarting.
  const data = useRef<MapData>({ servers: [], tunnels: [] });
  const lowRef = useRef(low);
  const nav = useRef(navigate);
  nav.current = navigate;
  data.current = {
    servers: servers.map((s) => ({ id: s.id, name: s.name, sub: s.local ? t("role.local") : `${s.arch} · ${s.version}`, st: s.online ? ("up" as const) : ("down" as const) })),
    tunnels: tunnels
      .filter((x) => x.paired)
      .map((x) => {
        const r = rateParts(x.rate);
        return {
          id: x.name,
          a: x.entry!.server.id,
          b: x.exit!.server.id,
          st: x.state,
          rate: x.rate,
          label: x.name,
          value: x.state === "up" ? `${num(r.value, r.decimals)} ${r.unit}` : t(stateKey[x.state]),
        };
      }),
  };
  lowRef.current = low;

  useEffect(() => {
    if (!canvas.current) return;
    return startMap(canvas.current, {
      data: () => data.current,
      palette: paletteNow,
      low: () => lowRef.current,
      rtl: () => document.documentElement.dir === "rtl",
      onHover: setTip,
      onOpen: (hit) => nav.current(hit.kind === "tunnel" ? { page: "tunnels", tunnel: hit.id } : { page: "servers" }),
    });
    // the canvas is there only once the first reading came
  }, [loaded]);

  const up = tunnels.filter((x) => x.state === "up");
  const total = up.reduce((n, x) => n + x.rate, 0);
  if (loaded && servers !== lastReading) {
    lastReading = servers;
    throughput.push(total);
    if (throughput.length > 72) throughput.shift();
  }
  const rate = rateParts(total);
  const conns = up.reduce((n, x) => n + x.connections, 0);
  const online = servers.filter((s) => s.online);
  const offline = servers.filter((s) => !s.online);
  const hot = online.filter((s) => (s.health?.cpu_pct ?? 0) > 85);
  const broken = tunnels.filter((x) => x.state === "down");
  const blocked = tunnels.filter((x) => x.blocked);
  const crowded = tunnels.filter((x) => !x.blocked && x.capacity && x.capacity.streams >= x.capacity.max * 0.8);
  const maxRate = Math.max(1, ...tunnels.map((x) => x.rate));
  const hoveredServer = tip?.kind === "server" ? servers.find((s) => s.id === tip.id) : undefined;
  const hoveredTunnel = tip?.kind === "tunnel" ? tunnels.find((x) => x.name === tip.id) : undefined;
  const bandW = band.current?.clientWidth ?? 800;
  const count = (s: TunnelState) => tunnels.filter((x) => x.state === s).length;

  if (!loaded) {
    return (
      <div className="page is-on">
        <div className="stats">
          {[0, 1, 2, 3].map((i) => (
            <div className="card stat-card" key={i}>
              <Skeleton rows={1} height={64} />
            </div>
          ))}
        </div>
        <div className="card">
          <Skeleton rows={1} height={380} />
        </div>
      </div>
    );
  }

  const attention: { key: string; tone: "danger" | "warn"; icon: string; text: string; action?: [string, () => void] }[] = [
    ...broken.map((x) => ({
      key: `t-${x.name}`,
      tone: "danger" as const,
      icon: "tunnels",
      text: t("att.broken", { name: x.name }),
      action: [t("att.open"), () => navigate({ page: "tunnels", tunnel: x.name })] as [string, () => void],
    })),
    ...blocked.map((x) => ({
      key: `b-${x.name}`,
      tone: "danger" as const,
      icon: "tunnels",
      text: t("att.blocked", { name: x.name }),
      action: [t("att.open"), () => navigate({ page: "tunnels", tunnel: x.name })] as [string, () => void],
    })),
    ...crowded.map((x) => ({
      key: `f-${x.name}`,
      tone: "warn" as const,
      icon: "tunnels",
      text: t("att.crowded", { name: x.name, n: num(Math.round(((x.capacity?.streams ?? 0) / (x.capacity?.max ?? 1)) * 100)) }),
      action: [t("att.open"), () => navigate({ page: "tunnels", tunnel: x.name })] as [string, () => void],
    })),
    ...offline.map((s) => ({
      key: `s-${s.id}`,
      tone: "danger" as const,
      icon: "servers",
      text: s.seen_secs != null ? t("att.offlineSeen", { name: s.name, ago: ago(s.seen_secs) }) : t("att.offline", { name: s.name }),
      action: [t("att.servers"), () => navigate({ page: "servers" })] as [string, () => void],
    })),
    ...hot.map((s) => ({
      key: `c-${s.id}`,
      tone: "warn" as const,
      icon: "cpu",
      text: t("att.cpu", { name: s.name, n: num(Math.round(s.health?.cpu_pct ?? 0)) }),
    })),
    ...(outdated > 0
      ? [{ key: "upd", tone: "warn" as const, icon: "update", text: t(outdated === 1 ? "att.outdated1" : "att.outdated", { n: num(outdated) }), action: [t("upd.serversGo"), onUpdateServers] as [string, () => void] }]
      : []),
  ];

  const danger = attention.some((a) => a.tone === "danger");

  return (
    <div className="page is-on dash">
      {/* What needs a hand comes first, above the numbers: an offline server must not wait below the map. */}
      {attention.length > 0 && (
        <section className={`card att-top ${danger ? "danger" : "warn"}`} aria-labelledby="att-h">
          <h2 id="att-h">
            <Icon name="alert" size={18} />
            {t("att.title")}
            <span className="att-count num">{num(attention.length)}</span>
          </h2>
          <ul className="att-list">
            {attention.map((a) => (
              <li key={a.key} className={a.tone}>
                <span className="att-icon" aria-hidden="true">
                  <Icon name={a.icon} size={16} />
                </span>
                <span className="att-text">{a.text}</span>
                {a.action && (
                  <button className="btn btn-ghost btn-xs" type="button" onClick={a.action[1]}>
                    {a.action[0]}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="stats">
        <div className="card stat-card hero">
          <Stat label={t("m.through")} icon="pulse" tone="water" value={<Odo value={num(rate.value, rate.decimals)} />} unit={rate.unit}>
            <Sparkline values={throughput} />
          </Stat>
        </div>
        <div className="card stat-card">
          <Stat label={t("m.conns")} icon="link" value={<Odo value={num(conns)} />} note={t("m.connsNote", { n: num(up.length) })} />
        </div>
        <div className="card stat-card">
          <Stat
            label={t("m.tunnels")}
            icon="tunnels"
            value={<Odo value={num(up.length)} />}
            unit={`${t("m.of")} ${num(tunnels.length)}`}
            note={
              tunnels.length ? (
                <span className="state-bar" aria-hidden="true">
                  {(["up", "down", "off"] as TunnelState[]).map((s) => count(s) > 0 && <i key={s} className={s} style={{ flexGrow: count(s) }} />)}
                </span>
              ) : undefined
            }
          />
        </div>
        <div className="card stat-card">
          <Stat
            label={t("m.servers")}
            icon="servers"
            value={<Odo value={num(online.length)} />}
            unit={`${t("m.of")} ${num(servers.length)}`}
            tone={offline.length ? "danger" : undefined}
            note={offline.length ? t("m.offlineNote", { names: offline.map((s) => s.name).join("، ") }) : t("m.allOnline")}
          />
        </div>
      </div>

      <section className="card flush map-card" aria-labelledby="map-h">
        <header className="card-head">
          <div className="card-titles">
            <h2 id="map-h">{t("map.title")}</h2>
            <p>{t("map.hint")}</p>
          </div>
          <div className="map-legend" aria-hidden="true">
            <span>
              <i className="dot up" />
              {t("st.up")}
            </span>
            <span>
              <i className="dot down" />
              {t("st.down")}
            </span>
            <span>
              <i className="dot off" />
              {t("st.off")}
            </span>
          </div>
        </header>
        <div className="map-band" ref={band}>
          <canvas id="map" ref={canvas} role="img" aria-label={t("nav.map")} aria-describedby="map-alt" />
          {tip && (hoveredServer || hoveredTunnel) && (
            <div className="map-tip is-on" style={{ left: Math.max(8, Math.min(tip.x + 16, bandW - 250)), top: tip.y + 16 }}>
              {hoveredServer && (
                <>
                  <b>
                    <i className={`dot ${hoveredServer.online ? "up" : "down"}`} /> {hoveredServer.name}
                  </b>
                  <div className="row">
                    <span>{t("srv.cpu")}</span>
                    <span className="num">{hoveredServer.health?.cpu_pct != null ? `${num(Math.round(hoveredServer.health.cpu_pct))}%` : "—"}</span>
                  </div>
                  <div className="row">
                    <span>{t("srv.ram")}</span>
                    <span className="num">{hoveredServer.health?.mem_total ? `${num(Math.round(((hoveredServer.health.mem_used ?? 0) * 100) / hoveredServer.health.mem_total))}%` : "—"}</span>
                  </div>
                  <div className="row">
                    <span>{t("tip.tunnels")}</span>
                    <span className="num">{num(hoveredServer.tunnels.length)}</span>
                  </div>
                </>
              )}
              {hoveredTunnel && (
                <>
                  <b>
                    <i className={`dot ${hoveredTunnel.state}`} /> {hoveredTunnel.name}
                  </b>
                  <div className="row">
                    <span className="mono">
                      {hoveredTunnel.entry?.server.name} → {hoveredTunnel.exit?.server.name}
                    </span>
                  </div>
                  <div className="row">
                    <span>{t("t.rate")}</span>
                    <span className="num" dir="ltr">
                      {hoveredTunnel.state === "up" ? `${num(rateParts(hoveredTunnel.rate).value, rateParts(hoveredTunnel.rate).decimals)} ${rateParts(hoveredTunnel.rate).unit}` : "—"}
                    </span>
                  </div>
                  <div className="row">
                    <span>{t("tun.conns")}</span>
                    <span className="num">{hoveredTunnel.state === "up" ? num(hoveredTunnel.connections) : "—"}</span>
                  </div>
                  {hoveredTunnel.rtt != null && (
                    <div className="row">
                      <span>{t("tun.rtt")}</span>
                      <span className="num" dir="ltr">
                        {num(hoveredTunnel.rtt, 0)} ms
                      </span>
                    </div>
                  )}
                  <div className="row">
                    <span>{t("t.transport")}</span>
                    <span className="mono">
                      {transportLabel(hoveredTunnel.transport, hoveredTunnel.via)} · {hoveredTunnel.profile}
                    </span>
                  </div>
                  {hoveredTunnel.error && hoveredTunnel.state !== "up" && <div className="tip-err">{hoveredTunnel.error}</div>}
                  <div className="tip-foot">{t("map.clickOpen")}</div>
                </>
              )}
            </div>
          )}
          <p className="sr-only" id="map-alt">
            {t("alt.prefix")} {servers.map((s) => s.name).join(", ")}; {tunnels.map((x) => `${x.name}: ${t(stateKey[x.state])}`).join(", ")}
          </p>
        </div>
      </section>

      <div className="dash-grid">
        <Card
          title={t("t.title")}
          sub={tunnels.length ? t("t.sub", { up: num(up.length), all: num(tunnels.length) }) : undefined}
          actions={
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => navigate({ page: "tunnels" })}>
              {t("t.all")}
              <Icon name="chevron" size={16} />
            </button>
          }
          flush
        >
          {tunnels.length === 0 ? (
            <Empty
              icon="tunnels"
              title={t("t.emptyTitle")}
              text={online.length < 2 ? t("tun.needTwo") : t("t.empty")}
              action={
                <button className="btn btn-primary btn-sm" type="button" onClick={() => navigate({ page: online.length < 2 ? "servers" : "tunnels" })}>
                  <Icon name="plus" size={18} />
                  {online.length < 2 ? t("srv.add") : t("tun.new")}
                </button>
              }
            />
          ) : (
            <ul className="t-list">
              {tunnels.map((x) => {
                const r = rateParts(x.rate);
                return (
                  <li key={x.name}>
                    <button type="button" className={`t-row ${x.state}`} onClick={() => navigate({ page: "tunnels", tunnel: x.name })}>
                      <span className={`t-mark ${x.state}`} aria-hidden="true" />
                      <span className="t-main">
                        <span className="t-name">{x.name}</span>
                        <span className="t-route">
                          {x.paired ? (
                            <>
                              <span>{x.entry!.server.name}</span>
                              <Icon name="arrow" size={14} />
                              <span>{x.exit!.server.name}</span>
                            </>
                          ) : (
                            <span>
                              {(x.entry ?? x.exit)!.server.name} · {t("t.oneSide")}
                            </span>
                          )}
                        </span>
                      </span>
                      <span className="t-bar" aria-hidden="true">
                        <i style={{ width: `${x.state === "up" ? Math.max(2, (x.rate / maxRate) * 100) : 0}%` }} />
                      </span>
                      <span className={`t-rate num ${x.state}`} dir="ltr">
                        {x.state === "up" ? (
                          <>
                            {num(r.value, r.decimals)} <small>{r.unit}</small>
                          </>
                        ) : (
                          <span dir="auto">{t(stateKey[x.state])}</span>
                        )}
                      </span>
                      <Icon name="chevron" size={16} />
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <div className="dash-side">
          {attention.length === 0 && (
            <Card title={t("att.title")} sub={t("att.clearText")}>
              <div className="all-clear">
                <span className="ok-mark" aria-hidden="true">
                  <Icon name="check" size={20} />
                </span>
                <span>{t("att.clear")}</span>
              </div>
            </Card>
          )}
          <Card
            title={t("m.load")}
            actions={
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => navigate({ page: "servers" })}>
                {t("t.all")}
                <Icon name="chevron" size={16} />
              </button>
            }
          >
            <ul className="mini-srv">
              {servers.map((s) => {
                const cpu = s.health?.cpu_pct ?? null;
                return (
                  <li key={s.id}>
                    <i className={`dot ${s.online ? "up" : "down"}`} aria-hidden="true" />
                    <span className="nm">{s.name}</span>
                    <span className={`mini-bar ${cpu != null && cpu > 85 ? "hot" : ""}`} aria-hidden="true">
                      <i style={{ width: `${s.online && cpu != null ? Math.max(2, Math.min(100, cpu)) : 0}%` }} />
                    </span>
                    <span className="num small">{s.online && cpu != null ? `${num(Math.round(cpu))}%` : t("srv.offline")}</span>
                  </li>
                );
              })}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- servers

function Well({ level = 0.6, online = true }: { level?: number; online?: boolean }) {
  const y = 40 - 14 * level;
  return (
    <svg className="srv-well" viewBox="0 0 44 44" aria-hidden="true">
      <path d="M4 16h36" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" />
      <path d="M12 16a10 7 0 0 1 20 0Z" fill="var(--accent)" />
      <rect x="18" y="16" width="8" height="25" rx="2" fill="var(--stratum-3)" />
      <rect x="18" y={y} width="8" height={41 - y} rx="2" fill={online ? "var(--water)" : "var(--text-3)"} />
    </svg>
  );
}

function Meter({ label, pct }: { label: string; pct: number | null }) {
  const { num } = useApp();
  const v = pct == null ? 0 : Math.max(0, Math.min(100, pct));
  return (
    <div className={`meter ${v > 85 ? "hot" : ""}`}>
      <div className="top">
        <span>{label}</span>
        <b>{pct == null ? "—" : `${num(Math.round(v))}%`}</b>
      </div>
      <div className="bar">
        <i style={{ width: `${v}%` }} />
      </div>
    </div>
  );
}

/**
 * How a new server joins: its agent dials the panel over the internet (the panel's public address) or over a
 * private GRE link the panel sets up for it, or the panel dials the agent (reverse).
 */
type JoinWay = "internet" | "gre" | "vxlan" | "reverse";

/** The port a reverse agent listens on, until another is typed. */
const REVERSE_PORT = "29001";

function AddServer({ servers, agentsOn, onClose }: { servers: ServerInfo[]; agentsOn: boolean; onClose: () => void }) {
  const { t, digitsOf, toast } = useApp();
  const [way, setWay] = useState<JoinWay>("internet");
  const [name, setName] = useState("");
  const [host, setHost] = useState(location.hostname.replace(/^\[|\]$/g, ""));
  const [transport, setTransport] = useState<LinkTransport>("auto");
  // An agents port of its own (empty: the panel's).
  const [ownPort, setOwnPort] = useState("");
  // Over GRE: the new server's public IPv4 address, and the network its link takes its addresses from.
  const [ip, setIp] = useState("");
  const { networks } = useNetworks();
  const [netId, setNetId] = useState("");
  const [gre, setGre] = useState<GreJoin | null>(null);
  // Reverse: where the panel reaches the new server, and the port its agent listens on.
  const [rhost, setRhost] = useState("");
  const [rport, setRport] = useState(REVERSE_PORT);
  const [rev, setRev] = useState<{ addr: string; port: number } | null>(null);
  // Reverse across a GRE link the panel makes: the new server's public IPv4 and network are the ones above.
  const [revGre, setRevGre] = useState(false);
  const [revKind, setRevKind] = useState<LinkKind>("gre");
  // Over a private link the panel makes (GRE or VXLAN), and its kind.
  const overLink = way === "gre" || way === "vxlan";
  const linkKind: LinkKind = way === "vxlan" ? "vxlan" : "gre";
  const [busy, setBusy] = useState(false);
  const [own, setOwn] = useState<PanelAddresses | null>(null);
  const [code, setCode] = useState("");
  const [left, setLeft] = useState(0);
  const [error, setError] = useState("");
  const known = useRef<Set<string>>(new Set());
  const joined = servers.find((s) => code && !known.current.has(s.id) && s.online);
  const names = new Map(servers.map((s) => [s.id, s.name]));

  // The panel's own public addresses (IPv4 and IPv6), to pick from.
  useEffect(() => {
    let alive = true;
    api
      .panelAddresses()
      .then((a) => alive && setOwn(a))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (left <= 0 || joined) return;
    const id = setInterval(() => setLeft((v) => Math.max(0, v - 1)), 1000);
    return () => clearInterval(id);
  }, [left > 0, !!joined]); // eslint-disable-line react-hooks/exhaustive-deps

  const make = async () => {
    setError("");
    setBusy(true);
    try {
      known.current = new Set(servers.map((s) => s.id));
      if (overLink) {
        const made = await api.joinGre(name.trim() || undefined, ip.trim(), networkOfKind(networks, netId, linkKind), "auto", linkKind, ownPort ? +ownPort : undefined);
        setGre(made);
        setCode(made.code);
        setLeft(made.valid_for);
      } else if (way === "reverse" && revGre) {
        const made = await api.joinReverse(name.trim() || undefined, "", +rport, transport, { ip: ip.trim(), network: networkOfKind(networks, netId, revKind), kind: revKind });
        setGre(made as GreJoin);
        setRev({ addr: hostPort(made.server_addr ?? "", rport.trim()), port: +rport });
        setCode(made.code);
        setLeft(made.valid_for);
      } else if (way === "reverse") {
        const made = await api.joinReverse(name.trim() || undefined, rhost.trim(), +rport, transport);
        setRev({ addr: hostPort(rhost.trim().replace(/^\[|\]$/g, ""), rport.trim()), port: +rport });
        setCode(made.code);
        setLeft(made.valid_for);
      } else {
        const made = await api.joinCode(name.trim() || undefined, host.trim(), transport, ownPort ? +ownPort : undefined);
        setCode(made.code);
        setLeft(made.valid_for);
      }
    } catch (e) {
      if (overLink) setError(e instanceof ApiError ? (agentPortError(t, e.code, names) ?? greJoinError(t, e.code, names)) : String(e));
      else if (way === "reverse" && revGre && !portOk) setError(t("add.rev.err.input"));
      else if (way === "reverse" && revGre) setError(e instanceof ApiError ? greJoinError(t, e.code, names) : String(e));
      else if (way === "reverse") setError(e instanceof ApiError && e.code !== "bad_input" ? greJoinError(t, e.code, names) : t("add.rev.err.input"));
      else if (e instanceof ApiError && agentPortError(t, e.code, names)) setError(agentPortError(t, e.code, names) ?? "");
      else setError(e instanceof ApiError && e.code === "agents_off" ? t("add.off") : t("add.bad"));
    } finally {
      setBusy(false);
    }
  };

  const mmss = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
  const mainPort = own?.agent_port ?? null;
  const port = way === "internet" || overLink ? agentPortOf(ownPort, mainPort) : mainPort;
  const here = location.hostname.replace(/^\[|\]$/g, "");
  const choices: [string, string][] = [
    ...(own?.v4 ? [[t("add.addr.v4"), own.v4] as [string, string]] : []),
    ...(own?.v6 ? [[t("add.addr.v6"), own.v6] as [string, string]] : []),
    ...(here && here !== own?.v4 && here !== own?.v6 ? [[t("add.addr.here"), here] as [string, string]] : []),
    ...(own?.gre ?? []).map((g) => [t("add.addr.gre", { kind: kindLabel(g.kind), network: g.network, server: servers.find((s) => s.id === g.server)?.name ?? g.server }), g.addr] as [string, string]),
  ];
  const greHost = (own?.gre ?? []).some((g) => g.addr === host.trim());
  const portText = (x: LinkTransport) => (port == null ? "?" : String(x === "wss" || x === "quic" ? port + 1 : port));
  const openList = port == null ? "" : linkPorts(port, transport);
  // The panel server's public address, the panel's end of the GRE link (unknown: it has to be set first).
  const panelPublic = own ? (own.gre_local ?? null) : undefined;
  const ipOk = ipv4Ok(ip);
  const portOk = /^\d+$/.test(rport) && +rport > 0 && +rport < 65535;
  const ready =
    overLink ? ipOk && panelPublic !== null && agentPortOk(ownPort) : way === "reverse" ? (revGre ? ipOk && panelPublic !== null && portOk : reverseOk(rhost, rport)) : !!host.trim() && agentPortOk(ownPort);
  // The panel needs no agents port of its own when it is the one that connects.
  const blocked = !agentsOn && way !== "reverse";
  const transportField = (help: string) => (
    <div className="field">
      <span className="label">{t("add.transport")}</span>
      <Seg
        value={transport}
        options={(["auto", "tcpmux", "kcp", "wss", "quic"] as LinkTransport[]).map((x) => [x, t(`add.x.${x}`)] as [LinkTransport, string])}
        onChange={setTransport}
      />
      <span className="help">{help}</span>
      {transport !== "auto" && <span className="help">{t(transport === "quic" ? "add.newAgentQuic" : "add.newAgent")}</span>}
    </div>
  );
  return (
    <Dialog
      title={t("add.title")}
      onClose={onClose}
      footer={
        joined ? (
          <button
            className="btn btn-primary btn-sm"
            type="button"
            onClick={() => {
              toast(t("add.connected", { name: joined.name }));
              onClose();
            }}
          >
            {t("add.done")}
          </button>
        ) : (
          <>
            <button className="btn btn-ghost btn-sm" type="button" onClick={onClose}>
              {code ? t("close") : t("cancel")}
            </button>
            {!code && (
              <button className="btn btn-primary btn-sm" type="button" disabled={!ready || blocked || busy} onClick={() => void make()}>
                {busy ? t("add.making") : t("add.make")}
              </button>
            )}
          </>
        )
      }
    >
      {blocked && <p className="err small">{t("add.off")}</p>}
      {!code && (
        <>
          <div className="field">
            <span className="label">{t("add.way")}</span>
            <div className="join-ways" role="group" aria-label={t("add.way")}>
              {(["internet", "gre", "vxlan", "reverse"] as JoinWay[]).map((w) => (
                <button
                  key={w}
                  type="button"
                  className="join-way"
                  aria-pressed={way === w}
                  onClick={() => {
                    setWay(w);
                    setError("");
                  }}
                >
                  <Icon name={w === "gre" || w === "vxlan" ? "networks" : w === "reverse" ? "back" : "map"} size={18} />
                  <b>{t(`add.way.${w}`)}</b>
                  <span>{t(`add.way.${w}.d`)}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="field">
            <label htmlFor="add-name">{t("add.name")}</label>
            <input className="text mono" id="add-name" dir="ltr" placeholder="istanbul-1" value={name} onChange={(e) => setName(e.target.value)} />
            <span className="help">{t(overLink ? "add.gre.nameHelp" : "add.nameHelp")}</span>
          </div>
          {way === "internet" && (
            <>
              <div className="field">
                <label htmlFor="add-host">{t("add.host")}</label>
                {choices.length > 1 && (
                  <div className="addr-picks" role="group" aria-label={t("add.host")}>
                    {choices.map(([label, value]) => (
                      <button key={value} type="button" className="addr-pick" aria-pressed={host === value} onClick={() => setHost(value)}>
                        <span>{label}</span>
                        <code dir="ltr">{value}</code>
                      </button>
                    ))}
                  </div>
                )}
                <input className="text mono" id="add-host" dir="ltr" value={host} onChange={(e) => setHost(e.target.value)} />
                <span className="help">{t("add.addrHelp")}</span>
                {greHost && <span className="help">{t("add.greHelp")}</span>}
                <span className="err">{error}</span>
              </div>
              <AgentPortField id="add-port" value={ownPort} onChange={setOwnPort} main={mainPort} />
              <div className="field">
                <span className="label">{t("add.transport")}</span>
                <Seg
                  value={transport}
                  options={(["auto", "tcpmux", "kcp", "wss", "quic"] as LinkTransport[]).map((x) => [x, t(`add.x.${x}`)] as [LinkTransport, string])}
                  onChange={setTransport}
                />
                <span className="help">{t(`add.x.${transport}.d`, { p: portText(transport) })}</span>
                {openList && (
                  <span className="help">
                    {t("add.ports", { list: "" })}
                    <code dir="ltr">{openList}</code>
                  </span>
                )}
                {transport !== "auto" && <span className="help">{t(transport === "quic" ? "add.newAgentQuic" : "add.newAgent")}</span>}
              </div>
            </>
          )}
          {way === "reverse" && (
            <>
              <div className="field">
                <label className="check">
                  <input
                    type="checkbox"
                    checked={revGre}
                    onChange={(e) => {
                      setRevGre(e.target.checked);
                      setError("");
                    }}
                  />{" "}
                  {t("add.rev.gre")}
                </label>
                <span className="help">{t("add.rev.gre.d")}</span>
              </div>
              {revGre && (
                <NewGreLinkFields
                  id="add-rip"
                  ip={ip}
                  onIp={setIp}
                  ipLabel={t("add.gre.ip")}
                  error={error}
                  networks={networks}
                  netId={netId}
                  onNet={setNetId}
                  panelPublic={panelPublic}
                  kind={revKind}
                  onKind={setRevKind}
                />
              )}
              <div className="grid-2">
                {!revGre && (
                  <div className="field">
                    <label htmlFor="add-rhost">{t("add.rev.host")}</label>
                    <input className="text mono" id="add-rhost" dir="ltr" placeholder="198.51.100.7" value={rhost} onChange={(e) => setRhost(e.target.value.trim())} />
                    <span className="help">{t("add.rev.hostHelp")}</span>
                  </div>
                )}
                <div className="field">
                  <label htmlFor="add-rport">{t("add.rev.port")}</label>
                  <input className="text mono" id="add-rport" dir="ltr" inputMode="numeric" value={rport} onChange={(e) => setRport(e.target.value.trim())} />
                  <span className="help">{t("add.rev.portHelp")}</span>
                </div>
              </div>
              {!revGre && (
                <span className="err" role="alert">
                  {error}
                </span>
              )}
              {transportField(
                transport === "auto"
                  ? t("add.rev.auto")
                  : t(`add.x.${transport}.d`, { p: String(/^\d+$/.test(rport) ? (transport === "wss" || transport === "quic" ? +rport + 1 : +rport) : "?") }),
              )}
              {portOk && (
                <p className="help">
                  {t(revGre ? "add.rev.gre.ports" : "add.rev.ports")} <code dir="ltr">{linkPorts(+rport, transport)}</code>
                </p>
              )}
              <ol className="gre-steps">
                <li>{t(revGre ? "add.rev.gre.step1" : "add.rev.step1", { kind: kindLabel(revKind) })}</li>
                <li>{t(revGre ? "add.rev.gre.step2" : "add.rev.step2")}</li>
                <li>{t(revGre ? "add.rev.gre.step3" : "add.rev.step3")}</li>
              </ol>
            </>
          )}
          {overLink && (
            <>
              <NewGreLinkFields id="add-ip" ip={ip} onIp={setIp} ipLabel={t("add.gre.ip")} error={error} networks={networks} netId={netId} onNet={setNetId} panelPublic={panelPublic} kind={linkKind} />
              <AgentPortField id="add-port" value={ownPort} onChange={setOwnPort} main={mainPort} />
              <ol className="gre-steps">
                <li>{t("add.gre.step1", { kind: kindLabel(linkKind) })}</li>
                <li>{t("add.gre.step2")}</li>
                <li>{t(linkKind === "vxlan" ? "add.vx.step3" : "add.gre.step3")}</li>
              </ol>
            </>
          )}
        </>
      )}
      {code && (
        <>
          {rev && (
            <div className="gre-made">
              <span className="badge">{t("srv.revChip", { addr: `\u2066${rev.addr}\u2069` })}</span>
              <span className="help">{t("add.rev.made", { addr: `\u2066${rev.addr}\u2069` })}</span>
              <span className="help">
                {t("add.rev.ports")} <code dir="ltr">{linkPorts(rev.port, transport)}</code>
              </span>
            </div>
          )}
          {gre && (
            <div className="gre-made">
              <span className="badge">{t("srv.greChip", { kind: kindLabel(gre.kind), network: gre.network })}</span>
              {/* The addresses are isolated left to right, so a Persian sentence around them keeps its order. */}
              <span className="small">{t("add.gre.link", { panel: `⁦${gre.panel_addr}⁩`, server: `⁦${gre.server_addr}⁩`, name: `⁨${gre.name}⁩` })}</span>
              <span className="help">{t(rev ? "add.rev.gre.made" : "add.gre.made")}</span>
            </div>
          )}
          <div className="field">
            <span className="label">{t("add.run")}</span>
            <CodeBlock text={`bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh) --agent ${code}`} />
            <span className="help">{t(gre && rev ? "add.rev.gre.runHelp" : gre ? "add.gre.runHelp" : rev ? "add.rev.runHelp" : "add.runHelp", { kind: kindLabel(gre?.kind) })}</span>
            <span className="label" style={{ marginTop: "var(--sp-3)" }}>
              {t("add.runInstalled")}
            </span>
            <CodeBlock text={`kariz-manager --agent ${code}`} />
            {(!gre || rev) && transport !== "auto" && <span className="help">{t("add.via", { t: t(`add.x.${transport}`) })}</span>}
            <span className="countdown">{joined ? "" : t("add.valid", { m: digitsOf(mmss) })}</span>
          </div>
          <div className={`waiting ${joined ? "done" : ""}`}>
            {!joined && (
              <svg className="qloader" viewBox="0 0 180 90" aria-hidden="true">
                <path className="bed" d="M30 58 L158 76" />
                <path className="flow" pathLength={1} d="M30 58 L158 76" />
                <path className="shaft" d="M38 26 V58 M84 26 V64 M130 26 V70" />
                <path className="ground" d="M8 26 H172" />
                <path className="mound" d="M30 26 a8 6 0 0 1 16 0Z M76 26 a8 6 0 0 1 16 0Z M122 26 a8 6 0 0 1 16 0Z" />
                <circle className="drop" cx="38" cy="26" r="4" />
                <path className="out" d="M164 68 L178 77 L164 86 Z" />
              </svg>
            )}
            <span>{joined ? t("add.connected", { name: joined.name }) : t("add.waiting")}</span>
          </div>
          {(gre || rev) && !joined && <p className="muted small">{t("add.gre.later")}</p>}
        </>
      )}
    </Dialog>
  );
}

export function ServersPage({ servers, loaded, agentsOn, onChanged }: { servers: ServerInfo[]; loaded: boolean; agentsOn: boolean; onChanged: () => void }) {
  const { t, num, toast, digitsOf } = useApp();
  const ago = useAgo();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<ServerInfo | null>(null);
  const [fixing, setFixing] = useState<string | null>(null);
  const [auto, setAuto] = useState<string | null>(null);
  // The order being arranged, while the page is in its Arrange mode.
  const [order, setOrder] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  // A saved order is shown until the next reading of the servers has it too.
  const [saved, setSaved] = useState<string[] | null>(null);
  const byId = new Map(servers.map((s) => [s.id, s]));
  const shown = saved ? arranged(saved, servers).map((id) => byId.get(id)!) : servers;
  useEffect(() => {
    if (saved && arranged(saved, servers).join() === servers.map((s) => s.id).join()) setSaved(null);
  }, [servers, saved]);
  const online = servers.filter((s) => s.online).length;
  const saveOrder = async () => {
    if (!order) return;
    const ids = arranged(order, servers);
    if (ids.join() === servers.map((s) => s.id).join()) {
      setOrder(null);
      return;
    }
    setSaving(true);
    try {
      await api.orderServers(ids);
      toast(t("arr.saved"), "ok");
      setSaved(ids);
      setOrder(null);
    } catch {
      toast(t("arr.failed"), "err");
    }
    setSaving(false);
    onChanged();
  };
  // Added, and its agent has never connected (one added over GRE waits here until its command is run).
  const waiting = (s: ServerInfo) => !s.local && !s.online && !s.last_seen;
  const uptime = (secs: number) => {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    return digitsOf(d > 0 ? t("srv.days", { d, h }) : t("srv.hours", { h: Math.max(0, h), m: Math.floor((secs % 3600) / 60) }));
  };
  return (
    <div className="page is-on">
      <div className="page-band">
        <div className="summary">
          <div>
            <b>{num(servers.length)}</b>
            <span>{t("m.serversNote")}</span>
          </div>
          <div>
            <b className={online < servers.length ? "warn-text" : "ok-text"}>{num(online)}</b>
            <span>{t("srv.online")}</span>
          </div>
        </div>
        <div className="grow" />
        {order ? (
          <>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setOrder(null)} disabled={saving}>
              {t("cancel")}
            </button>
            <button className="btn btn-primary btn-sm" type="button" onClick={saveOrder} disabled={saving}>
              <Icon name="check" size={18} />
              {t("arr.done")}
            </button>
          </>
        ) : (
          <>
            {loaded && servers.length > 1 && (
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => setOrder(servers.map((s) => s.id))}>
                <Icon name="arrange" size={18} />
                {t("arr.start")}
              </button>
            )}
            <button className="btn btn-primary btn-sm" type="button" onClick={() => setAdding(true)}>
              <span className="shine" />
              <Icon name="plus" size={18} />
              {t("srv.add")}
            </button>
          </>
        )}
      </div>
      {order && loaded ? (
        <ArrangeServers servers={servers} order={order} onOrder={setOrder} />
      ) : !loaded ? (
        <div className="srv-list">
          {[0, 1, 2].map((i) => (
            <div className="card" key={i}>
              <Skeleton rows={3} height={28} />
            </div>
          ))}
        </div>
      ) : (
        <ul className="srv-list">
          {shown.map((s) => {
            const h = s.health;
            const mem = h?.mem_total ? ((h.mem_used ?? 0) * 100) / h.mem_total : null;
            const rx = h?.rx_bps != null ? bytesPerSec(h.rx_bps) : null;
            const tx = h?.tx_bps != null ? bytesPerSec(h.tx_bps) : null;
            return (
              <li className={`srv card ${s.online ? "" : "is-off"}`} key={s.id}>
                <header className="srv-head">
                  <Well level={h?.cpu_pct != null ? Math.min(1, h.cpu_pct / 100 + 0.3) : 0.5} online={s.online} />
                  <div className="srv-id">
                    <div className="srv-name">
                      {s.name}
                      {s.local && <span className="badge">{t("srv.panelBadge")}</span>}
                    </div>
                    <div className="srv-sub">{s.version ? `${t("srv.version", { v: s.version })} · ${s.arch}` : t("srv.notYet")}</div>
                  </div>
                  <StatePill
                    state={s.online ? "up" : "down"}
                    label={s.online ? t("srv.online") : waiting(s) ? t("srv.waiting") : `${t("srv.offline")}${s.seen_secs != null ? ` · ${ago(s.seen_secs)}` : ""}`}
                  />
                </header>
                {!s.online && !s.local && (
                  <div className="srv-alert" role="status">
                    <p>
                      {waiting(s)
                        ? s.reverse
                          ? t("srv.alertWaitRev", { addr: `\u2066${hostPort(s.reverse.host, s.reverse.port)}\u2069` })
                          : t(s.gre ? "srv.alertWaitGre" : "srv.alertWait")
                        : s.last_error?.kind === "wrong_key"
                          ? t("srv.alertKey")
                          : t("srv.alertOff")}
                    </p>
                    <button className="btn btn-primary btn-sm" type="button" onClick={() => setFixing(s.id)}>
                      <Icon name="restart" size={16} />
                      {t(waiting(s) ? "srv.newCode" : "srv.reconnect")}
                    </button>
                  </div>
                )}
                {/* An offline server has no numbers to show: its card says when it was last seen and how to bring it back. */}
                {s.online && (
                  <>
                    <div className="srv-meters">
                      <Meter label={t("srv.cpu")} pct={h?.cpu_pct ?? null} />
                      <Meter label={t("srv.ram")} pct={mem} />
                    </div>
                    <dl className="srv-facts">
                      <div>
                        <dt>
                          {t("srv.net")}
                          {rx ? ` · ${rx.unit}` : ""}
                        </dt>
                        <dd className="num" dir="ltr">
                          {rx && tx ? (
                            <>
                              <span className="down-c">↓ {num(rx.value, rx.decimals)}</span> <span className="up-c">↑ {num(tx.value, tx.decimals)}</span>
                            </>
                          ) : (
                            "—"
                          )}
                        </dd>
                      </div>
                      <div>
                        <dt>{t("srv.uptime")}</dt>
                        <dd>{h?.uptime_secs != null ? uptime(h.uptime_secs) : "—"}</dd>
                      </div>
                      <div>
                        <dt>{t("srv.linkLabel")}</dt>
                        <dd className="mono">{s.local ? t("srv.localLink") : s.link ?? "—"}</dd>
                      </div>
                    </dl>
                  </>
                )}
                {s.reverse && (
                  <div className="srv-ips">
                    <span className="badge" title={t("srv.viaRev", { addr: hostPort(s.reverse.host, s.reverse.port) })}>
                      {t("srv.revChip", { addr: `\u2066${hostPort(s.reverse.host, s.reverse.port)}\u2069` })}
                    </span>
                  </div>
                )}
                {s.gre && (
                  <div className="srv-ips">
                    <span className="badge" title={t("srv.viaGre", { network: s.gre.network })}>
                      {t("srv.greChip", { kind: kindLabel(s.gre.kind), network: s.gre.network })}
                    </span>
                  </div>
                )}
                {s.agent_port && !s.reverse && (
                  <div className="srv-ips">
                    <span className="badge" title={t("srv.portTitle", { port: s.agent_port })}>
                      {t("srv.portChip", { port: s.agent_port })}
                    </span>
                  </div>
                )}
                {(s.ip4 || s.ip6) && (
                  <div className="srv-ips" dir="ltr">
                    {s.ip4 && <CopyValue what={t("srv.ip4")} label={t("srv.ip4")} value={s.ip4} />}
                    {s.ip6 && <CopyValue what={t("srv.ip6")} label={t("srv.ip6")} value={s.ip6} />}
                  </div>
                )}
                <footer className="srv-foot">
                  <span className={`badge ${s.tunnels.length ? "" : "muted"}`}>{t(s.tunnels.length === 1 ? "srv.tn1" : "srv.tn", { n: num(s.tunnels.length) })}</span>
                  {s.addr && s.addr !== s.ip4 && s.addr !== s.ip6 && <CopyValue what={t("srv.address")} value={s.addr} />}
                  <span className="grow" />
                  <button className="btn btn-quiet btn-sm" type="button" onClick={() => setAuto(s.id)}>
                    <Icon name="clock" size={16} />
                    {t("srv.auto")}
                  </button>
                  {!s.local && s.online && (
                    <button className="btn btn-quiet btn-sm" type="button" onClick={() => setFixing(s.id)}>
                      <Icon name="edit" size={16} />
                      {t("srv.edit")}
                    </button>
                  )}
                  {!s.local && (
                    <button className="btn btn-quiet btn-sm" type="button" onClick={() => setRemoving(s)}>
                      <Icon name="trash" size={16} />
                      {t("srv.remove")}
                    </button>
                  )}
                </footer>
              </li>
            );
          })}
          <li className="srv-add">
            <button type="button" onClick={() => setAdding(true)}>
              <span className="empty-icon" aria-hidden="true">
                <Icon name="plus" size={24} />
              </span>
              <b>{t("srv.add")}</b>
              <span>{t("srv.addHint")}</span>
            </button>
          </li>
        </ul>
      )}
      {adding && <AddServer servers={servers} agentsOn={agentsOn} onClose={() => setAdding(false)} />}
      {fixing && servers.find((s) => s.id === fixing) && (
        <ServerFixDialog server={servers.find((s) => s.id === fixing)!} servers={servers} agentsOn={agentsOn} onChanged={onChanged} onClose={() => setFixing(null)} />
      )}
      {auto && servers.find((s) => s.id === auto) && (
        <AutoRestartDialog server={auto} name={servers.find((s) => s.id === auto)!.name} offline={!servers.find((s) => s.id === auto)!.online} onClose={() => setAuto(null)} />
      )}
      {removing && (
        <Dialog
          title={t("srv.removeTitle", { name: removing.name })}
          onClose={() => setRemoving(null)}
          footer={
            <>
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => setRemoving(null)}>
                {t("cancel")}
              </button>
              <button
                className="btn btn-danger solid btn-sm"
                type="button"
                onClick={async () => {
                  const gone = removing;
                  setRemoving(null);
                  try {
                    await api.removeServer(gone.id);
                    toast(t("srv.removed", { name: gone.name }), "ok");
                  } catch {
                    toast(t("bak.failed"), "err");
                  }
                  onChanged();
                }}
              >
                {t("srv.remove")}
              </button>
            </>
          }
        >
          <p className="small" style={{ margin: 0 }}>
            {t("srv.removeText")}
          </p>
        </Dialog>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- settings

function strength(pw: string): number {
  let s = 0;
  if (pw.length >= 10) s++;
  if (pw.length >= 14) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw) && /[^\w]/.test(pw)) s++;
  return s;
}

function PasswordDialog({ hasPassword, onClose, onSaved }: { hasPassword: boolean; onClose: () => void; onSaved: () => void }) {
  const { t } = useApp();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const s = strength(next);
  const mismatch = again !== "" && again !== next;
  const ok = next.length >= 10 && next === again && (!hasPassword || current !== "");

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      await api.changePassword(hasPassword ? current : undefined, next);
      onSaved();
    } catch (e) {
      setBusy(false);
      if (e instanceof ApiError && e.code === "wrong") setError(t("set.pwWrong"));
      else if (e instanceof ApiError && e.code === "too_short") setError(t("set.pwShort"));
      else if (e instanceof ApiError && e.code === "locked") setError(t("login.locked", { m: Math.ceil(Number(e.body.retry_after ?? 900) / 60) }));
      else setError(t("login.error"));
    }
  };

  return (
    <Dialog
      title={hasPassword ? t("set.pwChange") : t("set.pwSetBtn")}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-ghost btn-sm" type="button" onClick={onClose}>
            {t("cancel")}
          </button>
          <button className="btn btn-primary btn-sm" type="button" disabled={!ok || busy} onClick={save}>
            {hasPassword ? t("set.pwChange") : t("set.pwSetBtn")}
          </button>
        </>
      }
    >
      {hasPassword && (
        <div className="field">
          <label htmlFor="pw0">{t("set.pwCur")}</label>
          <input className="text" id="pw0" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </div>
      )}
      <div className="field">
        <label htmlFor="pw1">{t("set.pwNew")}</label>
        <input className="text" id="pw1" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        <div className={`meter ${s < 2 && next ? "hot" : ""}`}>
          <div className="top">
            <span />
            <b>{next ? t(s < 2 ? "set.pwWeak" : s < 3 ? "set.pwOk" : "set.pwStrong") : ""}</b>
          </div>
          <div className="bar">
            <i style={{ width: `${(s / 4) * 100}%` }} />
          </div>
        </div>
      </div>
      <div className="field">
        <label htmlFor="pw2">{t("set.pwAgain")}</label>
        <input className="text" id="pw2" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
        <span className="err">{mismatch ? t("set.pwMismatch") : error}</span>
      </div>
    </Dialog>
  );
}

function LoginLink() {
  const { t, digitsOf } = useApp();
  const [url, setUrl] = useState("");
  const [left, setLeft] = useState(0);

  useEffect(() => {
    if (left <= 0) return;
    const id = setInterval(() => setLeft((v) => Math.max(0, v - 1)), 1000);
    return () => clearInterval(id);
  }, [left > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const make = async () => {
    const { token, valid_for } = await api.newLink();
    setUrl(`${location.origin}${location.pathname}#t=${token}`);
    setLeft(valid_for);
  };
  const mmss = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
  return (
    <>
      <button className="btn btn-ghost btn-sm" type="button" onClick={() => void make()}>
        <Icon name="key" size={18} />
        {t("set.linkMake")}
      </button>
      {url && (
        <div style={{ width: "100%" }}>
          <CodeBlock text={url} />
          <span className="countdown">{left > 0 ? t("set.linkValid", { m: digitsOf(mmss) }) : t("set.linkExpired")}</span>
        </div>
      )}
    </>
  );
}

/** "Edge · Windows" out of a User-Agent string. */
export function deviceName(ua: string): string {
  const browser =
    /Edg\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl/i.test(ua) ? "curl" : "";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Android/.test(ua)
      ? "Android"
      : /iPhone|iPad/.test(ua)
        ? "iOS"
        : /Mac OS X|Macintosh/.test(ua)
          ? "macOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return [browser, os].filter(Boolean).join(" · ") || ua.slice(0, 40) || "?";
}

function Sessions() {
  const { t, toast } = useApp();
  const ago = useAgo();
  const [rows, setRows] = useState<SessionRow[]>([]);
  const load = () => api.sessions().then((r) => setRows(r.sessions)).catch(() => {});
  useEffect(() => {
    void load();
  }, []);
  const now = Date.now() / 1000;
  return (
    <div style={{ width: "100%" }}>
      {rows.map((s) => (
        <div className="session" key={s.id}>
          <span className="who">
            {deviceName(s.agent)} {s.current && <span className="badge water">{t("set.thisDevice")}</span>}
          </span>
          {s.current ? (
            <span />
          ) : (
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              onClick={async () => {
                await api.revoke(s.id);
                toast(t("set.revoked"));
                void load();
              }}
            >
              {t("set.revoke")}
            </button>
          )}
          <span className="meta">
            <span className="mono" dir="ltr">
              {s.ip}
            </span>
            <Sep />
            {s.current ? t("now") : ago(now - s.last_seen)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function SettingsPage({ hasPassword, onPasswordSet, updates }: { hasPassword: boolean; onPasswordSet: () => void; updates?: React.ReactNode }) {
  const { t, lang, setLang, theme, setTheme, digits, setDigits, low, setLow, toast } = useApp();
  const [dialog, setDialog] = useState(false);
  const [backup, setBackup] = useState<"save" | "restore" | null>(null);
  const [at, setAt] = useState("sec");
  const row = (title: string, text: string, control: React.ReactNode) => (
    <div className="set-row">
      <div>
        <h3>{title}</h3>
        {text && <p>{text}</p>}
      </div>
      <div className="ctl">{control}</div>
    </div>
  );
  const sections: [string, string, string][] = [
    ["sec", t("set.sec"), "shield"],
    ["upd", t("set.updates"), "update"],
    ["tg", t("set.telegram"), "bell"],
    ["bak", t("set.backup"), "download"],
    ["look", t("set.look"), "palette"],
  ];

  // The section in view is the one lit in the list.
  useEffect(() => {
    const main = document.querySelector(".main");
    const els = sections.map(([id]) => document.getElementById(`set-${id}`)).filter((x): x is HTMLElement => !!x);
    const io = new IntersectionObserver(
      (entries) => {
        const seen = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (seen) setAt(seen.target.id.slice(4));
      },
      { root: main, rootMargin: "0px 0px -60% 0px" },
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [!!updates]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="page is-on settings">
      <nav className="settings-nav" aria-label={t("page.settings")}>
        {sections.map(([id, label, icon]) => (
          <button
            key={id}
            type="button"
            aria-current={at === id ? "true" : undefined}
            onClick={() => {
              setAt(id);
              document.getElementById(`set-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          >
            <Icon name={icon} size={18} />
            {label}
          </button>
        ))}
      </nav>
      <div className="settings-body">
        <Card title={t("set.sec")} id="set-sec" className="set-section">
          {row(
            t("set.pw"),
            t(hasPassword ? "set.pwSet" : "set.pwNone"),
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setDialog(true)}>
              <Icon name="key" size={18} />
              {t(hasPassword ? "set.pwChange" : "set.pwSetBtn")}
            </button>,
          )}
          {row(t("set.link"), t("set.linkText"), <LoginLink />)}
          {row(t("set.sessions"), t("set.sessionsText"), <Sessions />)}
        </Card>
        <div id="set-upd" className="set-section">
          {updates}
        </div>
        <div id="set-tg" className="set-section">
          <TelegramSection />
        </div>
        <Card title={t("set.backup")} id="set-bak" className="set-section">
          {row(
            t("set.backupSave"),
            t("set.backupSaveText"),
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setBackup("save")}>
              <Icon name="download" size={18} />
              {t("bak.download")}
            </button>,
          )}
          {row(
            t("set.backupRestore"),
            t("set.backupRestoreText"),
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setBackup("restore")}>
              <Icon name="upload" size={18} />
              {t("rst.go")}
            </button>,
          )}
        </Card>
        <Card title={t("set.look")} id="set-look" className="set-section">
          {row(t("set.lang"), "", <Seg value={lang} options={[["fa", "فارسی"], ["en", "English"]]} onChange={setLang} />)}
          {row(t("set.theme"), "", <Seg value={theme} options={[["night", t("set.night")], ["dawn", t("set.dawn")]]} onChange={setTheme} />)}
          {lang === "fa" && row(t("set.digits"), "", <Seg value={digits} options={[["fa", t("set.digitsFa")], ["latin", t("set.digitsLatin")]]} onChange={setDigits} />)}
          {row(t("set.motion"), t("set.motionText"), <Seg value={low ? "low" : "full"} options={[["full", t("set.motionFull")], ["low", t("set.motionLow")]]} onChange={(v) => setLow(v === "low", true)} />)}
        </Card>
      </div>
      {backup === "save" && <BackupDialog onClose={() => setBackup(null)} />}
      {backup === "restore" && <RestoreDialog onClose={() => setBackup(null)} onDone={() => {}} />}
      {dialog && (
        <PasswordDialog
          hasPassword={hasPassword}
          onClose={() => setDialog(false)}
          onSaved={() => {
            setDialog(false);
            onPasswordSet();
            toast(t("set.pwSaved"), "ok");
          }}
        />
      )}
    </div>
  );
}
