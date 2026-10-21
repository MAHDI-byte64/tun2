import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ApiError, api, isPrivatePath } from "./api";
import type { CheckReply, ForwardSpec, PairRequest, ServerInfo } from "./api";
import { useApp } from "./store";
import { Icon, Seg, useFocusTrap } from "./ui";
import { Checklist, opError, useOp } from "./ops";
import { useNetworks } from "./Networks";
import { GreChoice, linkBetween } from "./GreChoice";
import { MuxFields, MuxToggle, emptyMux, muxSpecOf, muxToSpec } from "./MuxFields";
import { TlsChoice, emptyTls, tlsReady } from "./TlsChoice";
import { EncryptionChoice, cipherOf, cipherReady } from "./EncryptionChoice";
import { QuicObfs, obfsOf } from "./QuicObfs";
import { PerIpLimit, perIpOf } from "./PerIpLimit";
import { UdpFlows, udpFlowsOf } from "./UdpFlows";
import { ProxyProtocol, proxyOf } from "./ProxyProtocol";
import type { ProxyChoice } from "./ProxyProtocol";
import { BenchPanel, benchLabel, isV6 } from "./Benchmark";
import type { BenchChoice } from "./Benchmark";
import { MUX_OPTIONAL, ROOT_ONLY, SPLIT_TRANSPORTS, SPOOF_SHAPES, TRANSPORTS, joinTransport, transportLabel } from "./transport";
import {
  FaketcpOptions,
  HelperFields,
  AsymmetricPicker,
  IcmpOptions,
  L3Options,
  RootWarning,
  SpoofOptions,
  StealthOptions,
  emptyFaketcp,
  emptyHelper,
  emptyIcmp,
  emptyL3,
  emptySpoof,
  emptyStealth,
  faketcpOf,
  helperOf,
  icmpOf,
  l3Of,
  parseSpoofPool,
  spoofOf,
  stealthOf,
} from "./TransportOptions";
import { FIRST_TUNNEL_PORT, freeTunnelPort, hostOf, portOf, portsInUse } from "./ports";

export const PROFILES = ["balanced", "ultraspeed", "gaming"] as const;
const NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** A tunnel name made from the names of its two servers ("tehran-1" and "fra" give "tehran-1-fra"), or "" when nothing usable is left. */
export function suggestName(entry: string, exit: string): string {
  const part = (x: string) => x.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return [part(entry), part(exit)].filter(Boolean).join("-").slice(0, 32).replace(/-+$/, "");
}

/** "443, 8080-8090, 2053=53" as forwards; the piece that is wrong if one is. */
export function parsePorts(text: string, protocol: string, host: string): { forwards: ForwardSpec[]; bad?: string } {
  const forwards: ForwardSpec[] = [];
  const port = (s: string) => (/^\d{1,5}$/.test(s) && +s >= 1 && +s <= 65535 ? +s : null);
  for (const raw of text.split(",")) {
    const bit = raw.trim();
    if (!bit) continue;
    const [left, right] = bit.split("=").map((x) => x.trim());
    const range = left.match(/^(\d+)-(\d+)$/);
    if (range) {
      const a = port(range[1]);
      const b = port(range[2]);
      if (a === null || b === null || b < a || right !== undefined || forwards.length + (b - a + 1) > 200) return { forwards, bad: bit };
      for (let p = a; p <= b; p++) forwards.push({ listen: `0.0.0.0:${p}`, target: `${host}:${p}`, protocol });
      continue;
    }
    const l = port(left);
    const r = right === undefined ? l : port(right);
    if (l === null || r === null) return { forwards, bad: bit };
    forwards.push({ listen: `0.0.0.0:${l}`, target: `${host}:${r}`, protocol });
  }
  if (forwards.length === 0) return { forwards, bad: "" };
  return { forwards };
}

/** The addresses a server can be dialed at, best first: the one set for it, the panel's own host name (for the panel's server), its public IPv4, its IPv6. */
export function addressesOf(s: ServerInfo): string[] {
  const out: string[] = [];
  const add = (a?: string | null) => {
    if (a && !out.includes(a)) out.push(a);
  };
  add(s.addr);
  if (s.local && !/^(localhost|127\.|\[?::1\]?$)/.test(location.hostname)) add(location.hostname.replace(/^\[|\]$/g, ""));
  add(s.ip4);
  add(s.ip6);
  return out;
}

export { hostOf, portOf };

export function Wizard({ servers, onClose }: { servers: ServerInfo[]; onClose: () => void }) {
  const { t, num, lang, toast } = useApp();
  const online = servers.filter((s) => s.online);
  const [on, setOn] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useFocusTrap(box);
  const [step, setStep] = useState(0);
  const [back, setBack] = useState(false);
  const [name, setName] = useState("");
  // The name follows the two servers picked (tehran-frankfurt) until one is typed.
  const [nameTouched, setNameTouched] = useState(false);
  // Which field the error of the first step is about, to show it there.
  const [errAt, setErrAt] = useState<"name" | "servers" | null>(null);
  const [entry, setEntry] = useState("");
  const [exit, setExit] = useState("");
  const [mode, setMode] = useState("reverse");
  const [transport, setTransport] = useState<string>("tcp");
  // Source spoofing is a third "connection kind" beside reverse/direct: when on, the tunnel
  // transport is `spoof` and the tiles below pick its on-wire shape.
  const [spoof, setSpoof] = useState(false);
  const [spoofShape, setSpoofShape] = useState<string>("udp");
  const [spoofS, setSpoofS] = useState(emptySpoof());
  // Asymmetric transport: a different transport (or spoof shape) each way. `transport` /
  // `spoofShape` are then the send (entry→exit) half, and these are the receive (exit→entry) one.
  const [asym, setAsym] = useState(false);
  const [recvTransport, setRecvTransport] = useState<string>("tcp");
  const [spoofRecvShape, setSpoofRecvShape] = useState<string>("tcp");
  const [muxOn, setMuxOn] = useState(true);
  const [profile, setProfile] = useState<string>("balanced");
  const [listenPort, setListenPort] = useState(String(FIRST_TUNNEL_PORT));
  // Until a port is typed, the wizard picks a free one.
  const [portTouched, setPortTouched] = useState(false);
  const [dialHost, setDialHost] = useState("");
  // The host the accepting side listens on: every IPv4 address, every address (IPv6 too) when it is dialed at
  // its IPv6 address, or (for a tunnel that was made over a private network) its private one.
  const listenHost = isV6(dialHost) ? "[::]" : "0.0.0.0";
  const [netId, setNetId] = useState("");
  const { networks, links } = useNetworks();
  const [wsPath, setWsPath] = useState("/");
  const [wsHost, setWsHost] = useState("");
  const [sni, setSni] = useState("");
  const [mux, setMux] = useState(emptyMux());
  const [tls, setTls] = useState(emptyTls());
  const [enc, setEnc] = useState<string>("auto");
  const [encAck, setEncAck] = useState(false);
  // Sealed QUIC (obfs) is on unless it is turned off: it is what makes QUIC work where it is filtered.
  const [obfs, setObfs] = useState(true);
  const [stealthS, setStealthS] = useState(emptyStealth());
  const [faketcpS, setFaketcpS] = useState(emptyFaketcp());
  const [icmpS, setIcmpS] = useState(emptyIcmp());
  const [helperS, setHelperS] = useState(emptyHelper());
  const [l3S, setL3S] = useState(emptyL3());
  // Once the address to dial is typed (or loaded from the tunnel), it is not guessed again.
  const [dialTouched, setDialTouched] = useState(false);
  const [ports, setPorts] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [target, setTarget] = useState("127.0.0.1");
  const [perIp, setPerIp] = useState("");
  const [udpFlows, setUdpFlows] = useState("");
  const [proxy, setProxy] = useState<ProxyChoice>("off");
  const [pool, setPool] = useState<number | undefined>();
  const [check, setCheck] = useState<{ entry: CheckReply; exit: CheckReply } | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [opId, setOpId] = useState<string | null>(null);
  const op = useOp(opId);

  useEffect(() => {
    const id = requestAnimationFrame(() => setOn(true));
    return () => cancelAnimationFrame(id);
  }, []);

  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? id;
  const takenNames = useMemo(() => new Set(servers.flatMap((s) => s.tunnels.map((x) => x.name))), [servers]);
  useEffect(() => {
    if (nameTouched || !entry || !exit) return;
    const guess = suggestName(serverName(entry), serverName(exit));
    if (NAME.test(guess)) setName(guess);
  }, [entry, exit, nameTouched]); // eslint-disable-line react-hooks/exhaustive-deps
  // An error about the servers goes once both are picked.
  useEffect(() => {
    if (errAt === "servers" && entry && exit && entry !== exit) {
      setErrAt(null);
      setError("");
    }
  }, [entry, exit]); // eslint-disable-line react-hooks/exhaustive-deps

  // A benchmark result chosen: its direction, transport (with mux, as the benchmark measured it), the private
  // network of a GRE path, and the IPv6 address of an IPv6 path (or back to the IPv4 one from an IPv6 address).
  const applyBench = (c: BenchChoice) => {
    setMode(c.mode);
    setSpoof(false);
    setAsym(false);
    setTransport(c.transport === "tcpmux" ? "tcp" : c.transport);
    setMuxOn(true);
    setNetId(c.network ?? "");
    if (c.host && (c.path === "ipv6" || isV6(dialHost))) {
      setDialHost(c.host);
      setDialTouched(true);
    }
    if (c.sni) setSni(c.sni);
    toast(t("bench.applied", { t: benchLabel(c.transport), mode: t(`bench.mode.${c.mode}`) }), "ok");
  };
  const acceptor = mode === "reverse" ? entry : exit;
  const dialer = mode === "reverse" ? exit : entry;
  const parsed = useMemo(() => parsePorts(ports, protocol, target.trim() || "127.0.0.1"), [ports, protocol, target]);
  const greLink = netId ? linkBetween(links, netId, entry, exit) : undefined;
  // The tunnel listens on the private address of the server that accepts it, in either mode.
  const greAddr = greLink ? (greLink.a === acceptor ? greLink.addr_a : greLink.addr_b) : "";
  // The transport the backend sees: `spoof` when the spoofing kind is on, else the picked one.
  const tp = spoof ? "spoof" : transport;
  const udp = !spoof && (transport === "quic" || transport === "kcp" || transport === "udp");
  // Either direction being a WebSocket transport needs the ws path; either being wss needs TLS.
  const wsName = (x: string) => x === "ws" || x === "wss" || x === "wsmux" || x === "wssmux";
  const splittable = (x: string) => (SPLIT_TRANSPORTS as readonly string[]).includes(x);
  const isWs = !spoof && (wsName(transport) || (asym && wsName(recvTransport)));
  const usesWss = !spoof && (transport === "wss" || (asym && recvTransport === "wss"));
  const isL3 = !spoof && transport === "l3";
  const rootOnly = ROOT_ONLY.includes(tp) || (isL3 && ["faketcp", "icmp", "proto47"].includes(l3S.carrier));

  // The accepting server's address, as the other one reaches it. A new tunnel starts from
  // the best guess (the address set for it, else the one the panel sees) until one is typed.
  const acceptorServer = servers.find((s) => s.id === acceptor);
  const addrChoices = acceptorServer ? addressesOf(acceptorServer) : [];
  useEffect(() => {
    if (dialTouched || !acceptorServer) return;
    const guess = addrChoices[0];
    if (guess) setDialHost(guess);
  }, [acceptor, servers]); // eslint-disable-line react-hooks/exhaustive-deps

  // The port a new tunnel listens on starts at 3080 and moves up past the ports the accepting
  // server's other tunnels hold: 3080, then 3081, then 3082. It follows the choice of server
  // and transport (auto needs one more port), and stops once a port is typed.
  const takenPorts = useMemo(() => portsInUse(acceptorServer), [acceptorServer]);
  const suggestedPort = String(freeTunnelPort(takenPorts, transport));
  useEffect(() => {
    if (!portTouched) setListenPort(suggestedPort);
  }, [portTouched, suggestedPort]);

  const request = (): PairRequest => ({
    name,
    entry,
    exit,
    mode,
    // Asymmetric sends the base transport (tcp/ws/wss) and muxes over the combined stream;
    // a symmetric tcp tunnel still folds mux into the `tcpmux` name.
    transport: spoof ? "spoof" : asym ? transport : joinTransport(transport, muxOn).core,
    recv_transport: asym && !spoof ? recvTransport : undefined,
    profile,
    listen: `${listenHost}:${listenPort}`,
    dial: `${dialHost.includes(":") && !dialHost.startsWith("[") ? `[${dialHost}]` : dialHost}:${listenPort}`,
    network: netId || undefined,
    pool,
    ws_path: isWs ? wsPath : undefined,
    ws_host: isWs && wsHost.trim() ? wsHost.trim() : undefined,
    // A server name typed for a self-signed certificate is not sent with a real one: the
    // other side checks a real one against the name it was issued for (tls_host).
    tls_sni: usesWss && tls.mode === "self" && sni.trim() ? sni.trim() : undefined,
    // Asymmetric rides one combined connection, so it always muxes over it.
    mux: muxSpecOf(mux, tp, asym ? true : muxOn),
    encryption: cipherOf(enc, tp),
    quic_obfs: obfsOf(obfs, transport),
    max_conns_per_ip: perIpOf(perIp).value,
    udp_max_flows: protocol.includes("udp") ? udpFlowsOf(udpFlows).value : undefined,
    proxy_protocol: proxyOf(proxy, protocol),
    tls_cert: usesWss && tls.mode === "real" && tls.cert ? tls.cert : undefined,
    tls_key: usesWss && tls.mode === "real" && tls.key ? tls.key : undefined,
    tls_host: usesWss && tls.mode === "real" && tls.cert && tls.host ? tls.host : undefined,
    stealth: stealthOf(stealthS, transport),
    faketcp: faketcpOf(faketcpS, transport),
    icmp: icmpOf(icmpS, transport),
    spoof: spoofOf(spoofS, spoofShape, spoof, asym ? spoofRecvShape : undefined),
    helper: helperOf(helperS, transport),
    ...l3Of(l3S, transport),
    forwards: parsed.forwards,
  });

  const problem = (s: number): string => {
    if (s === 0) {
      if (!entry || !exit) return t("wz.pickBoth");
      if (entry === exit) return t("wz.samePick");
      if (!name) return t("wz.nameEmpty");
      if (!NAME.test(name)) return t("wz.nameBad");
      if (takenNames.has(name)) return t("wz.nameTaken");
    }
    if (s === 2) {
      if (!/^\d{1,5}$/.test(listenPort) || +listenPort < 1 || +listenPort > 65535) return t("wz.port", { server: serverName(acceptor) });
      if (!dialHost.trim() && !netId) return t("wz.dial", { server: serverName(acceptor), other: serverName(dialer) });
      if (isWs && !wsPath.startsWith("/")) return t("wz.wsPath");
      if (transport === "wss" && !tlsReady(tls)) return t("tls.needCert");
    }
    if (s === 1 && spoof && (parseSpoofPool(spoofS.entryPool).length === 0 || parseSpoofPool(spoofS.exitPool).length === 0))
      return t("spf.poolNeeded");
    // Asymmetric: the two directions must differ, else it is just a normal symmetric tunnel.
    if (s === 1 && asym && !spoof && recvTransport === transport) return t("asym.needDiffer");
    if (s === 1 && asym && spoof && spoofRecvShape === spoofShape) return t("asym.needDiffer");
    if (s === 1 && !cipherReady(enc, tp, encAck)) return t("enc.needAck");
    if (s === 1 && muxToSpec(mux).bad) return t(`mux.${muxToSpec(mux).bad}`) + ": " + t("mux.badValue");
    if (s === 3 && parsed.bad !== undefined) return parsed.bad ? t("wz.badPorts", { bit: parsed.bad }) : t("wz.ports");
    if (s === 3 && perIpOf(perIp).bad) return t("perip.bad");
    if (s === 3 && protocol.includes("udp") && udpFlowsOf(udpFlows).bad) return t("udpflows.bad");
    return "";
  };

  const go = async (to: number) => {
    setError("");
    setErrAt(null);
    if (to > step) {
      const p = problem(step);
      if (p) {
        if (step === 0) {
          const at = !entry || !exit || entry === exit ? "servers" : "name";
          setErrAt(at);
          if (at === "name") document.getElementById("wz-name")?.focus();
        }
        return setError(p);
      }
    }
    setBack(to < step);
    setStep(to);
    if (to === 4 && !opId) {
      setChecking(true);
      setCheck(null);
      try {
        setCheck(await api.tunnelCheck(request()));
      } catch (e) {
        setError(e instanceof ApiError ? opError(t, e.code, new Map(servers.map((x) => [x.id, x.name]))) : String(e));
      } finally {
        setChecking(false);
      }
    }
  };

  const conflict = (c: CheckReply | undefined, id: string) => {
    if (!c || c.ok) return "";
    const first = c.conflicts[0];
    return first ? t("wz.taken", { server: serverName(id), who: first.process ?? `port ${first.port}` }) : (c.error ?? "");
  };
  const conflicts = [conflict(check?.entry, entry), conflict(check?.exit, exit)].filter(Boolean);

  const build = async () => {
    setError("");
    try {
      const r = await api.createTunnel(request());
      setOpId(r.op);
    } catch (e) {
      setError(e instanceof ApiError && e.code === "busy" ? t("wz.busy") : e instanceof ApiError ? opError(t, e.code, new Map(servers.map((x) => [x.id, x.name]))) : String(e));
    }
  };

  const running = !!opId && (!op || op.state === "running");
  const labels = [t("wz.s1"), t("wz.s2"), t("wz.s3"), t("wz.s4"), t("wz.s5")];
  const dir = lang === "fa" ? -1 : 1;

  return createPortal(
    <div ref={box} className={`wizard ${on ? "is-on" : ""}`} role="dialog" aria-modal="true" aria-label={t("wz.titleNew")}>
      <div className="wz-top">
        <h2>{t("wz.titleNew")}</h2>
        <button className="x-btn" type="button" onClick={onClose} disabled={running} aria-label={t("close")}>
          <Icon name="x" />
        </button>
      </div>
      <nav className="wz-steps" aria-label={t("tun.new")}>
        <div className="wz-channel" />
        <div className="wz-flow">
          <i style={{ width: `${(step / 4) * 100}%` }} />
        </div>
        <ol>
          {labels.map((label, i) => (
            <li key={label} className={i < step ? "done" : i === step ? "now" : ""} aria-current={i === step ? "step" : undefined} onClick={() => i < step && !running && !opId && void go(i)}>
              <span className="mound" />
              <span className="lbl">{label}</span>
            </li>
          ))}
        </ol>
      </nav>

      <div className="wz-body">
        <div className="wz-inner">
          <div className={`wz-step ${back ? "back" : ""}`} key={step} style={{ ["--dir" as string]: dir }}>
            
            {step === 0 && (
              <>
                <h3 className="wz-q">{t("wz.q1")}</h3>
                <p className="wz-lead">{t("wz.lead1")}</p>
                <div className="field" style={{ marginBottom: "var(--sp-5)", maxWidth: 360 }}>
                  <label htmlFor="wz-name">{t("wz.name")}</label>
                  <input
                    className="text mono"
                    id="wz-name"
                    dir="ltr"
                    value={name}
                    placeholder="tehran-frankfurt"
                    aria-invalid={errAt === "name"}
                    aria-describedby={errAt === "name" ? "wz-err" : "wz-name-help"}
                    onChange={(e) => {
                      setNameTouched(e.target.value !== "");
                      setName(e.target.value.toLowerCase());
                      if (errAt === "name") setErrAt(null);
                    }}
                  />
                  <span className="help" id="wz-name-help">
                    {t(nameTouched || !name ? "wz.nameHelp" : "wz.nameAuto")}
                  </span>
                  {errAt === "name" && (
                    <span className="err" id="wz-err" role="alert">
                      {error}
                    </span>
                  )}
                </div>
                <div className="pair">
                  <Picker label={t("wz.entry")} servers={servers} value={entry} other={exit} locked={false} onPick={setEntry} />
                  <div className="pair-mid">
                    <svg viewBox="0 0 90 36" aria-hidden="true">
                      <path d="M4 18 H80" stroke="var(--water)" strokeWidth="2" strokeDasharray="4 6" fill="none" />
                      <path d="M74 10 L86 18 L74 26" stroke="var(--water)" strokeWidth="2" fill="none" />
                    </svg>
                  </div>
                  <Picker label={t("wz.exit")} servers={servers} value={exit} other={entry} locked={false} onPick={setExit} />
                </div>
                {online.length < 2 && <p className="err small">{t("tun.needTwo")}</p>}
                {errAt === "servers" && (
                  <p className="err small" role="alert">
                    {error}
                  </p>
                )}
              </>
            )}

            {step === 1 && (
              <>
                <h3 className="wz-q">{t("wz.q2")}</h3>
                <p className="wz-lead">{t("wz.lead2")}</p>
                <div className="wz-bench">
                  <BenchPanel
                    entry={entry}
                    exit={exit}
                    profile={profile}
                    port={+suggestedPort || 0}
                    servers={servers}
                    applyLabel={t("bench.useWizard")}
                    currentLabel={t("bench.chosenWizard")}
                    context="wizard"
                    sni={sni}
                    isCurrent={(c) =>
                      c.transport === joinTransport(transport, muxOn).core &&
                      c.mode === mode &&
                      (isPrivatePath(c.path) ? c.network === netId : !netId) &&
                      (c.path === "ipv6") === (!netId && isV6(dialHost)) &&
                      !c.sni === !(transport === "wss" && sni)
                    }
                    onApply={applyBench}
                  />
                </div>
                <div className="tiles" role="radiogroup" aria-label={t("wz.q2")}>
                  {(["reverse", "direct"] as const).map((m) => (
                    <button
                      key={m}
                      type="button"
                      role="radio"
                      aria-checked={!spoof && mode === m}
                      className="tile"
                      onClick={() => {
                        setSpoof(false);
                        setMode(m);
                      }}
                    >
                      <span className="t1">{t(`wz.mode.${m}`)}</span>
                      <span className="t2">{t(`wz.mode.${m}.d`)}</span>
                      <span className="tick">
                        <Icon name="check" size={14} />
                      </span>
                    </button>
                  ))}
                  <button key="spoof" type="button" role="radio" aria-checked={spoof} className="tile" onClick={() => setSpoof(true)}>
                    <span className="t1">{t("wz.mode.spoof")}</span>
                    <span className="t2">{t("wz.mode.spoof.d")}</span>
                    <span className="tick">
                      <Icon name="check" size={14} />
                    </span>
                  </button>
                </div>
                <div className="wz-trhead">
                  <h3 className="wz-q" style={{ margin: 0, fontSize: "var(--fs-lg)" }}>
                    {asym ? t("asym.pick") : spoof ? t("wz.spoofShape") : t("wz.transport")}
                  </h3>
                  <label className="check asym-toggle">
                    <button
                      type="button"
                      role="switch"
                      className="switch"
                      aria-checked={asym}
                      aria-label={t("asym.toggle")}
                      onClick={() => {
                        const on = !asym;
                        setAsym(on);
                        if (on) {
                          setMuxOn(true);
                          if (!spoof) {
                            const send = splittable(transport) ? transport : "ws";
                            setTransport(send);
                            setRecvTransport(send === "tcp" ? "ws" : "tcp");
                          } else if (spoofRecvShape === spoofShape) {
                            setSpoofRecvShape(spoofShape === "tcp" ? "udp" : "tcp");
                          }
                        }
                      }}
                    />
                    {t("asym.toggle")}
                  </label>
                </div>
                <p className="help" style={{ margin: "0 0 var(--sp-3)" }}>
                  {t("asym.hint")}
                </p>
                {asym ? (
                  <AsymmetricPicker
                    options={spoof ? SPOOF_SHAPES : SPLIT_TRANSPORTS}
                    send={spoof ? spoofShape : transport}
                    recv={spoof ? spoofRecvShape : recvTransport}
                    onSend={spoof ? setSpoofShape : setTransport}
                    onRecv={spoof ? setSpoofRecvShape : setRecvTransport}
                    entryName={serverName(entry)}
                    exitName={serverName(exit)}
                    labelFor={(x) => t(spoof ? `wz.shape.${x}` : `wz.tr.${x}`)}
                  />
                ) : (
                  <div className="tiles" role="radiogroup" aria-label={spoof ? t("wz.spoofShape") : t("wz.transport")}>
                    {spoof
                      ? SPOOF_SHAPES.map((x) => (
                          <button key={x} type="button" role="radio" aria-checked={spoofShape === x} className="tile" onClick={() => setSpoofShape(x)}>
                            <span className="t1 mono">{x}</span>
                            <span className="t2">{t(`wz.shape.${x}`)}</span>
                            <span className="tick">
                              <Icon name="check" size={14} />
                            </span>
                          </button>
                        ))
                      : TRANSPORTS.map((x) => (
                          <button key={x} type="button" role="radio" aria-checked={transport === x} className="tile" onClick={() => setTransport(x)}>
                            <span className="t1 mono">{x}</span>
                            <span className="t2">{t(`wz.tr.${x}`)}</span>
                            <span className="tick">
                              <Icon name="check" size={14} />
                            </span>
                          </button>
                        ))}
                  </div>
                )}
                <h3 className="wz-q" style={{ marginTop: "var(--sp-6)", fontSize: "var(--fs-lg)" }}>
                  {t("wz.profile")}
                </h3>
                <div className="tiles" role="radiogroup" aria-label={t("wz.profile")}>
                  {PROFILES.map((p) => (
                    <button key={p} type="button" role="radio" aria-checked={profile === p} className="tile" onClick={() => setProfile(p)}>
                      <span className="t1">{t(`wz.pf.${p}`)}</span>
                      <span className="t2">{t(`wz.pf.${p}.d`)}</span>
                      <span className="tick">
                        <Icon name="check" size={14} />
                      </span>
                    </button>
                  ))}
                </div>
                <div style={{ marginTop: "var(--sp-6)" }}>
                  <EncryptionChoice value={enc} onChange={setEnc} transport={tp} ack={encAck} onAck={setEncAck} />
                </div>
                {!spoof && transport === "quic" && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <QuicObfs value={obfs} onChange={setObfs} />
                  </div>
                )}
                {rootOnly && <RootWarning />}
                {spoof && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <SpoofOptions value={spoofS} onChange={setSpoofS} entryName={serverName(entry)} exitName={serverName(exit)} />
                  </div>
                )}
                {!spoof && transport === "stealth" && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <StealthOptions value={stealthS} onChange={setStealthS} />
                  </div>
                )}
                {!spoof && transport === "faketcp" && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <FaketcpOptions value={faketcpS} onChange={setFaketcpS} />
                  </div>
                )}
                {!spoof && transport === "icmp" && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <IcmpOptions value={icmpS} onChange={setIcmpS} />
                  </div>
                )}
                {!spoof && ["naive", "xhttp", "reality"].includes(transport) && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <HelperFields transport={transport} value={helperS} onChange={setHelperS} />
                  </div>
                )}
                {isL3 && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <L3Options value={l3S} onChange={setL3S} />
                  </div>
                )}
                {!isL3 && (
                  <div style={{ marginTop: "var(--sp-5)" }}>
                    <MuxToggle transport={tp} value={muxOn} onChange={setMuxOn} />
                  </div>
                )}
                {!isL3 && (muxOn || !MUX_OPTIONAL.includes(tp)) && (
                  <details className="adv">
                    <summary>{t("mux.title")}</summary>
                    <MuxFields value={mux} onChange={setMux} profile={profile} transport={tp} />
                  </details>
                )}
              </>
            )}

            {step === 2 && (
              <>
                <h3 className="wz-q">{t("wz.q3")}</h3>
                <p className="wz-lead">{t("wz.lead3", { acceptor: serverName(acceptor), dialer: serverName(dialer) })}</p>
                <GreChoice value={netId} onChange={setNetId} networks={networks} links={links} entry={entry} exit={exit} acceptor={acceptor} port={listenPort} serverName={serverName} />
                <div className="grid-2" style={{ display: "grid", gap: "var(--sp-5)", gridTemplateColumns: "1fr 1fr" }}>
                  <div className="field">
                    <label htmlFor="wz-port">{t("wz.port", { server: serverName(acceptor) })}</label>
                    <input
                      className="text mono"
                      id="wz-port"
                      dir="ltr"
                      inputMode="numeric"
                      value={listenPort}
                      onChange={(e) => {
                        setPortTouched(true);
                        setListenPort(e.target.value.trim());
                      }}
                    />
                    {!portTouched && suggestedPort !== String(FIRST_TUNNEL_PORT) && (
                      <span className="help">{t("wz.portMoved", { first: String(FIRST_TUNNEL_PORT), server: serverName(acceptor), port: suggestedPort })}</span>
                    )}
                  </div>
                  <div className="field" hidden={!!netId}>
                    <label htmlFor="wz-dial">{t("wz.dial", { server: serverName(acceptor), other: serverName(dialer) })}</label>
                    <input
                      className="text mono"
                      id="wz-dial"
                      dir="ltr"
                      value={dialHost}
                      placeholder="203.0.113.5"
                      onChange={(e) => {
                        setDialTouched(true);
                        setDialHost(e.target.value.trim());
                      }}
                    />
                    <span className="help">{t("wz.dialHelp")}</span>
                    {addrChoices.length > 0 && (
                      <span className="addr-chips" aria-label={t("wz.dialSeen", { server: serverName(acceptor) })}>
                        {addrChoices.map((a) => (
                          <button
                            key={a}
                            type="button"
                            className={`pchip as-btn ${a === dialHost ? "on" : ""}`}
                            dir="ltr"
                            onClick={() => {
                              setDialTouched(true);
                              setDialHost(a);
                            }}
                          >
                            {a}
                          </button>
                        ))}
                      </span>
                    )}
                    {mode === "direct" && <span className="help">{t("wz.directHelp", { server: serverName(acceptor), port: listenPort })}</span>}
                  </div>
                  {isWs && (
                    <div className="field">
                      <label htmlFor="wz-ws">{t("wz.wsPath")}</label>
                      <input className="text mono" id="wz-ws" dir="ltr" value={wsPath} onChange={(e) => setWsPath(e.target.value.trim())} />
                    </div>
                  )}
                  {isWs && (
                    <div className="field">
                      <label htmlFor="wz-wshost">{t("wz.wsHost")}</label>
                      <input className="text mono" id="wz-wshost" dir="ltr" value={wsHost} placeholder="cdn.example.com" onChange={(e) => setWsHost(e.target.value.trim())} />
                      <span className="help">{t("wz.wsHostHelp")}</span>
                    </div>
                  )}
                  {transport === "wss" && (
                    <div style={{ gridColumn: "1 / -1" }}>
                      <TlsChoice
                        value={tls}
                        onChange={setTls}
                        server={acceptor}
                        serverName={serverName(acceptor)}
                        onHost={(h) => {
                          setDialTouched(true);
                          setDialHost(h);
                        }}
                      />
                    </div>
                  )}
                  {transport === "wss" && tls.mode === "self" && (
                    <div className="field">
                      <label htmlFor="wz-sni">{t("wz.sni")}</label>
                      <input className="text mono" id="wz-sni" dir="ltr" value={sni} placeholder="www.example.com" onChange={(e) => setSni(e.target.value.trim())} />
                      <span className="help">{t("wz.sniHelp")}</span>
                    </div>
                  )}
                  {transport === "tcp" && !muxOn && (
                    <div className="field">
                      <label htmlFor="wz-pool">{t("wz.pool")}</label>
                      <input
                        className="text mono"
                        id="wz-pool"
                        dir="ltr"
                        inputMode="numeric"
                        value={pool ?? ""}
                        placeholder="8"
                        onChange={(e) => setPool(/^\d{1,3}$/.test(e.target.value.trim()) ? +e.target.value.trim() : undefined)}
                      />
                      <span className="help">{t("wz.poolHelp")}</span>
                    </div>
                  )}
                </div>
                {udp && <p className="muted small">UDP</p>}
                {transport === "auto" && <p className="muted small">{t("wz.autoPorts", { server: serverName(acceptor), tcp: listenPort, udp: listenPort, ws: String(+listenPort + 1) })}</p>}
              </>
            )}

            {step === 3 && (
              <>
                <h3 className="wz-q">{t("wz.q4")}</h3>
                <p className="wz-lead">{t("wz.lead4")}</p>
                <div className="field" style={{ maxWidth: 520 }}>
                  <label htmlFor="wz-ports">{t("wz.ports")}</label>
                  <input className="text mono" id="wz-ports" dir="ltr" value={ports} placeholder="443, 8080-8090" onChange={(e) => setPorts(e.target.value)} />
                  <span className="help">{t("wz.portsHelp")}</span>
                </div>
                <div className="port-chips" style={{ margin: "var(--sp-4) 0" }} aria-live="polite">
                  {parsed.forwards.slice(0, 40).map((f) => (
                    <span className="pchip" key={f.listen + f.target}>
                      {f.listen.split(":").pop()}
                      <small>→ {f.target.split(":").pop()}</small>
                    </span>
                  ))}
                  {parsed.forwards.length > 40 && <span className="pchip">+{num(parsed.forwards.length - 40)}</span>}
                  {parsed.bad && <span className="pchip bad">{parsed.bad}</span>}
                </div>
                <div className="grid-2" style={{ display: "grid", gap: "var(--sp-5)", gridTemplateColumns: "1fr 1fr", maxWidth: 520 }}>
                  <div className="field">
                    <span className="label">{t("wz.protocol")}</span>
                    <Seg value={protocol} options={[["tcp", "TCP"], ["udp", "UDP"], ["tcp+udp", "TCP+UDP"]]} onChange={setProtocol} />
                  </div>
                  <div className="field">
                    <label htmlFor="wz-target">{t("wz.targetHost")}</label>
                    <input className="text mono" id="wz-target" dir="ltr" value={target} onChange={(e) => setTarget(e.target.value.trim())} />
                  </div>
                </div>
                <div style={{ maxWidth: 520 }}>
                  <PerIpLimit id="wz-perip" value={perIp} onChange={setPerIp} />
                  <UdpFlows id="wz-udpflows" value={udpFlows} onChange={setUdpFlows} protocol={protocol} />
                  <ProxyProtocol value={proxy} onChange={setProxy} protocol={protocol} />
                </div>
              </>
            )}

            {step === 4 && (
              <>
                <h3 className="wz-q">{opId ? name : t("wz.q5")}</h3>
                {!opId && <p className="wz-lead">{t("wz.lead5")}</p>}
                {!opId && (
                  <div className="review">
                    {(["entry", "exit"] as const).map((side) => {
                      const id = side === "entry" ? entry : exit;
                      const accepts = id === acceptor;
                      return (
                        <div className="review-card" key={side}>
                          <h4>
                            {t(`wz.review.${side}`)} · {serverName(id)}
                          </h4>
                          <dl className="kv">
                            <dt>{t("wz.transport")}</dt>
                            <dd className="mono">
                              {transportLabel(joinTransport(transport, muxOn).core)} · {mode} · {profile}
                            </dd>
                            <dt>{accepts ? "⇢" : "⇠"}</dt>
                            <dd className="mono" dir="ltr">
                              {netId ? (greAddr ? `${greAddr}:${listenPort}` : "GRE") : accepts ? `${listenHost}:${listenPort}` : `${dialHost}:${listenPort}`}
                            </dd>
                            {side === "entry" && (
                              <>
                                <dt>{t("tun.forwards")}</dt>
                                <dd className="mono" dir="ltr">
                                  {parsed.forwards.length ? ports : "—"}
                                </dd>
                                {proxyOf(proxy, protocol) && (
                                  <>
                                    <dt>{t("proxy.short")}</dt>
                                    <dd className="mono">{proxy}</dd>
                                  </>
                                )}
                              </>
                            )}
                          </dl>
                        </div>
                      );
                    })}
                  </div>
                )}
                {checking && <p className="muted small">…</p>}
                {!opId && conflicts.map((c) => (
                  <p className="err small" key={c}>
                    {c}
                  </p>
                ))}
                <Checklist op={op} />
                {op?.state === "done" && <p className="ok small">{t("tun.done")}</p>}
                {op?.state === "failed" && (
                  <>
                    <p className="err small">{t("tun.failed", { why: opError(t, op.error, new Map(servers.map((x) => [x.id, x.name]))) })}</p>
                    <p className="muted small">{op.undone ? t("tun.undone") : t("tun.notUndone")}</p>
                  </>
                )}
              </>
            )}
            {error && !errAt && <p className="err small" role="alert">{error}</p>}
          </div>
        </div>
      </div>

      <div className="wz-foot">
        {step > 0 && !opId && (
          <button className="btn btn-ghost" type="button" onClick={() => void go(step - 1)}>
            {t("wz.back")}
          </button>
        )}
        <span className="grow" />
        {op?.state === "done" && (
          <button className="btn btn-primary" type="button" onClick={onClose}>
            {t("wz.close")}
          </button>
        )}
        {op?.state === "failed" && (
          <>
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              {t("wz.close")}
            </button>
            <button className="btn btn-primary" type="button" onClick={() => setOpId(null)}>
              {t("wz.retry")}
            </button>
          </>
        )}
        {!opId && step < 4 && (
          <button className="btn btn-primary" type="button" onClick={() => void go(step + 1)}>
            {t("wz.next")}
          </button>
        )}
        {!opId && step === 4 && (
          <button className="btn btn-primary" type="button" disabled={checking || conflicts.length > 0} onClick={() => void build()}>
            <span className="shine" />
            {t("wz.make")}
          </button>
        )}
      </div>
    </div>,
    document.body,
  );
}

function Picker({ label, servers, value, other, locked, onPick }: { label: string; servers: ServerInfo[]; value: string; other: string; locked: boolean; onPick: (id: string) => void }) {
  const { t } = useApp();
  return (
    <div className="field">
      <span className="label">{label}</span>
      <div className="pick-list" role="radiogroup" aria-label={label}>
        {servers.map((s) => {
          const disabled = locked || !s.online || s.id === other;
          return (
            <button key={s.id} type="button" role="radio" aria-checked={value === s.id} aria-disabled={disabled} className="pick" onClick={() => !disabled && onPick(s.id)}>
              <span className="radio" />
              <span>
                <span className="nm">{s.name}</span>
                <br />
                <span className="mt">{s.online ? `${s.arch} · Kariz ${s.version}` : t("wz.offline")}</span>
              </span>
              <span />
            </button>
          );
        })}
      </div>
    </div>
  );
}
