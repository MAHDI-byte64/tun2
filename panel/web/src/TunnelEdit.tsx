import { useEffect, useMemo, useState } from "react";
import { ApiError, api } from "./api";
import type { PairRequest } from "./api";
import type { ServerInfo } from "./api";
import type { Tunnel } from "./derive";
import { useApp } from "./store";
import { Icon, Seg } from "./ui";
import { Checklist, opError, useOp } from "./ops";
import { MuxFields, MuxToggle, muxFromSpec, muxSpecOf, muxToSpec } from "./MuxFields";
import { TlsChoice, emptyTls, tlsReady } from "./TlsChoice";
import { EncryptionChoice, cipherOf, cipherReady } from "./EncryptionChoice";
import { QuicObfs, obfsOf } from "./QuicObfs";
import { PerIpLimit, perIpOf } from "./PerIpLimit";
import { UdpFlows, udpFlowsOf } from "./UdpFlows";
import { ProxyProtocol, proxyFromSpec, proxyOf } from "./ProxyProtocol";
import type { ProxyChoice } from "./ProxyProtocol";
import { GreChoice, linkWithAddress } from "./GreChoice";
import { useNetworks } from "./Networks";
import { MUX_OPTIONAL, ROOT_ONLY, SPLIT_TRANSPORTS, SPOOF_SHAPES, TRANSPORTS, joinTransport, splitTransport } from "./transport";
import {
  FaketcpOptions,
  HelperFields,
  IcmpOptions,
  L3Options,
  RootWarning,
  AsymmetricPicker,
  SpoofOptions,
  StealthOptions,
  emptyFaketcp,
  emptyHelper,
  emptyIcmp,
  emptyL3,
  emptySpoof,
  emptyStealth,
  faketcpFrom,
  faketcpOf,
  helperFrom,
  helperOf,
  icmpFrom,
  icmpOf,
  l3From,
  l3Of,
  parseSpoofPool,
  spoofFrom,
  spoofOf,
  stealthFrom,
  stealthOf,
} from "./TransportOptions";
import { PROFILES, addressesOf, hostOf, parsePorts, portOf } from "./Wizard";
import { benchLabel, isV6 } from "./Benchmark";
import type { BenchChoice } from "./Benchmark";

/** Editing a tunnel: everything about it on one page, no steps. */
export function TunnelEdit({ tunnel, servers, preset, onBack }: { tunnel: Tunnel; servers: ServerInfo[]; preset?: BenchChoice | null; onBack: () => void }) {
  const { t } = useApp();
  const entry = tunnel.entry?.server.id ?? "";
  const exit = tunnel.exit?.server.id ?? "";
  const [loading, setLoading] = useState(true);
  // The tunnel cannot be edited now (a server is away, or it has one side only): say why.
  const [blocked, setBlocked] = useState(false);
  const [mode, setMode] = useState("reverse");
  const [transport, setTransport] = useState("tcp");
  const [spoof, setSpoof] = useState(false);
  const [spoofShape, setSpoofShape] = useState("udp");
  const [spoofS, setSpoofS] = useState(emptySpoof());
  const [asym, setAsym] = useState(false);
  const [recvTransport, setRecvTransport] = useState("tcp");
  const [spoofRecvShape, setSpoofRecvShape] = useState("tcp");
  const [muxOn, setMuxOn] = useState(true);
  const [profile, setProfile] = useState("balanced");
  const [listenHost, setListenHost] = useState("0.0.0.0");
  const [listenPort, setListenPort] = useState("");
  const [dialHost, setDialHost] = useState("");
  const [wsPath, setWsPath] = useState("/");
  const [wsHost, setWsHost] = useState("");
  const [sni, setSni] = useState("");
  const [pool, setPool] = useState<number | undefined>();
  const [ports, setPorts] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [target, setTarget] = useState("127.0.0.1");
  const [mux, setMux] = useState(muxFromSpec());
  const [tls, setTls] = useState(emptyTls());
  const [enc, setEnc] = useState("auto");
  const [encAck, setEncAck] = useState(false);
  const [obfs, setObfs] = useState(false);
  const [stealthS, setStealthS] = useState(emptyStealth());
  const [faketcpS, setFaketcpS] = useState(emptyFaketcp());
  const [icmpS, setIcmpS] = useState(emptyIcmp());
  const [helperS, setHelperS] = useState(emptyHelper());
  const [l3S, setL3S] = useState(emptyL3());
  const [perIp, setPerIp] = useState("");
  const [udpFlows, setUdpFlows] = useState("");
  const [proxy, setProxy] = useState<ProxyChoice>("off");
  // The private GRE network the tunnel runs over (its id), or none: found from the address the
  // tunnel listens on once the networks have come in.
  const [netId, setNetId] = useState("");
  const [loadedHost, setLoadedHost] = useState<string | null>(null);
  const [netReady, setNetReady] = useState(false);
  const { networks, links, loaded: netsLoaded } = useNetworks();
  const [rotate, setRotate] = useState(false);
  const [error, setError] = useState("");
  const [opId, setOpId] = useState<string | null>(null);
  const [initial, setInitial] = useState("");
  const op = useOp(opId);
  const running = !!opId && (!op || op.state === "running");

  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? id;
  const acceptor = mode === "reverse" ? entry : exit;
  const dialer = mode === "reverse" ? exit : entry;
  const parsed = useMemo(() => parsePorts(ports, protocol, target.trim() || "127.0.0.1"), [ports, protocol, target]);
  const tp = spoof ? "spoof" : transport;
  const wsName = (x: string) => x === "ws" || x === "wss" || x === "wsmux" || x === "wssmux";
  const splittable = (x: string) => (SPLIT_TRANSPORTS as readonly string[]).includes(x);
  const isWs = !spoof && (wsName(transport) || (asym && wsName(recvTransport)));
  const usesWss = !spoof && (transport === "wss" || (asym && recvTransport === "wss"));
  const isL3 = !spoof && transport === "l3";
  const rootOnly = ROOT_ONLY.includes(tp) || (isL3 && ["faketcp", "icmp", "proto47"].includes(l3S.carrier));
  const choices = (() => {
    const s = servers.find((x) => x.id === acceptor);
    return s ? addressesOf(s) : [];
  })();

  // What the two servers hold now.
  useEffect(() => {
    if (!tunnel.entry || !tunnel.exit) {
      setError(t("wz.oneSide"));
      setBlocked(true);
      setLoading(false);
      return;
    }
    const away = [entry, exit].filter((id) => !servers.find((s) => s.id === id)?.online);
    if (away.length) {
      setError(t("te.offline", { servers: away.map(serverName).join(", ") }));
      setBlocked(true);
      setLoading(false);
      return;
    }
    let alive = true;
    void Promise.all([api.tunnelSpec(entry, tunnel.name), api.tunnelSpec(exit, tunnel.name)])
      .then(([a, b]) => {
        if (!alive) return;
        const acc = a.mode === "reverse" ? a : b;
        const dia = a.mode === "reverse" ? b : a;
        setMode(a.mode);
        if (a.transport === "spoof") {
          setSpoof(true);
          setTransport("tcp");
          setMuxOn((a.mux ?? b.mux)?.enabled ?? true);
          // a is the entry server's spec: its `shape` is the upload (entry→exit) shape and
          // `recv_shape`, if set, the download one — so the tunnel is asymmetric.
          const rs = a.spoof?.recv_shape ?? b.spoof?.recv_shape;
          setSpoofShape(a.spoof?.shape ?? b.spoof?.shape ?? "udp");
          setAsym(!!rs);
          if (rs) setSpoofRecvShape(rs);
          // a is the entry server's spec, b the exit's — each carries its own forged list.
          setSpoofS(spoofFrom(a.spoof, b.spoof));
        } else if (a.recv_transport) {
          // Asymmetric: link A = `transport`, link B = `recv_transport`. Map the two links back
          // to the user's send (entry→exit) / receive (exit→entry) by who dials.
          setSpoof(false);
          setAsym(true);
          setMuxOn(true);
          const [send, recv] =
            a.mode === "reverse" ? [a.recv_transport, a.transport] : [a.transport, a.recv_transport];
          setTransport(send);
          setRecvTransport(recv);
          setSpoofS(spoofFrom(a.spoof, b.spoof));
        } else {
          setSpoof(false);
          setAsym(false);
          const split = splitTransport(a.transport, a.mux ?? b.mux);
          setTransport(split.transport);
          setMuxOn(split.mux);
          setSpoofS(spoofFrom(a.spoof, b.spoof));
        }
        setProfile(a.profile ?? "balanced");
        setLoadedHost(hostOf(acc.listen));
        setListenHost(hostOf(acc.listen) || "0.0.0.0");
        setListenPort(portOf(acc.listen));
        setDialHost(hostOf(dia.remote));
        setWsPath(a.ws_path ?? "/");
        setWsHost(a.ws_host ?? b.ws_host ?? "");
        const real = acc.tls_cert && acc.tls_key ? { cert: acc.tls_cert, key: acc.tls_key } : null;
        // With a real certificate the server name is the certificate's own (not one to edit).
        setSni(real ? "" : (dia.tls_sni ?? ""));
        setPool(a.pool);
        const list = a.forwards;
        setPorts(list.map((f) => (portOf(f.listen) === portOf(f.target) ? portOf(f.listen) : `${portOf(f.listen)}=${portOf(f.target)}`)).join(", "));
        setProtocol(list[0]?.protocol ?? "tcp");
        setTarget(hostOf(list[0]?.target) || "127.0.0.1");
        setMux(muxFromSpec(a.mux ?? b.mux));
        setEnc(a.encryption ?? "auto");
        setObfs(!!(a.quic_obfs ?? b.quic_obfs));
        setStealthS(stealthFrom(a.stealth ?? b.stealth));
        setFaketcpS(faketcpFrom(a.faketcp ?? b.faketcp));
        setIcmpS(icmpFrom(a.icmp ?? b.icmp));
        // The managed-helper credentials are split per side; the two specs together hold them.
        setHelperS(helperFrom({ ...b.helper, ...acc.helper }));
        setL3S(l3From(a.l3 ?? b.l3));
        setPerIp(String(a.max_conns_per_ip ?? b.max_conns_per_ip ?? ""));
        setUdpFlows(String(a.udp_max_flows ?? b.udp_max_flows ?? ""));
        setProxy(proxyFromSpec(a.proxy_protocol ?? b.proxy_protocol));
        // A tunnel that has no encryption already was confirmed when it was made.
        setEncAck((a.encryption ?? "auto") === "none");
        setTls(real ? { mode: "real", host: dia.tls_sni || hostOf(dia.remote), email: "", ...real } : emptyTls());
        setInitial("");
      })
      .catch(() => {
        setError(t("tun.failed", { why: "no_such_tunnel" }));
        setBlocked(true);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [tunnel.name]); // eslint-disable-line react-hooks/exhaustive-deps

  // A tunnel that listens on the private address of a link runs over that link's network.
  useEffect(() => {
    if (loadedHost === null || !netsLoaded || netReady) return;
    const link = linkWithAddress(links, loadedHost);
    if (link) setNetId(link.network);
    setNetReady(true);
  }, [loadedHost, netsLoaded, netReady, links]);

  // Off the network, the tunnel goes back to the public addresses: it listens on every address and
  // dials the one the panel knows the accepting server by (changeable below).
  const chooseNetwork = (id: string) => {
    if (!id && netId) {
      setListenHost("0.0.0.0");
      setDialHost(choices[0] ?? "");
    }
    setNetId(id);
  };

  const muxSpec = muxToSpec(mux);
  const request = (): PairRequest => ({
    name: tunnel.name,
    entry,
    exit,
    mode,
    transport: spoof ? "spoof" : asym ? transport : joinTransport(transport, muxOn).core,
    recv_transport: asym && !spoof ? recvTransport : undefined,
    profile,
    listen: `${listenHost}:${listenPort}`,
    dial: `${dialHost.includes(":") && !dialHost.startsWith("[") ? `[${dialHost}]` : dialHost}:${listenPort}`,
    network: netId || undefined,
    pool,
    ws_path: isWs ? wsPath : undefined,
    ws_host: isWs && wsHost.trim() ? wsHost.trim() : undefined,
    tls_sni: usesWss && tls.mode === "self" && sni.trim() ? sni.trim() : undefined,
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
    rotate: rotate ? true : undefined,
    forwards: parsed.forwards,
  });

  // What was loaded, to tell whether anything changed.
  const ready = !loading && (blocked || netReady);
  const now = ready ? JSON.stringify(request()) : "";
  useEffect(() => {
    if (ready && !initial) setInitial(now);
  }, [ready, now]); // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = !!initial && now !== initial;

  // Dialed at an IPv6 address, the accepting side listens on every address, IPv6 too (on every IPv4 one it
  // would never answer).
  useEffect(() => {
    if (!netId && isV6(dialHost) && listenHost === "0.0.0.0") setListenHost("[::]");
  }, [dialHost, netId, listenHost]);

  // Opened from a benchmark result: once what the tunnel has is known, its direction, transport, network, the
  // IPv6 address of an IPv6 result and the server name of a wss one are put in, as changes to look over and save.
  const [presetDone, setPresetDone] = useState(false);
  useEffect(() => {
    if (!preset || presetDone || !initial || blocked) return;
    setMode(preset.mode);
    setSpoof(false);
    setTransport(preset.transport === "tcpmux" ? "tcp" : preset.transport);
    setMuxOn(true);
    chooseNetwork(preset.network ?? "");
    if (preset.host && (preset.path === "ipv6" || isV6(dialHost))) setDialHost(preset.host);
    if (preset.sni) setSni(preset.sni);
    setPresetDone(true);
  }, [initial]); // eslint-disable-line react-hooks/exhaustive-deps

  const problem = (): string => {
    if (!/^\d{1,5}$/.test(listenPort) || +listenPort < 1 || +listenPort > 65535) return t("wz.port", { server: serverName(acceptor) });
    if (!dialHost.trim() && !netId) return t("wz.dial", { server: serverName(acceptor), other: serverName(dialer) });
    if (isWs && !wsPath.startsWith("/")) return t("wz.wsPath");
    if (usesWss && !tlsReady(tls)) return t("tls.needCert");
    if (spoof && (parseSpoofPool(spoofS.entryPool).length === 0 || parseSpoofPool(spoofS.exitPool).length === 0)) return t("spf.poolNeeded");
    if (asym && !spoof && recvTransport === transport) return t("asym.needDiffer");
    if (asym && spoof && spoofRecvShape === spoofShape) return t("asym.needDiffer");
    if (!cipherReady(enc, tp, encAck)) return t("enc.needAck");
    if (parsed.bad !== undefined) return parsed.bad ? t("wz.badPorts", { bit: parsed.bad }) : t("wz.ports");
    if (muxSpec.bad) return `${t(`mux.${muxSpec.bad}`)}: ${t("mux.badValue")}`;
    if (perIpOf(perIp).bad) return t("perip.bad");
    if (protocol.includes("udp") && udpFlowsOf(udpFlows).bad) return t("udpflows.bad");
    return "";
  };

  const save = async () => {
    const p = problem();
    if (p) return setError(p);
    setError("");
    try {
      setOpId((await api.editTunnel(request())).op);
    } catch (e) {
      setError(e instanceof ApiError && e.code === "busy" ? t("wz.busy") : e instanceof ApiError ? opError(t, e.code, new Map(servers.map((x) => [x.id, x.name]))) : String(e));
    }
  };

  const names = new Map(servers.map((x) => [x.id, x.name]));
  const choose = (list: readonly string[], value: string, set: (v: string) => void, text: (v: string) => [string, string]) => (
    <div className="tiles" role="radiogroup">
      {list.map((x) => {
        const [title, hint] = text(x);
        return (
          <button key={x} type="button" role="radio" aria-checked={value === x} className="tile" onClick={() => set(x)}>
            <span className="t1">{title}</span>
            <span className="t2">{hint}</span>
            <span className="tick">
              <Icon name="check" size={14} />
            </span>
          </button>
        );
      })}
    </div>
  );

  return (
    <div className="page is-on tunnel-edit">
      <section className="card edit-head">
        <button className="icon-square td-back" type="button" onClick={onBack} disabled={running} aria-label={t("td.back")} title={t("td.back")}>
          <Icon name="back" size={18} />
        </button>
        <div className="td-title">
          <h2 className="td-name mono">{tunnel.name}</h2>
          <p className="muted small">{t("te.lead", { entry: serverName(entry), exit: serverName(exit) })}</p>
        </div>
      </section>
      {preset && !blocked && !loading && (
        <div className="banner info">
          <Icon name="gauge" size={18} />
          <span>{t("te.fromBench", { t: benchLabel(preset.transport), mode: t(`bench.mode.${preset.mode}`) })}</span>
        </div>
      )}

      {blocked ? (
        <section className="card edit-sec">
          <p className="err small" role="alert">
            {error}
          </p>
          <div className="edit-bar">
            <button className="btn btn-ghost" type="button" onClick={onBack}>
              {t("td.back")}
            </button>
          </div>
        </section>
      ) : loading ? (
        <section className="card">
          <p className="muted">…</p>
        </section>
      ) : (
        <>
          <fieldset className="card edit-sec" disabled={running || op?.state === "done"}>
            <legend>{t("te.how")}</legend>
            <div className="field">
              <span className="label">{t("wz.q2")}</span>
              <Seg
                value={spoof ? "spoof" : mode}
                options={[["reverse", t("wz.mode.reverse")], ["direct", t("wz.mode.direct")], ["spoof", t("wz.mode.spoof")]]}
                onChange={(v) => {
                  if (v === "spoof") setSpoof(true);
                  else {
                    setSpoof(false);
                    setMode(v);
                  }
                }}
              />
              <span className="help">{t(spoof ? "wz.mode.spoof.d" : `wz.mode.${mode}.d`)}</span>
            </div>
            <div className="field">
              <div className="wz-trhead" style={{ marginTop: 0 }}>
                <span className="label" style={{ margin: 0 }}>
                  {asym ? t("asym.pick") : spoof ? t("wz.spoofShape") : t("wz.transport")}
                </span>
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
              <span className="help">{t("asym.hint")}</span>
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
              ) : spoof ? (
                choose(SPOOF_SHAPES, spoofShape, setSpoofShape, (x) => [x, t(`wz.shape.${x}`)])
              ) : (
                choose(TRANSPORTS, transport, setTransport, (x) => [x, t(`wz.tr.${x}`)])
              )}
              {!spoof && !asym && joinTransport(transport, muxOn).core !== tunnel.transport && <span className="help warn-text">{t("te.transportChange")}</span>}
              {spoof && tunnel.transport !== "spoof" && <span className="help warn-text">{t("te.transportChange")}</span>}
            </div>
            <div className="field">
              <span className="label">{t("wz.profile")}</span>
              {choose(PROFILES, profile, setProfile, (x) => [t(`wz.pf.${x}`), t(`wz.pf.${x}.d`)])}
            </div>
            <EncryptionChoice value={enc} onChange={setEnc} transport={tp} ack={encAck} onAck={setEncAck} />
            {!spoof && transport === "quic" && <QuicObfs value={obfs} onChange={setObfs} />}
            {rootOnly && <RootWarning />}
            {spoof && <SpoofOptions value={spoofS} onChange={setSpoofS} entryName={serverName(entry)} exitName={serverName(exit)} />}
            {!spoof && transport === "stealth" && <StealthOptions value={stealthS} onChange={setStealthS} />}
            {!spoof && transport === "faketcp" && <FaketcpOptions value={faketcpS} onChange={setFaketcpS} />}
            {!spoof && transport === "icmp" && <IcmpOptions value={icmpS} onChange={setIcmpS} />}
            {!spoof && ["naive", "xhttp", "reality"].includes(transport) && <HelperFields transport={transport} value={helperS} onChange={setHelperS} />}
            {isL3 && <L3Options value={l3S} onChange={setL3S} />}
          </fieldset>

          <fieldset className="card edit-sec" disabled={running || op?.state === "done"}>
            <legend>{t("te.where")}</legend>
            <p className="muted small">{t("wz.lead3", { acceptor: serverName(acceptor), dialer: serverName(dialer) })}</p>
            <GreChoice value={netId} onChange={chooseNetwork} networks={networks} links={links} entry={entry} exit={exit} acceptor={acceptor} port={listenPort} serverName={serverName} />
            {!netId && loadedHost !== null && !!linkWithAddress(links, loadedHost) && <p className="help warn-text">{t("te.greOff")}</p>}
            <div className="grid-2">
              <div className="field">
                <label htmlFor="te-port">{t("wz.port", { server: serverName(acceptor) })}</label>
                <input className="text mono" id="te-port" dir="ltr" inputMode="numeric" value={listenPort} onChange={(e) => setListenPort(e.target.value.trim())} />
                {transport === "auto" && <span className="help">{t("wz.autoPorts", { server: serverName(acceptor), tcp: listenPort, udp: listenPort, ws: String(+listenPort + 1) })}</span>}
              </div>
              <div className="field" hidden={!!netId}>
                <label htmlFor="te-dial">{t("wz.dial", { server: serverName(acceptor), other: serverName(dialer) })}</label>
                <input className="text mono" id="te-dial" dir="ltr" value={dialHost} placeholder="203.0.113.5" onChange={(e) => setDialHost(e.target.value.trim())} />
                {choices.length > 0 && (
                  <span className="addr-chips">
                    {choices.map((a) => (
                      <button key={a} type="button" className={`pchip as-btn ${a === dialHost ? "on" : ""}`} dir="ltr" onClick={() => setDialHost(a)}>
                        {a}
                      </button>
                    ))}
                  </span>
                )}
                {mode === "direct" && <span className="help">{t("wz.directHelp", { server: serverName(acceptor), port: listenPort })}</span>}
              </div>
              {isWs && (
                <div className="field">
                  <label htmlFor="te-ws">{t("wz.wsPath")}</label>
                  <input className="text mono" id="te-ws" dir="ltr" value={wsPath} onChange={(e) => setWsPath(e.target.value.trim())} />
                </div>
              )}
              {isWs && (
                <div className="field">
                  <label htmlFor="te-wshost">{t("wz.wsHost")}</label>
                  <input className="text mono" id="te-wshost" dir="ltr" value={wsHost} placeholder="cdn.example.com" onChange={(e) => setWsHost(e.target.value.trim())} />
                  <span className="help">{t("wz.wsHostHelp")}</span>
                </div>
              )}
              {usesWss && (
                <div style={{ gridColumn: "1 / -1" }}>
                  <TlsChoice value={tls} onChange={setTls} server={acceptor} serverName={serverName(acceptor)} onHost={(h) => setDialHost(h)} />
                </div>
              )}
              {usesWss && tls.mode === "self" && (
                <div className="field">
                  <label htmlFor="te-sni">{t("wz.sni")}</label>
                  <input className="text mono" id="te-sni" dir="ltr" value={sni} placeholder="www.example.com" onChange={(e) => setSni(e.target.value.trim())} />
                  <span className="help">{t("wz.sniHelp")}</span>
                </div>
              )}
              {transport === "tcp" && !muxOn && (
                <div className="field">
                  <label htmlFor="te-pool">{t("wz.pool")}</label>
                  <input
                    className="text mono"
                    id="te-pool"
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
          </fieldset>

          <fieldset className="card edit-sec" disabled={running || op?.state === "done"}>
            <legend>{t("te.ports")}</legend>
            <p className="muted small">{t("wz.lead4")}</p>
            <div className="field" style={{ maxWidth: 520 }}>
              <label htmlFor="te-ports">{t("wz.ports")}</label>
              <input className="text mono" id="te-ports" dir="ltr" value={ports} placeholder="443, 8080-8090" onChange={(e) => setPorts(e.target.value)} />
              <span className="help">{t("wz.portsHelp")}</span>
            </div>
            <div className="port-chips" aria-live="polite">
              {parsed.forwards.slice(0, 40).map((f) => (
                <span className="pchip" key={f.listen + f.target}>
                  {f.listen.split(":").pop()}
                  <small>→ {f.target.split(":").pop()}</small>
                </span>
              ))}
              {parsed.forwards.length > 40 && <span className="pchip">+{parsed.forwards.length - 40}</span>}
              {parsed.bad && <span className="pchip bad">{parsed.bad}</span>}
            </div>
            <div className="grid-2" style={{ maxWidth: 520 }}>
              <div className="field">
                <span className="label">{t("wz.protocol")}</span>
                <Seg value={protocol} options={[["tcp", "TCP"], ["udp", "UDP"], ["tcp+udp", "TCP+UDP"]]} onChange={setProtocol} />
              </div>
              <div className="field">
                <label htmlFor="te-target">{t("wz.targetHost")}</label>
                <input className="text mono" id="te-target" dir="ltr" value={target} onChange={(e) => setTarget(e.target.value.trim())} />
              </div>
            </div>
            <div style={{ maxWidth: 520 }}>
              <PerIpLimit id="te-perip" value={perIp} onChange={setPerIp} />
              <UdpFlows id="te-udpflows" value={udpFlows} onChange={setUdpFlows} protocol={protocol} />
              <ProxyProtocol value={proxy} onChange={setProxy} protocol={protocol} />
            </div>
          </fieldset>

          {!isL3 && (
            <fieldset className="card edit-sec" disabled={running || op?.state === "done"}>
              <legend>{t("mux.title")}</legend>
              <MuxToggle transport={tp} value={muxOn} onChange={setMuxOn} />
              {(muxOn || !MUX_OPTIONAL.includes(tp)) && <MuxFields value={mux} onChange={setMux} profile={profile} transport={tp} />}
            </fieldset>
          )}

          <fieldset className="card edit-sec" disabled={running || op?.state === "done"}>
            <legend>{t("te.security")}</legend>
            <label className="check">
              <input type="checkbox" checked={rotate} onChange={(e) => setRotate(e.target.checked)} /> {t("wz.rotate")}
            </label>
          </fieldset>

          {(opId || error) && (
            <section className="card edit-sec" aria-live="polite">
              {error && (
                <p className="err small" role="alert">
                  {error}
                </p>
              )}
              <Checklist op={op} />
              {op?.state === "done" && <p className="ok small">{t("tun.done")}</p>}
              {op?.state === "failed" && (
                <>
                  <p className="err small">{t("tun.failed", { why: opError(t, op.error, names) })}</p>
                  <p className="muted small">{op.undone ? t("tun.undone") : t("tun.notUndone")}</p>
                </>
              )}
            </section>
          )}

          <div className="edit-bar">
            <button className="btn btn-ghost" type="button" disabled={running} onClick={onBack}>
              {op?.state === "done" ? t("wz.close") : t("cancel")}
            </button>
            <span className="grow" />
            {op?.state === "failed" && (
              <button className="btn btn-ghost" type="button" onClick={() => setOpId(null)}>
                {t("wz.retry")}
              </button>
            )}
            {!opId && (
              <button className="btn btn-primary" type="button" disabled={!dirty} onClick={() => void save()}>
                <span className="shine" />
                {t("wz.save")}
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
