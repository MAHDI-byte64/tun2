import { useEffect, useRef, useState } from "react";
import { api, ApiError, kindLabel } from "./api";
import type { GreJoin, LinkKind, LinkTransport, PanelAddresses, ServerInfo } from "./api";
import { NewGreLinkFields, greJoinError, ipv4Ok, networkOfKind } from "./GreLink";
import { AgentPortField, agentPortError, agentPortOf, agentPortOk } from "./AgentPort";
import { useNetworks } from "./Networks";
import { useApp } from "./store";
import { linkPorts, reverseOk } from "./transport";
import { CodeBlock, Dialog, Icon, Seg, useAgo } from "./ui";

/** Who makes the server's link: its agent dials the panel, or the panel dials its agent (reverse). */
type Way = "dial" | "reverse";

const TRANSPORTS: LinkTransport[] = ["auto", "tcpmux", "kcp", "wss", "quic"];

/**
 * A server whose agent is not connected, or one that is to change how its agent reaches the
 * panel: what the panel knows, what to look at on that server, and a join code that makes the
 * new agent that same server again (same name, same tunnels, same private network links).
 * Also its name.
 */
export function ServerFixDialog({ server, servers, agentsOn, onChanged, onClose }: { server: ServerInfo; servers: ServerInfo[]; agentsOn: boolean; onChanged: () => void; onClose: () => void }) {
  const { t, toast, digitsOf } = useApp();
  const ago = useAgo();
  const live = servers.find((s) => s.id === server.id) ?? server;
  const wasOffline = useRef(!server.online);
  const [name, setName] = useState(server.name);
  // A server that came in through a private network link goes on dialling the panel's end of it.
  const [host, setHost] = useState(location.hostname.replace(/^\[|\]$/g, ""));
  const picked = useRef(false);
  const [transport, setTransport] = useState<LinkTransport>((server.reverse?.transport as LinkTransport | undefined) ?? "auto");
  // A server the panel connects to goes on being one, at the address it has, until that is changed here.
  const [way, setWay] = useState<Way>(server.reverse ? "reverse" : "dial");
  const [rhost, setRhost] = useState(server.reverse?.host ?? server.ip4 ?? server.addr ?? "");
  const [rport, setRport] = useState(String(server.reverse?.port ?? 29001));
  // Reverse across a GRE link to the panel's server: one it has (by link id), or a new one the panel makes.
  const [greOn, setGreOn] = useState(!!(server.reverse && server.gre));
  const [greLink, setGreLink] = useState(server.reverse && server.gre ? server.gre.link : "");
  // Reverse through the panel's SOCKS5 proxy (Settings → Proxy), as it is set now.
  const [viaProxy, setViaProxy] = useState(!!server.reverse?.via_proxy);
  const [proxyOn, setProxyOn] = useState<boolean | null>(null);
  const [ip, setIp] = useState(server.addr ?? server.ip4 ?? "");
  const { networks } = useNetworks();
  const [netId, setNetId] = useState("");
  const [linkKind, setLinkKind] = useState<LinkKind>("gre");
  // The agents port its agent dials (empty: the panel's), as it has it now.
  const [ownPort, setOwnPort] = useState(server.agent_port ? String(server.agent_port) : "");
  const [madeGre, setMadeGre] = useState<GreJoin | null>(null);
  const [own, setOwn] = useState<PanelAddresses | null>(null);
  const [code, setCode] = useState("");
  const [left, setLeft] = useState(0);
  const [error, setError] = useState("");
  const [nameError, setNameError] = useState("");
  const back = !!code && wasOffline.current && live.online;

  useEffect(() => {
    let alive = true;
    api
      .panelAddresses()
      .then((a) => {
        if (!alive) return;
        setOwn(a);
        const mine = (a.gre ?? []).find((g) => g.server === server.id);
        if (mine && server.gre && !picked.current) setHost(mine.addr);
      })
      .catch(() => {});
    api
      .proxy()
      .then((p) => alive && setProxyOn(p.enabled))
      .catch(() => alive && setProxyOn(false));
    return () => {
      alive = false;
    };
  }, []);
  useEffect(() => {
    if (left <= 0 || back) return;
    const id = setInterval(() => setLeft((v) => Math.max(0, v - 1)), 1000);
    return () => clearInterval(id);
  }, [left > 0, back]); // eslint-disable-line react-hooks/exhaustive-deps

  const saveName = async () => {
    setNameError("");
    try {
      await api.renameServer(server.id, name.trim());
      toast(t("fix.renamed"), "ok");
      onChanged();
    } catch (e) {
      setNameError(e instanceof ApiError && e.code === "name_taken" ? t("fix.nameTaken") : t("fix.nameBad"));
    }
  };

  // The private network links between this server and the panel's, and the one picked (none: a new one).
  const mine = (own?.gre ?? []).filter((g) => g.server === server.id);
  const viaLink = greOn ? (mine.find((g) => g.link === greLink) ?? (greLink === "new" ? undefined : mine[0])) : undefined;
  const newLink = way === "reverse" && greOn && !viaLink;
  const throughProxy = way === "reverse" && !greOn && viaProxy;
  // A SOCKS5 proxy carries no UDP: through it, only the TCP transports are offered.
  const transports = TRANSPORTS.filter((x) => !throughProxy || (x !== "kcp" && x !== "quic"));

  const make = async () => {
    setError("");
    try {
      if (newLink) {
        const made = await api.reconnectServer(server.id, "", transport, { host: "", port: +rport }, { ip: ip.trim(), network: networkOfKind(networks, netId, linkKind), kind: linkKind });
        setMadeGre(made as GreJoin);
        setCode(made.code);
        setLeft(made.valid_for);
        return;
      }
      const made =
        way === "reverse"
          ? await api.reconnectServer(server.id, "", transport, { host: viaLink ? viaLink.peer_addr : rhost.trim().replace(/^\[|\]$/g, ""), port: +rport, via_proxy: throughProxy })
          : await api.reconnectServer(server.id, host.trim(), transport, undefined, undefined, agentPortOf(ownPort, port) ?? undefined);
      setCode(made.code);
      setLeft(made.valid_for);
    } catch (e) {
      if (newLink) setError(e instanceof ApiError ? greJoinError(t, e.code, new Map(servers.map((s) => [s.id, s.name]))) : String(e));
      else if (e instanceof ApiError && (e.code === "proxy_udp" || e.code === "proxy_off")) setError(t(`add.rev.err.${e.code}`));
      else if (e instanceof ApiError && agentPortError(t, e.code, new Map(servers.map((s) => [s.id, s.name])))) setError(agentPortError(t, e.code, new Map(servers.map((s) => [s.id, s.name]))) ?? "");
      else setError(e instanceof ApiError && e.code === "agents_off" ? t("add.off") : t(way === "reverse" ? "add.rev.err.input" : "add.bad"));
    }
  };

  const mmss = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
  const port = own?.agent_port ?? null;
  const here = location.hostname.replace(/^\[|\]$/g, "");
  const choices: [string, string][] = [
    ...(own?.v4 ? [[t("add.addr.v4"), own.v4] as [string, string]] : []),
    ...(own?.v6 ? [[t("add.addr.v6"), own.v6] as [string, string]] : []),
    ...(here && here !== own?.v4 && here !== own?.v6 ? [[t("add.addr.here"), here] as [string, string]] : []),
    ...(own?.gre ?? []).filter((g) => g.server === server.id).map((g) => [t("fix.addr.gre", { kind: kindLabel(g.kind), network: g.network }), g.addr] as [string, string]),
  ];
  const greNow = (own?.gre ?? []).find((g) => g.server === server.id && g.addr === host.trim());
  const dialPort = agentPortOf(ownPort, port);
  const portText = (x: LinkTransport) => (dialPort == null ? "?" : String(x === "wss" ? dialPort + 1 : dialPort));
  const seenAgo = live.last_seen ? ago(Math.max(0, Date.now() / 1000 - live.last_seen)) : null;
  const err = live.last_error;
  const title = live.online ? t("fix.titleOnline", { name: live.name }) : t("fix.title", { name: live.name });
  // The panel needs no agents port of its own when it is the one that connects.
  const blocked = !agentsOn && way === "dial";
  const portOk = /^\d+$/.test(rport) && +rport > 0 && +rport < 65535;
  const panelPublic = own ? (own.gre_local ?? null) : undefined;
  const ready = way === "reverse" ? (newLink ? ipv4Ok(ip) && panelPublic !== null && portOk : viaLink ? portOk : reverseOk(rhost, rport)) : !!host.trim() && agentPortOk(ownPort);

  return (
    <Dialog
      title={title}
      onClose={onClose}
      footer={
        back ? (
          <button
            className="btn btn-primary btn-sm"
            type="button"
            onClick={() => {
              toast(t("fix.connected", { name: live.name }), "ok");
              onChanged();
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
              <button className="btn btn-primary btn-sm" type="button" disabled={!ready || blocked} onClick={() => void make()}>
                {t("fix.make")}
              </button>
            )}
          </>
        )
      }
    >
      {blocked && <p className="err small">{t("add.off")}</p>}

      <div className="fix-state">
        {live.online ? (
          <p>
            <Icon name="check" size={16} /> {t("fix.onlineNow")}
          </p>
        ) : (
          <>
            <p>
              <Icon name="alert" size={16} /> {t("fix.offlineNow")}
              {seenAgo ? ` ${t("fix.lastSeen", { ago: digitsOf(seenAgo) })}` : ` ${t("fix.neverSeen")}`}
            </p>
            {err?.kind === "wrong_key" && <p className="err small">{t("fix.err.wrong_key")}</p>}
            {err?.kind === "proxy_off" && <p className="err small">{t("fix.err.proxy_off")}</p>}
            {err?.kind === "link_ended" && (
              <p className="small">
                {t("fix.err.link_ended")} {err.detail && <code dir="ltr">{err.detail}</code>}
              </p>
            )}
            {!err && <p className="small muted">{t("fix.err.none")}</p>}
          </>
        )}
        <span className="help">{t("fix.tunnelsKeep")}</span>
      </div>

      <div className="field">
        <label htmlFor="fix-name">{t("fix.name")}</label>
        <div className="ar-row fix-name-row">
          <input id="fix-name" className="text mono" dir="ltr" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="btn btn-ghost btn-sm" type="button" disabled={!name.trim() || name.trim() === live.name} onClick={() => void saveName()}>
            {t("ar.save")}
          </button>
        </div>
        {nameError && <span className="err">{nameError}</span>}
      </div>

      {!live.online && !code && !live.last_seen && (
        <div className="field">
          <span className="label">{t("fix.waitTitle")}</span>
          <span className="help">{t("fix.waitText")}</span>
        </div>
      )}

      {!live.online && !code && !!live.last_seen && (
        <div className="field">
          <span className="label">{t("fix.checkTitle")}</span>
          <span className="help">{t("fix.check1")}</span>
          <CodeBlock text="kariz-manager agent status" />
          <span className="help">{t("fix.check2")}</span>
          <CodeBlock text="systemctl restart kariz-agent" />
          <span className="help">{t("fix.check3")}</span>
        </div>
      )}

      {!code && (
        <div className="field">
          <span className="label">{t("fix.way")}</span>
          <Seg<Way>
            value={way}
            options={[
              ["dial", t("fix.way.dial")],
              ["reverse", t("fix.way.reverse")],
            ]}
            onChange={(w) => {
              setWay(w);
              setError("");
            }}
          />
          <span className="help">{t(way === "reverse" ? "fix.way.reverse.d" : "fix.way.dial.d")}</span>
        </div>
      )}

      {!code && way === "reverse" && (
        <>
          <div className="field">
            <label className="check">
              <input
                type="checkbox"
                checked={greOn}
                onChange={(e) => {
                  setGreOn(e.target.checked);
                  setError("");
                }}
              />{" "}
              {t("fix.rev.gre")}
            </label>
            <span className="help">{t("fix.rev.gre.d")}</span>
          </div>
          {greOn && mine.length > 0 && (
            <div className="field">
              <span className="label">{t("fix.rev.gre.which")}</span>
              <div className="addr-picks" role="group" aria-label={t("fix.rev.gre.which")}>
                {mine.map((g) => (
                  <button key={g.link} type="button" className="addr-pick" aria-pressed={viaLink?.link === g.link} onClick={() => setGreLink(g.link)}>
                    <span>{t("fix.addr.gre", { kind: kindLabel(g.kind), network: g.network })}</span>
                    <code dir="ltr">{g.peer_addr}</code>
                  </button>
                ))}
                <button type="button" className="addr-pick" aria-pressed={!viaLink} onClick={() => setGreLink("new")}>
                  <span>{t("fix.rev.gre.new")}</span>
                  <code dir="ltr">GRE +</code>
                </button>
              </div>
              {viaLink && <span className="help">{t("fix.rev.gre.via", { addr: `\u2066${viaLink.peer_addr}\u2069`, network: viaLink.network })}</span>}
            </div>
          )}
          {newLink && (
            <NewGreLinkFields
              id="fix-rip"
              ip={ip}
              onIp={setIp}
              ipLabel={t("fix.rev.gre.ip")}
              error={error}
              networks={networks}
              netId={netId}
              onNet={setNetId}
              panelPublic={panelPublic}
              kind={linkKind}
              onKind={setLinkKind}
            />
          )}
          {!greOn && (
            <div className="field">
              <label className="check">
                <input
                  type="checkbox"
                  id="fix-proxy"
                  checked={viaProxy}
                  disabled={proxyOn === false && !viaProxy}
                  onChange={(e) => {
                    setViaProxy(e.target.checked);
                    if (e.target.checked && (transport === "kcp" || transport === "quic")) setTransport("auto");
                    setError("");
                  }}
                />{" "}
                {t("add.rev.proxy")}
              </label>
              <span className="help">{proxyOn === false ? t("add.rev.proxy.off") : t("add.rev.proxy.d")}</span>
            </div>
          )}
          <div className="grid-2">
            {!greOn && (
              <div className="field">
                <label htmlFor="fix-rhost">{t("fix.rev.host")}</label>
                <input className="text mono" id="fix-rhost" dir="ltr" value={rhost} onChange={(e) => setRhost(e.target.value.trim())} />
                <span className="help">{t("add.rev.hostHelp")}</span>
              </div>
            )}
            <div className="field">
              <label htmlFor="fix-rport">{t("add.rev.port")}</label>
              <input className="text mono" id="fix-rport" dir="ltr" inputMode="numeric" value={rport} onChange={(e) => setRport(e.target.value.trim())} />
              <span className="help">{t("add.rev.portHelp")}</span>
            </div>
          </div>
          {!newLink && (
            <span className="err" role="alert">
              {error}
            </span>
          )}
          <div className="field">
            <span className="label">{t("fix.rev.protocol")}</span>
            <Seg<LinkTransport> value={transport} options={transports.map((x) => [x, t(`add.x.${x}`)] as [LinkTransport, string])} onChange={setTransport} />
            {portOk && (
              <span className="help">
                {t(greOn ? "fix.rev.gre.ports" : "fix.rev.ports")} <code dir="ltr">{linkPorts(+rport, transport)}</code>
              </span>
            )}
            <span className="help">{t(greOn ? "fix.rev.gre.help" : "fix.rev.help")}</span>
          </div>
          <div className="field">
            <span className="help">{t("fix.codeHelp")}</span>
          </div>
        </>
      )}

      {!code && way === "dial" && (
        <>
          <div className="field">
            <label htmlFor="fix-host">{t("add.host")}</label>
            {choices.length > 1 && (
              <div className="addr-picks" role="group" aria-label={t("add.host")}>
                {choices.map(([label, value]) => (
                  <button
                    key={value}
                    type="button"
                    className="addr-pick"
                    aria-pressed={host === value}
                    onClick={() => {
                      picked.current = true;
                      setHost(value);
                    }}
                  >
                    <span>{label}</span>
                    <code dir="ltr">{value}</code>
                  </button>
                ))}
              </div>
            )}
            <input className="text mono" id="fix-host" dir="ltr" value={host} onChange={(e) => setHost(e.target.value)} />
            <span className="help">{t("add.addrHelp")}</span>
            {greNow && <span className="help">{t("fix.greHelp", { network: greNow.network })}</span>}
            {!greNow && (own?.gre ?? []).some((g) => g.server === server.id) && <span className="help">{t("fix.greAvailable")}</span>}
            <span className="err">{error}</span>
          </div>
          <AgentPortField id="fix-port" value={ownPort} onChange={setOwnPort} main={port} />
          <div className="field">
            <span className="label">{t("fix.protocol")}</span>
            <Seg<LinkTransport> value={transport} options={TRANSPORTS.map((x) => [x, t(`add.x.${x}`)] as [LinkTransport, string])} onChange={setTransport} />
            <span className="help">{t(`add.x.${transport}.d`, { p: portText(transport) })}</span>
            <span className="help">{t("fix.protocolWhy")}</span>
            {transport !== "auto" && <span className="help">{t("add.newAgent")}</span>}
          </div>
          <div className="field">
            <span className="help">{t("fix.codeHelp")}</span>
          </div>
        </>
      )}

      {code && (
        <>
          {madeGre && (
            <div className="gre-made">
              <span className="badge">{t("srv.greChip", { kind: kindLabel(madeGre.kind), network: madeGre.network })}</span>
              {/* The addresses are isolated left to right, so a Persian sentence around them keeps its order. */}
              <span className="small">{t("add.gre.link", { panel: `\u2066${madeGre.panel_addr}\u2069`, server: `\u2066${madeGre.server_addr}\u2069`, name: `\u2068${madeGre.name}\u2069` })}</span>
              <span className="help">{t("fix.rev.gre.made", { addr: `\u2066${madeGre.server_addr}:${rport}\u2069` })}</span>
            </div>
          )}
          <div className="field">
            <span className="label">{t("fix.run")}</span>
            <CodeBlock text={`kariz-manager --agent ${code}`} />
            <span className="help">{t("fix.runHelp")}</span>
            <span className="label" style={{ marginTop: "var(--sp-3)" }}>
              {t("fix.runFresh")}
            </span>
            <CodeBlock text={`bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh) --agent ${code}`} />
            {transport !== "auto" && <span className="help">{t("add.via", { t: t(`add.x.${transport}`) })}</span>}
            <span className="countdown">{back ? "" : t("add.valid", { m: digitsOf(mmss) })}</span>
          </div>
          <div className={`waiting ${back ? "done" : ""}`}>
            <span>{back ? t("fix.connected", { name: live.name }) : wasOffline.current ? t("add.waiting") : t("fix.waitingOnline")}</span>
          </div>
        </>
      )}
    </Dialog>
  );
}
