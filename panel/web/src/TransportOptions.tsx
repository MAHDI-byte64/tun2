import type { FaketcpSpec, HelperSpec, IcmpSpec, SpoofSpec, StealthSpec } from "./api";
import { useApp } from "./store";
import { Icon } from "./ui";

/** A whole number from a text field, or undefined when it is empty or out of range. */
const num = (v: string, max: number): number | undefined => {
  const n = v.trim();
  return /^\d{1,6}$/.test(n) && +n >= 0 && +n <= max ? +n : undefined;
};
const str = (v: string): string | undefined => (v.trim() ? v.trim() : undefined);

// ---- stealth ----

export interface StealthState {
  padding: boolean;
  padMax: string;
  jitterMs: string;
}
export const emptyStealth = (): StealthState => ({ padding: true, padMax: "", jitterMs: "" });
export const stealthFrom = (s?: StealthSpec | null): StealthState => ({
  padding: s?.padding ?? true,
  padMax: s?.pad_max != null ? String(s.pad_max) : "",
  jitterMs: s?.jitter_ms != null ? String(s.jitter_ms) : "",
});
/** The `[tunnel.stealth]` spec to send, or nothing for another transport. */
export const stealthOf = (s: StealthState, transport: string): StealthSpec | undefined => {
  if (transport !== "stealth") return undefined;
  return { padding: s.padding, pad_max: num(s.padMax, 4096), jitter_ms: num(s.jitterMs, 1000) };
};

export function StealthOptions({ value, onChange }: { value: StealthState; onChange: (v: StealthState) => void }) {
  const { t } = useApp();
  return (
    <div className="field">
      <span className="label">{t("st.title")}</span>
      <label className="check">
        <input type="checkbox" checked={value.padding} onChange={(e) => onChange({ ...value, padding: e.target.checked })} /> {t("st.padding")}
      </label>
      <span className="help">{t("st.paddingHelp")}</span>
      <div className="row2" style={{ marginTop: "var(--sp-3)" }}>
        <label>
          {t("st.padMax")}
          <input className="text mono" dir="ltr" inputMode="numeric" value={value.padMax} placeholder="256" onChange={(e) => onChange({ ...value, padMax: e.target.value })} />
        </label>
        <label>
          {t("st.jitter")}
          <input className="text mono" dir="ltr" inputMode="numeric" value={value.jitterMs} placeholder="0" onChange={(e) => onChange({ ...value, jitterMs: e.target.value })} />
        </label>
      </div>
    </div>
  );
}

// ---- faketcp ----

export const FAKETCP_FLAGS = ["A", "PA", "PA,A", "PA,A,PA,PAU"] as const;
export interface FaketcpState {
  flags: string;
  manageFw: boolean;
}
export const emptyFaketcp = (): FaketcpState => ({ flags: "PA", manageFw: true });
export const faketcpFrom = (s?: FaketcpSpec | null): FaketcpState => ({
  flags: s?.flags ?? "PA",
  manageFw: s?.manage_firewall ?? true,
});
export const faketcpOf = (s: FaketcpState, transport: string): FaketcpSpec | undefined =>
  transport === "faketcp" ? { flags: s.flags, manage_firewall: s.manageFw } : undefined;

export function FaketcpOptions({ value, onChange }: { value: FaketcpState; onChange: (v: FaketcpState) => void }) {
  const { t } = useApp();
  return (
    <div className="field">
      <span className="label">{t("ft.title")}</span>
      <div className="field">
        <label htmlFor="ft-flags">{t("ft.flags")}</label>
        <select id="ft-flags" className="text mono" value={value.flags} onChange={(e) => onChange({ ...value, flags: e.target.value })}>
          {FAKETCP_FLAGS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <span className="help">{t("ft.flagsHelp")}</span>
      </div>
      <label className="check">
        <input type="checkbox" checked={value.manageFw} onChange={(e) => onChange({ ...value, manageFw: e.target.checked })} /> {t("ft.manageFw")}
      </label>
      <span className="help">{t("ft.manageFwHelp")}</span>
    </div>
  );
}

// ---- icmp ----

export interface IcmpState {
  manageFw: boolean;
}
export const emptyIcmp = (): IcmpState => ({ manageFw: true });
export const icmpFrom = (s?: IcmpSpec | null): IcmpState => ({ manageFw: s?.manage_firewall ?? true });
export const icmpOf = (s: IcmpState, transport: string): IcmpSpec | undefined => (transport === "icmp" ? { manage_firewall: s.manageFw } : undefined);

export function IcmpOptions({ value, onChange }: { value: IcmpState; onChange: (v: IcmpState) => void }) {
  const { t } = useApp();
  return (
    <div className="field">
      <span className="label">{t("ic.title")}</span>
      <label className="check">
        <input type="checkbox" checked={value.manageFw} onChange={(e) => onChange({ ...value, manageFw: e.target.checked })} /> {t("ic.manageFw")}
      </label>
      <span className="help">{t("ic.manageFwHelp")}</span>
    </div>
  );
}

// ---- spoof ----

export interface SpoofState {
  /** The entry server's forged-source list, as typed (IPs/CIDRs/ranges, per line or comma-separated). */
  entryPool: string;
  /** The exit server's forged-source list — the two servers never share a list. */
  exitPool: string;
  manageFw: boolean;
}
export const emptySpoof = (): SpoofState => ({ entryPool: "", exitPool: "", manageFw: true });
/** Rebuilds the two-list state from the two servers' resolved per-side specs (entry, exit). */
export const spoofFrom = (entry?: SpoofSpec | null, exit?: SpoofSpec | null): SpoofState => ({
  entryPool: (entry?.pool ?? []).join("\n"),
  exitPool: (exit?.pool ?? []).join("\n"),
  manageFw: entry?.manage_firewall ?? exit?.manage_firewall ?? true,
});

/** Splits the pool text into entries (one per line, comma or whitespace separated). */
export function parseSpoofPool(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

/** How many addresses a pool text expands to, for the hint (CIDR and ranges counted). */
export function spoofPoolCount(text: string): number {
  let n = 0;
  for (const e of parseSpoofPool(text)) {
    const cidr = e.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
    const range = e.match(/^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/);
    if (cidr) {
      const bits = +cidr[2];
      n += bits >= 31 ? 1 << (32 - bits) : (1 << (32 - bits)) - 2;
    } else if (range) {
      const lo = range[1].split(".").reduce((a, b) => a * 256 + +b, 0);
      const hi = range[2].split(".").reduce((a, b) => a * 256 + +b, 0);
      n += Math.max(0, hi - lo + 1);
    } else {
      n += 1;
    }
  }
  return n;
}

export const spoofOf = (s: SpoofState, shape: string, active: boolean, recvShape?: string): SpoofSpec | undefined =>
  active
    ? {
        shape,
        // Only when asymmetric and the two shapes differ (same shape is just symmetric).
        recv_shape: recvShape && recvShape !== shape ? recvShape : undefined,
        entry_pool: parseSpoofPool(s.entryPool),
        exit_pool: parseSpoofPool(s.exitPool),
        manage_firewall: s.manageFw,
      }
    : undefined;

export function SpoofOptions({
  value,
  onChange,
  entryName,
  exitName,
}: {
  value: SpoofState;
  onChange: (v: SpoofState) => void;
  entryName?: string;
  exitName?: string;
}) {
  const { t } = useApp();
  // Each server forges from its own list, so the two sides never share addresses.
  const poolField = (which: "entry" | "exit", server: string | undefined, text: string) => {
    const count = spoofPoolCount(text);
    const label = server ? t(`spf.poolFor`, { server }) : t(which === "entry" ? "spf.poolEntry" : "spf.poolExit");
    return (
      <div className="field">
        <label htmlFor={`sp-pool-${which}`}>{label}</label>
        <textarea
          id={`sp-pool-${which}`}
          className="text mono"
          rows={4}
          dir="ltr"
          spellCheck={false}
          placeholder={"203.0.113.10\n203.0.113.0/24\n198.51.100.1-198.51.100.9"}
          value={text}
          onChange={(e) => onChange(which === "entry" ? { ...value, entryPool: e.target.value } : { ...value, exitPool: e.target.value })}
        />
        <span className="help">{count > 0 ? t("spf.poolCount", { n: String(count) }) : t("spf.poolHelp")}</span>
      </div>
    );
  };
  return (
    <div className="field">
      <span className="label">{t("spf.title")}</span>
      <p className="help" style={{ margin: "0 0 var(--sp-2)" }}>
        {t("spf.twoLists")}
      </p>
      <div className="grid-2">
        {poolField("entry", entryName, value.entryPool)}
        {poolField("exit", exitName, value.exitPool)}
      </div>
      <label className="check">
        <input type="checkbox" checked={value.manageFw} onChange={(e) => onChange({ ...value, manageFw: e.target.checked })} /> {t("spf.manageFw")}
      </label>
      <span className="help">{t("spf.manageFwHelp")}</span>
      <p className="help" style={{ marginTop: "var(--sp-3)" }}>
        {t("spf.tip")}
      </p>
    </div>
  );
}

// ---- asymmetric (split) transport ----

/** The beautiful two-direction picker shown when a tunnel rides a different transport (or
 *  spoof shape) each way: a little flow diagram of the two servers and two colour-coded legs,
 *  with a tile row to choose each direction's transport. */
export function AsymmetricPicker({
  options,
  send,
  recv,
  onSend,
  onRecv,
  entryName,
  exitName,
  labelFor,
}: {
  options: readonly string[];
  send: string;
  recv: string;
  onSend: (v: string) => void;
  onRecv: (v: string) => void;
  entryName: string;
  exitName: string;
  /** The human description for a transport/shape value (from i18n). */
  labelFor: (x: string) => string;
}) {
  const { t } = useApp();
  const tiles = (value: string, onChange: (v: string) => void, which: "send" | "recv") => (
    <div className="tiles asym-tiles" role="radiogroup" aria-label={which === "send" ? t("asym.send.aria") : t("asym.recv.aria")}>
      {options.map((x) => (
        <button key={x} type="button" role="radio" aria-checked={value === x} className="tile" onClick={() => onChange(x)}>
          <span className="t1 mono">{x}</span>
          <span className="t2">{labelFor(x)}</span>
          <span className="tick">
            <Icon name="check" size={14} />
          </span>
        </button>
      ))}
    </div>
  );
  return (
    <div className="asym">
      <div className="asym-flow" aria-hidden="true">
        <div className="asym-leg">
          <span className="asym-node">{entryName}</span>
          <span className="asym-path send">
            <span className="asym-tag mono">{send}</span>
          </span>
          <span className="asym-node">{exitName}</span>
        </div>
        <div className="asym-leg rev">
          <span className="asym-node">{entryName}</span>
          <span className="asym-path recv">
            <span className="asym-tag mono">{recv}</span>
          </span>
          <span className="asym-node">{exitName}</span>
        </div>
      </div>
      <div className="field">
        <span className="asym-dir send">{t("asym.send", { from: entryName, to: exitName })}</span>
        {tiles(send, onSend, "send")}
      </div>
      <div className="field">
        <span className="asym-dir recv">{t("asym.recv", { from: exitName, to: entryName })}</span>
        {tiles(recv, onRecv, "recv")}
      </div>
    </div>
  );
}

// ---- managed helpers (naive / xhttp / reality) ----

export interface HelperState {
  binary: string;
  username: string;
  password: string;
  uuid: string;
  path: string;
  serverName: string;
  host: string;
  shortId: string;
  privateKey: string;
  publicKey: string;
  target: string;
  certificate: string;
  key: string;
  caFile: string;
}
export const emptyHelper = (): HelperState => ({
  binary: "",
  username: "",
  password: "",
  uuid: "",
  path: "/",
  serverName: "",
  host: "",
  shortId: "",
  privateKey: "",
  publicKey: "",
  target: "",
  certificate: "",
  key: "",
  caFile: "",
});
export const helperFrom = (s?: HelperSpec | null): HelperState => ({
  ...emptyHelper(),
  binary: s?.binary ?? "",
  username: s?.username ?? "",
  password: s?.password ?? "",
  uuid: s?.uuid ?? "",
  path: s?.path ?? "/",
  serverName: s?.server_name ?? "",
  host: s?.host ?? "",
  shortId: s?.short_id ?? "",
  privateKey: s?.private_key ?? "",
  publicKey: s?.public_key ?? "",
  target: s?.target ?? "",
  certificate: s?.certificate ?? "",
  key: s?.key ?? "",
  caFile: s?.ca_file ?? "",
});
/** The helper credentials to send for a helper transport. The panel splits them per side. */
export const helperOf = (s: HelperState, transport: string): HelperSpec | undefined => {
  if (!["naive", "xhttp", "reality"].includes(transport)) return undefined;
  return {
    binary: str(s.binary),
    username: str(s.username),
    password: str(s.password),
    uuid: str(s.uuid),
    path: str(s.path),
    server_name: str(s.serverName),
    host: str(s.host),
    short_id: str(s.shortId),
    private_key: str(s.privateKey),
    public_key: str(s.publicKey),
    target: str(s.target),
    certificate: str(s.certificate),
    key: str(s.key),
    ca_file: str(s.caFile),
  };
};

/** The credential fields a managed-helper transport collects. */
export function HelperFields({ transport, value, onChange }: { transport: string; value: HelperState; onChange: (v: HelperState) => void }) {
  const { t } = useApp();
  const set = (k: keyof HelperState) => (e: { target: { value: string } }) => onChange({ ...value, [k]: e.target.value });
  const field = (k: keyof HelperState, label: string, placeholder = "") => (
    <div className="field">
      <label htmlFor={`hl-${k}`}>{t(label)}</label>
      <input id={`hl-${k}`} className="text mono" dir="ltr" value={value[k]} placeholder={placeholder} onChange={set(k)} />
    </div>
  );
  return (
    <div className="field">
      <span className="label">{t("hl.title")}</span>
      <span className="help">{t(`hl.help.${transport}`)}</span>
      <div className="row2" style={{ marginTop: "var(--sp-3)" }}>
        {transport === "naive" && (
          <>
            {field("username", "hl.username")}
            {field("password", "hl.password")}
          </>
        )}
        {(transport === "xhttp" || transport === "reality") && field("uuid", "hl.uuid", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")}
        {transport === "xhttp" && field("path", "hl.path", "/stream")}
        {(transport === "xhttp" || transport === "reality") && field("serverName", "hl.serverName", "www.example.com")}
        {transport === "xhttp" && field("host", "hl.host", "cdn.example.com")}
        {transport === "reality" && field("shortId", "hl.shortId", "0123abcd")}
        {transport === "reality" && field("privateKey", "hl.privateKey")}
        {transport === "reality" && field("publicKey", "hl.publicKey")}
        {transport === "reality" && field("target", "hl.target", "www.microsoft.com:443")}
        {(transport === "naive" || transport === "xhttp") && field("certificate", "hl.certificate", "/etc/letsencrypt/live/…/fullchain.pem")}
        {(transport === "naive" || transport === "xhttp") && field("key", "hl.key", "/etc/letsencrypt/live/…/privkey.pem")}
        {field("caFile", "hl.caFile", "/etc/letsencrypt/live/…/chain.pem")}
        {field("binary", "hl.binary")}
      </div>
    </div>
  );
}

// ---- l3 / GRE ----

export const L3_CARRIERS = ["udp", "quic", "faketcp", "icmp", "proto47"] as const;
export interface L3State {
  carrier: string;
  layer: number;
  net: string;
  greKey: string;
  mtu: string;
}
export const emptyL3 = (): L3State => ({ carrier: "udp", layer: 3, net: "", greKey: "", mtu: "" });
export const l3From = (s?: { carrier: string; layer?: number; gre_key?: number; mtu?: number; local_ip?: string } | null): L3State => ({
  carrier: s?.carrier ?? "udp",
  layer: s?.layer ?? 3,
  // The `N` is read from the local address `10.10.N.x/30` when it is one.
  net: s?.local_ip?.match(/^10\.10\.(\d{1,3})\./)?.[1] ?? "",
  greKey: s?.gre_key ? String(s.gre_key) : "",
  mtu: s?.mtu ? String(s.mtu) : "",
});
/** The l3 fields a PairRequest carries (flat, not nested). */
export const l3Of = (s: L3State, transport: string) =>
  transport !== "l3"
    ? {}
    : {
        l3_carrier: s.carrier,
        l3_layer: s.layer,
        l3_net: num(s.net, 255),
        l3_gre_key: num(s.greKey, 4294967295),
        l3_mtu: num(s.mtu, 1500),
      };

/** The L3 / GRE options: which unreliable carrier, layer 3 (TUN) or 2 (TAP), and the address block. */
export function L3Options({ value, onChange }: { value: L3State; onChange: (v: L3State) => void }) {
  const { t } = useApp();
  return (
    <div className="field">
      <span className="label">{t("l3.title")}</span>
      <span className="help">{t("l3.help")}</span>
      <div className="field" style={{ marginTop: "var(--sp-3)" }}>
        <span className="label">{t("l3.carrier")}</span>
        <div className="tiles" role="radiogroup" aria-label={t("l3.carrier")}>
          {L3_CARRIERS.map((c) => (
            <button key={c} type="button" role="radio" aria-checked={value.carrier === c} className="tile" onClick={() => onChange({ ...value, carrier: c })}>
              <span className="t1 mono">{c}</span>
              <span className="t2">{t(`l3.carrier.${c}`)}</span>
              <span className="tick">
                <Icon name="check" size={14} />
              </span>
            </button>
          ))}
        </div>
      </div>
      <div className="field" style={{ marginTop: "var(--sp-3)" }}>
        <span className="label">{t("l3.layer")}</span>
        <div className="tiles" role="radiogroup" aria-label={t("l3.layer")}>
          {[3, 2].map((l) => (
            <button key={l} type="button" role="radio" aria-checked={value.layer === l} className="tile" onClick={() => onChange({ ...value, layer: l })}>
              <span className="t1">{t(`l3.layer.${l}`)}</span>
              <span className="t2">{t(`l3.layer.${l}.d`)}</span>
              <span className="tick">
                <Icon name="check" size={14} />
              </span>
            </button>
          ))}
        </div>
      </div>
      {value.layer === 3 && (
        <div className="field">
          <label htmlFor="l3-net">{t("l3.net")}</label>
          <input id="l3-net" className="text mono" dir="ltr" inputMode="numeric" value={value.net} placeholder={t("l3.netAuto")} onChange={(e) => onChange({ ...value, net: e.target.value })} />
          <span className="help">{value.net.trim() ? `10.10.${value.net.trim()}.0/30` : t("l3.netHelp")}</span>
        </div>
      )}
      <div className="row2">
        <label>
          {t("l3.mtu")}
          <input className="text mono" dir="ltr" inputMode="numeric" value={value.mtu} placeholder="1400" onChange={(e) => onChange({ ...value, mtu: e.target.value })} />
        </label>
        <label>
          {t("l3.greKey")}
          <input className="text mono" dir="ltr" inputMode="numeric" value={value.greKey} placeholder="0" onChange={(e) => onChange({ ...value, greKey: e.target.value })} />
        </label>
      </div>
    </div>
  );
}

// ---- the root-required note ----

/** A note that the picked transport needs root (raw sockets or a TUN device) on both servers. */
export function RootWarning() {
  const { t } = useApp();
  return (
    <div className="enc-warn" role="status" style={{ marginTop: "var(--sp-4)" }}>
      <Icon name="alert" size={18} />
      <div>
        <p>{t("tr.rootNeeded")}</p>
      </div>
    </div>
  );
}
