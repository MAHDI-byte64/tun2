// The panel's JSON API. Addresses are relative, so the app works under any secret path.

export interface SessionInfo {
  authenticated: boolean;
  has_password: boolean;
  csrf?: string;
}

export interface Health {
  cpu_pct: number | null;
  mem_total: number | null;
  mem_used: number | null;
  rx_bps: number | null;
  tx_bps: number | null;
  uptime_secs: number | null;
  load1: number | null;
  /** IPv4 networks the server already routes. */
  routes?: string[];
}

/** The entry side's health probe (2.4): a connection made the way a user's is, to the target. */
export interface ProbeStatus {
  outcome: "ok" | "target_failed" | "failed" | "unsupported";
  ms: number | null;
  /** Empty: the tunnel alone (only UDP forwarded). */
  target: string;
  error: string | null;
  fails: number;
  target_fails: number;
  ok_total: number;
  failed_total: number;
  secs_ago: number;
}

export interface TunnelStatus {
  peer: {
    connected: boolean;
    transport?: string | null;
    sessions: number | null;
    rtt_ms: number | null;
    last_error: { secs_ago: number; text: string } | null;
    /** With mux (2.4): streams in use and how many the live connections take. */
    streams?: number | null;
    streams_max?: number | null;
    /** New connections that failed because every connection was full. */
    full?: number;
  };
  totals: { bytes_up: number; bytes_down: number; tcp_open: number; udp_flows: number };
  /** Marks one life of the byte counters (2.9.2): absent from older daemons, whose counters reset at every restart. */
  counter_id?: string | null;
  /** The entry's forward rules as they run: the counters of each (the bytes and the connections that went through it). */
  forwards?: {
    listen: string;
    target?: string;
    protocol?: string;
    tcp_open?: number;
    tcp_total?: number;
    udp_flows?: number;
    udp_total?: number;
    bytes_up?: number;
    bytes_down?: number;
    open_failures: number;
    refused_per_ip?: number;
  }[];
  probe?: ProbeStatus | null;
}

export interface TunnelInfo {
  name: string;
  role: string;
  mode: string;
  transport: string;
  profile: string;
  /** The tunnel's cipher setting; empty from an older agent. */
  encryption?: string;
  listen: string | null;
  remote: string | null;
  forwards: { listen: string; target: string; protocol: string }[];
  active: boolean | null;
  status: TunnelStatus | null;
  error: string | null;
  rate_mbps: number | null;
}

export interface Latency {
  sent: number;
  received: number;
  p50_ms: number;
  p99_ms: number;
  jitter_ms: number;
}

export interface Rate {
  mbps: number;
  peak_mbps: number;
  bytes: number;
}

/** What a speed test measured (`kariz::speedtest::Report`). */
/** One thing a benchmark measures: a transport, over a path, in a direction. */
export interface BenchCandidate {
  key: string;
  /** The core transport: tcpmux, kcp, ws, wss or quic. */
  transport: string;
  /** public, ipv6 (the public IPv6 addresses), or gre (across the private network link between the two servers). */
  path: "public" | "ipv6" | "gre" | "vxlan";
  /** The server name a wss candidate sends (none: none, as for an IP address); missing in an older result. */
  sni?: string | null;
  network: string | null;
  /** reverse (the entry listens) or direct (the exit listens). */
  mode: "reverse" | "direct";
  listener: string;
  host: string;
  port: number | null;
  state: "wait" | "probe" | "speed" | "ok" | "fail" | "skip";
  connect_ms: number | null;
  latency: Latency | null;
  download_mbps: number | null;
  upload_mbps: number | null;
  loaded: Latency | null;
  score: number | null;
  parts: { speed: number; latency: number; stability: number } | null;
  error: string | null;
}

/** A benchmark run between two servers. */
export interface Bench {
  id: string;
  entry: string;
  exit: string;
  profile: string;
  state: "probe" | "speed" | "done" | "stopped" | "failed";
  /** Unix milliseconds. */
  started: number;
  finished: number | null;
  candidates: BenchCandidate[];
  best: string | null;
  error: string | null;
  /** Whether IPv6 was measured: "tested", or "missing:ID" (that server has no public IPv6 address); missing in an older result. */
  ipv6?: string | null;
}

export interface SpeedReport {
  seconds: number;
  streams: number;
  idle: Latency;
  download: Rate;
  download_latency: Latency;
  upload: Rate;
  upload_latency: Latency;
  udp: Latency | null;
  notes: string[];
}

/** A speed test's answer; an older agent sends only `text`. */
export interface SpeedResult {
  ok: boolean;
  error: string | null;
  text: string;
  report?: SpeedReport | null;
}

/** A speed test that runs in the background (`start`), and what it has said since (`poll`). */
export interface SpeedStart {
  ok: boolean;
  error: string | null;
  id: string;
}
export interface SpeedPoll {
  ok: boolean;
  error: string | null;
  /** The progress lines of `kariz::speedtest::run`, after the ones already seen. */
  lines: string[];
  next: number;
  done: boolean;
  report: SpeedReport | null;
}

/** How an agent reaches the panel: `auto` tries every transport in turn. */
export type LinkTransport = "auto" | "tcpmux" | "kcp" | "wss" | "quic";

/** How a private network's links are made. */
export type LinkKind = "gre" | "vxlan";

/** A request to probe which forged source addresses get from one server to another. */
export interface IpTestAsk {
  from: string;
  to: string;
  shape: string;
  sources: string[];
  port?: number;
  count?: number;
  loss?: number;
}

/** One forged source address's result in an IP spoof test. */
export interface IpSourceResult {
  ip: string;
  received: number;
  ok: boolean;
}

/** The scored report of an IP spoof test. */
export interface IpReport {
  run_id: number;
  shape: string;
  expect: number;
  loss_pct: number;
  results: IpSourceResult[];
  usable: number;
  seen: number;
}

/** A saved IP-test result for a (from, to) pair. */
export interface IpSaved {
  from: string;
  to: string;
  created: number;
  report: IpReport;
}

/** Whether a benchmark path goes across a private network link (GRE or VXLAN). */
export const isPrivatePath = (path: string) => path === "gre" || path === "vxlan";

/** "GRE" or "VXLAN", as a label. */
export const kindLabel = (kind: LinkKind | undefined) => (kind === "vxlan" ? "VXLAN" : "GRE");

/** The panel's address on a private (GRE or VXLAN) network link to another server: what that server's agent can dial. */
export interface GreAddr {
  link: string;
  network: string;
  /** The other server (id). */
  server: string;
  addr: string;
  peer_addr: string;
  kind?: LinkKind;
}

export interface PanelAddresses {
  v4: string | null;
  v6: string | null;
  agent_port: number | null;
  gre?: GreAddr[];
  /** The panel server's public IPv4 address as private network links use it, if it is known. */
  gre_local?: string | null;
}

/** Where the panel dials a server it connects to (reverse): its agent listens on `port` and the next one. */
export interface ReverseTarget {
  host: string;
  port: number;
  /** The one link transport; none: all of them in turn. */
  transport?: string | null;
  /** Dialed through the panel's SOCKS5 proxy (Settings → Proxy). */
  via_proxy?: boolean;
}

/** A GRE link the panel is to make to a server: its public IPv4 address, and the network that gives the addresses (none: the first, or a new one). */
export interface NewGreLink {
  ip: string;
  network?: string;
  /** Without a network, the first one of this kind (or a new one). */
  kind?: LinkKind;
}

/** What *Add server* over a private network made: the server (waiting for its agent) and its code. */
export interface GreJoin {
  code: string;
  valid_for: number;
  id: string;
  name: string;
  /** The private network the link's addresses come from. */
  network: string;
  /** The panel's end of the link (what the agent dials) and the new server's. */
  panel_addr: string;
  server_addr: string;
  kind?: LinkKind;
}

export interface LinkError {
  at: number;
  /** `link_ended`: the link dropped or went quiet. `wrong_key`: an agent came with this server's id and a key that does not match. */
  kind: "link_ended" | "wrong_key" | "proxy_off";
  detail: string;
}

/** An automatic restart of a tunnel (by name) or of the running tunnels of a server (by id). */
export interface ScheduleRow {
  kind: "tunnel" | "server";
  subject: string;
  mode: "every" | "daily";
  every_secs: number;
  /** For `daily`: minutes after midnight, UTC. */
  daily_min: number;
  enabled: boolean;
  since: number;
  last_run: number;
  /** `ok`, `ok:N`, `skipped_offline`, `skipped_stopped`, `skipped_none`, `busy`, `missed`, or `failed:` and why. */
  last_result: string;
  next_run: number | null;
}

/** A tunnel's traffic limit and the usage the panel adds up (`/api/quotas`). */
export interface QuotaRow {
  name: string;
  limit_bytes: number;
  used: number;
  /** 0: reset by hand; 1..28: every month on that day (00:00 UTC). */
  reset_day: number;
  last_reset: number;
  warned: boolean;
  /** When the limit stopped the tunnel (0: it did not). */
  stopped: number;
  /** The panel still has to start it again (a server was away, or the tunnel busy). */
  start_due: boolean;
  since: number;
  next_reset: number | null;
  pct: number;
  /** When the limit ends (unix seconds; 0: it does not): the tunnel is stopped then, until it is extended. */
  expires_at: number;
  /** When the end stopped the tunnel (0: it did not). */
  expired: number;
  /** The renter's page, when one was made. */
  share: { token: string; title: string; created: number; views: number } | null;
}

export interface QuotaBody {
  name: string;
  /** 0: a limit of time alone. */
  limit_bytes: number;
  reset_day: number;
  /** An end this many days from now, or at a time. */
  days?: number;
  expires_at?: number;
}

export interface ScheduleBody {
  kind: "tunnel" | "server";
  subject: string;
  mode: "every" | "daily";
  every_secs?: number;
  daily_min?: number;
  enabled: boolean;
}

export interface ServerInfo {
  id: string;
  name: string;
  local: boolean;
  online: boolean;
  version: string;
  arch: string;
  hostname: string;
  /** The address other servers reach it at (private networks), if one was set. */
  addr: string | null;
  /** The address it is known by (public IPv4, else IPv6): what private networks use until one is set. */
  addr_default?: string | null;
  seen_secs: number | null;
  /** When the panel last heard from it (unix seconds), also from before the panel started. */
  last_seen?: number | null;
  /** Why its link last ended or was refused, until it connects again. */
  last_error?: LinkError | null;
  /** The private network link its agent connects through, when it does. */
  gre?: { link: string; network: string; kind?: LinkKind } | null;
  /** Where the panel dials it, for a server the panel connects to (reverse). */
  reverse?: ReverseTarget | null;
  /** An agents port of its own its agent dials, if it has one. */
  agent_port?: number | null;
  /** The transport its agent's link uses now (tcpmux or kcp). */
  link?: string | null;
  health: Health | null;
  /** Its public IPv4 and IPv6 addresses, when known. */
  ip4?: string | null;
  ip6?: string | null;
  tunnels: TunnelInfo[];
}

export interface SessionRow {
  id: number;
  ip: string;
  agent: string;
  created: number;
  last_seen: number;
  current: boolean;
}

export interface ForwardSpec {
  listen: string;
  target: string;
  protocol: string;
}

/** What the wizard sends: one tunnel, both sides. */
/** A tunnel's mux settings; what is left out keeps the profile's value. */
export interface MuxSpec {
  /** Only ever false: mux off for ws, wss or kcp. */
  enabled?: boolean;
  connections?: number;
  max_streams?: number;
  /** Bytes. */
  stream_window?: number;
  max_lifetime_secs?: number;
  ping_interval_secs?: number;
  coalesce?: boolean;
}

export interface PairRequest {
  /** A traffic limit for the new tunnel (the wizard): bytes, and the day of the month the usage resets on (0: by hand). */
  quota?: { limit_bytes: number; reset_day: number; days?: number };
  /** A server (entry or exit) the panel cannot reach: write the other side and hand over this one's config. */
  manual?: string;
  name: string;
  entry: string;
  exit: string;
  mode: string;
  transport: string;
  profile?: string;
  listen: string;
  dial: string;
  pool?: number;
  ws_path?: string;
  ws_host?: string;
  tls_sni?: string;
  mux?: MuxSpec;
  /** wss: the files of a real certificate on the listening side. */
  tls_cert?: string;
  tls_key?: string;
  /** wss with a real certificate: the name it was issued for, which the dialing side checks it against. */
  tls_host?: string;
  /** `auto` (left out), `aes-256-gcm`, `chacha20-poly1305` or `none`. */
  encryption?: string;
  /** quic: seal every UDP packet with a key from the token (`[tunnel.quic] obfs`). */
  quic_obfs?: boolean;
  /** quic: a fixed send rate in Mbit/s (`[tunnel.quic] congestion = "fixed"`). */
  quic_bandwidth?: number;
  /** The entry side's limit of open connections per client address; left out or 0: none. */
  max_conns_per_ip?: number;
  /** The entry side's UDP flows (clients) per port; left out: the default (4096). */
  udp_max_flows?: number;
  /** `v1` or `v2`: the target gets a PROXY header with each user's address on every TCP port; left out: none. */
  proxy_protocol?: string;
  forwards: ForwardSpec[];
  rotate?: boolean;
  /** Direct mode: run over this private GRE network (its id). */
  network?: string;
  /** stealth: record padding and timing jitter. */
  stealth?: StealthSpec;
  /** faketcp: the fake-TCP carrier knobs. */
  faketcp?: FaketcpSpec;
  /** icmp: the ICMP carrier knobs. */
  icmp?: IcmpSpec;
  /** spoof: the source-spoofing carrier knobs (shape, forged-source pool). */
  spoof?: SpoofSpec;
  /** naive / xhttp / reality: the managed-helper credentials (split per side by the panel). */
  helper?: HelperSpec;
  /** l3: the carrier the sealed GRE rides (`udp`, `quic`, `faketcp` or `icmp`). */
  l3_carrier?: string;
  /** l3: `3` (TUN, IP packets) or `2` (TAP, Ethernet frames). */
  l3_layer?: number;
  /** l3 layer 3: the `N` of the auto-picked `10.10.N.0/30`. Left out: picked from the name. */
  l3_net?: number;
  /** l3: the RFC 2890 GRE key, the same on both sides. */
  l3_gre_key?: number;
  /** l3: the TUN/TAP MTU. */
  l3_mtu?: number;
}

/** stealth: record-length padding and timing jitter (`[tunnel.stealth]`). */
export interface StealthSpec {
  padding?: boolean;
  /** Largest padding a record carries, in bytes. */
  pad_max?: number;
  /** Random delay before a record is flushed, in milliseconds. */
  jitter_ms?: number;
}

/** faketcp: the raw-socket fake-TCP carrier knobs (`[tunnel.faketcp]`). */
export interface FaketcpSpec {
  /** The TCP flag pattern (`A`, `PA`, `PA,A`, `PA,A,PA,PAU`). */
  flags?: string;
  /** Install and remove the iptables rules (RAII). */
  manage_firewall?: boolean;
}

/** icmp: the ICMP-echo carrier knobs (`[tunnel.icmp]`). */
export interface IcmpSpec {
  manage_firewall?: boolean;
}

/** spoof: the source-spoofing carrier knobs (`[tunnel.spoof]`). */
export interface SpoofSpec {
  /** The on-wire packet shape: `udp`, `tcp`, `icmp`, `gre`, `ipip` or `proto58`. */
  shape?: string;
  /** This side's resolved forged-source list (IPs, CIDR blocks or `a-b` ranges). Set per
   * side by the panel; on a wizard request the two servers' lists go in entry_pool/exit_pool. */
  pool?: string[];
  /** Wizard-only: the entry server's forged-source list. */
  entry_pool?: string[];
  /** Wizard-only: the exit server's forged-source list. */
  exit_pool?: string[];
  /** The peer's real address (filled in by the panel for the accepting side). */
  peer?: string;
  /** Install and remove the best-effort iptables rules (RAII). */
  manage_firewall?: boolean;
}

/** naive / xhttp / reality: the managed-helper credentials (`[tunnel.helper]`). */
export interface HelperSpec {
  binary?: string;
  /** naive. */
  username?: string;
  password?: string;
  /** xhttp / reality. */
  uuid?: string;
  /** xhttp. */
  path?: string;
  /** xhttp / reality. */
  server_name?: string;
  /** xhttp. */
  host?: string;
  /** reality: hex, even length, at most 16. */
  short_id?: string;
  /** reality acceptor: X25519 private key (base64url). */
  private_key?: string;
  /** reality dialer: X25519 public key (base64url). */
  public_key?: string;
  /** reality acceptor: cover target `host:port`. */
  target?: string;
  /** naive / xhttp acceptor TLS. */
  certificate?: string;
  key?: string;
  /** dialer: a CA bundle to trust. */
  ca_file?: string;
}

/** One side of a tunnel as an agent keeps it (never with its token). */
export interface Spec {
  name: string;
  role: string;
  mode: string;
  transport: string;
  profile?: string;
  listen?: string;
  remote?: string;
  pool?: number;
  ws_path?: string;
  ws_host?: string;
  tls_sni?: string;
  tls_pin?: string;
  mux?: MuxSpec;
  tls_cert?: string;
  tls_key?: string;
  encryption?: string;
  quic_obfs?: boolean;
  quic_bandwidth?: number;
  max_conns_per_ip?: number;
  udp_max_flows?: number;
  proxy_protocol?: string;
  forwards: ForwardSpec[];
  stealth?: StealthSpec;
  faketcp?: FaketcpSpec;
  icmp?: IcmpSpec;
  spoof?: SpoofSpec;
  helper?: HelperSpec;
  l3?: L3Spec;
}

/** l3: the GRE direct-tunnel settings an agent keeps (`[l3]`), this side's. */
export interface L3Spec {
  carrier: string;
  layer?: number;
  local_ip?: string;
  peer_ip?: string;
  gre_key?: number;
  mtu?: number;
  accept_udp?: boolean;
}

export interface PortOwner {
  proto: string;
  addr: string;
  port: number;
  process: string | null;
  pid: number | null;
}

export interface CheckReply {
  ok: boolean;
  error?: string;
  warnings: string[];
  conflicts: PortOwner[];
}

export interface Step {
  id: string;
  state: "run" | "ok" | "fail";
  detail: string | null;
}

export interface Op {
  id: string;
  kind: "create" | "edit" | "control" | "delete";
  name: string;
  state: "running" | "done" | "failed";
  steps: Step[];
  error: string | null;
  undone: boolean | null;
  /** Servers that could not be reached and were left out. */
  offline?: string[];
  /** A side to set up by hand (shown once, carries the token). */
  bundle?: ManualBundle;
}

/** Everything to bring up a tunnel side by hand, on a server the panel could not reach. */
export interface ManualBundle {
  server: string;
  role: "entry" | "exit";
  /** The file to write as `/etc/kariz/NAME.toml` (its token is inside). */
  config: string;
  /** A self-signed wss side also needs these, as NAME.crt and NAME.key. */
  cert?: string;
  key?: string;
  /** The shell commands to write the files and start the service. */
  commands: string;
}

/** One tunnel waiting for a side set up by hand. */
export interface ManualPending {
  name: string;
  role: "entry" | "exit";
  server: string;
  created: number;
}

/** The panel's copy of a tunnel's settings (kept at each create or edit, or read back from the servers). */
export interface TunnelCopy {
  name: string;
  entry: string;
  exit: string;
  updated: number;
  source: "panel" | "server";
  /** Some server still lists the tunnel. */
  present: boolean;
}

export interface EventRow {
  id: number;
  at: number;
  kind: string;
  subject: string;
  detail: string;
}

export interface LogLine {
  server: string;
  role: string;
  text: string;
}

export interface Network {
  id: string;
  name: string;
  cidr: string;
  /** GRE, or VXLAN over UDP `port` (0 for GRE). */
  kind: LinkKind;
  port: number;
  created: number;
  links: number;
  capacity: number;
}

export interface Link {
  id: string;
  network: string;
  a: string;
  b: string;
  subnet: string;
  addr_a: string;
  addr_b: string;
  /** The GRE key, or for VXLAN the VNI. */
  gre_key: number;
  ifname: string;
  kind: LinkKind;
  port: number;
}

export interface UpdateStatus {
  current: string;
  configured: boolean;
  channel: "stable" | "beta";
  auto: boolean;
  state: "none" | "newer" | "same" | "older";
  major: boolean;
  latest: { tag: string; version: string; notes: string; prerelease: boolean } | null;
  checked_at: number | null;
  error: string | null;
  last_result: { version: string; ok: boolean; rolled_back: boolean; error: string | null; at: number } | null;
  busy: boolean;
  /** Servers whose agent is older than this panel. */
  outdated: { id: string; name: string; version: string; online: boolean }[];
}

/** The Telegram bot's settings as the panel shows them: the token itself is never sent. */
export interface TelegramView {
  enabled: boolean;
  token_set: boolean;
  token_tail: string;
  chats: { id: number; name: string }[];
  lang: "fa" | "en";
  servers: boolean;
  tunnels: boolean;
  server_grace: number;
  tunnel_grace: number;
  digest_hours: number;
  api_base: string;
  proxy: string;
  connect_via: string;
  muted_until: number | null;
  pair: { code: string; expires_in: number } | null;
  last_ok: number | null;
  last_error: string | null;
}

export type TelegramChange = Partial<
  Pick<TelegramView, "enabled" | "lang" | "servers" | "tunnels" | "server_grace" | "tunnel_grace" | "digest_hours" | "api_base" | "proxy" | "connect_via">
> & { token?: string; remove_token?: boolean };

export interface ProxyView {
  enabled: boolean;
  addr: string;
  username: string;
  has_password: boolean;
  panel_internet: boolean;
}

export interface MetricsView {
  enabled: boolean;
  token: string;
}

export type ProxyChange = Partial<Pick<ProxyView, "enabled" | "addr" | "username" | "panel_internet">> & {
  password?: string;
  remove_password?: boolean;
};

export class ApiError extends Error {
  status: number;
  code: string;
  body: Record<string, unknown>;
  constructor(status: number, body: Record<string, unknown>) {
    super(String(body.error ?? status));
    this.status = status;
    this.code = String(body.error ?? "error");
    this.body = body;
  }
}

let csrf = "";

/** The session's CSRF value, for a request made outside `call` (the terminal's WebSocket). */
export function csrfToken(): string {
  return csrf;
}

export function setCsrf(value: string | undefined) {
  csrf = value ?? "";
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers["X-Kariz-CSRF"] = csrf;
  const response = await fetch(`./api/${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: Record<string, unknown> = {};
  try {
    data = await response.json();
  } catch {
    // an empty or non-JSON answer
  }
  if (!response.ok) throw new ApiError(response.status, data);
  return data as T;
}

export const api = {
  session: () => call<SessionInfo>("GET", "session"),
  login: (password: string) => call<{ csrf: string }>("POST", "login", { password }),
  loginWithLink: (token: string) => call<{ csrf: string }>("POST", "link", { token }),
  logout: () => call<object>("POST", "logout"),
  servers: () => call<{ servers: ServerInfo[]; agents: boolean }>("GET", "servers"),
  /** With `port`, the server gets an agents port of its own (and is listed now, waiting for its agent). */
  joinCode: (name: string | undefined, host: string, transport: LinkTransport, port?: number) =>
    call<{ code: string; valid_for: number; id?: string; name?: string; port?: number }>("POST", "servers/join-code", { name, host, transport, port }),
  panelAddresses: () => call<PanelAddresses>("GET", "servers/panel-addresses"),
  /** With `port`, the server's agent dials an agents port of its own across the link. */
  joinGre: (name: string | undefined, ip: string, network: string | undefined, transport: LinkTransport, kind: LinkKind = "gre", port?: number) =>
    call<GreJoin>("POST", "servers/join-gre", { name, ip, network, transport, kind, port }),
  removeServer: (id: string) => call<object>("POST", "servers/remove", { id }),
  /** With `gre`, a GRE link to the server is made first and the link to the panel goes across it (the answer then says what was made). */
  /** `port`: the agents port its agent dials (the panel's own clears a port of its own; left out: unchanged). */
  reconnectServer: (id: string, host: string, transport: LinkTransport, reverse?: { host: string; port: number; via_proxy?: boolean }, gre?: NewGreLink, port?: number) =>
    call<{ code: string; valid_for: number } & Partial<GreJoin>>("POST", "servers/reconnect", { id, host, transport, reverse, gre, port }),
  /** With `gre`, the panel makes a GRE link to the new server and dials it across that link (`host` is not used). */
  joinReverse: (name: string | undefined, host: string, port: number, transport: LinkTransport, gre?: NewGreLink, via_proxy?: boolean) =>
    call<{ code: string; valid_for: number; id: string; name: string } & Partial<GreJoin>>("POST", "servers/join-reverse", { name, host, port, transport, gre, via_proxy }),
  renameServer: (id: string, name: string) => call<object>("POST", "servers/rename", { id, name }),
  /** Every server's id once (the panel's own, `local`, too), in the order every list shows them. */
  orderServers: (ids: string[]) => call<object>("POST", "servers/order", { ids }),
  schedules: () => call<{ schedules: ScheduleRow[] }>("GET", "schedules"),
  setSchedule: (body: ScheduleBody) => call<object>("POST", "schedules", body),
  deleteSchedule: (kind: string, subject: string) => call<object>("POST", "schedules/delete", { kind, subject }),
  runSchedule: (kind: string, subject: string) => call<object>("POST", "schedules/run", { kind, subject }),
  quotas: () => call<{ quotas: QuotaRow[] }>("GET", "quotas"),
  setQuota: (body: QuotaBody) => call<object>("POST", "quotas", body),
  deleteQuota: (name: string) => call<object>("POST", "quotas/delete", { name }),
  resetQuota: (name: string) => call<object>("POST", "quotas/reset", { name }),
  extendQuota: (name: string, days: number) => call<object>("POST", "quotas/extend", { name, days }),
  shareQuota: (name: string, title: string) => call<{ token: string; title: string }>("POST", "quotas/share", { name, title }),
  unshareQuota: (name: string) => call<object>("POST", "quotas/share/delete", { name }),
  sessions: () => call<{ sessions: SessionRow[] }>("GET", "sessions"),
  revoke: (id: number) => call<object>("POST", "sessions/revoke", { id }),
  changePassword: (current: string | undefined, next: string) =>
    call<object>("POST", "password", { current, new: next }),
  tunnelCert: (server: string, host: string, email?: string) =>
    call<{ ok: boolean; error: string | null; cert: string | null; key: string | null }>("POST", "tunnels/cert", { server, host, email }),
  tunnelCheck: (body: PairRequest) => call<{ entry: CheckReply; exit: CheckReply }>("POST", "tunnels/check", body),
  createTunnel: (body: PairRequest) => call<{ op: string }>("POST", "tunnels", body),
  editTunnel: (body: PairRequest) => call<{ op: string }>("POST", "tunnels/edit", body),
  controlTunnel: (name: string, action: "start" | "stop" | "restart") => call<{ op: string }>("POST", "tunnels/control", { name, action }),
  deleteTunnel: (name: string) => call<{ op: string }>("POST", "tunnels/delete", { name }),
  tunnelCopies: () => call<{ specs: TunnelCopy[] }>("GET", "tunnels/specs"),
  tunnelManual: () => call<{ pending: ManualPending[] }>("GET", "tunnels/manual"),
  recreateTunnel: (body: { name: string; entry?: string; exit?: string }) => call<{ op: string }>("POST", "tunnels/recreate", body),
  forgetTunnelCopy: (name: string) => call<{ ok?: boolean }>("POST", "tunnels/specs/delete", { name }),
  tunnelSpec: (server: string, name: string) =>
    call<Spec>("GET", `tunnel?server=${encodeURIComponent(server)}&name=${encodeURIComponent(name)}`),
  op: (id: string) => call<Op>("GET", `op?id=${encodeURIComponent(id)}`),
  ports: (server: string) => call<{ ports: PortOwner[] }>("GET", `ports?server=${encodeURIComponent(server)}`),
  history: (key: string, range: string) => call<{ points: [number, number][] }>("GET", `history?key=${encodeURIComponent(key)}&range=${range}`),
  events: (limit = 100) => call<{ events: EventRow[] }>("GET", `events?limit=${limit}`),
  logs: (name: string, lines = 200) => call<{ lines: LogLine[] }>("GET", `logs?name=${encodeURIComponent(name)}&lines=${lines}`),
  benchStart: (entry: string, exit: string, profile: string, port: number, sni?: string) =>
    call<{ id: string }>("POST", "bench", { entry, exit, profile, port, ...(sni ? { sni } : {}) }),
  benchState: (id: string) => call<Bench>("GET", `bench?id=${encodeURIComponent(id)}`),
  benchStop: (id: string) => call<object>("POST", "bench/stop", { id }),
  benchLast: (entry: string, exit: string) => call<{ bench: Bench | null }>("GET", `bench/last?entry=${encodeURIComponent(entry)}&exit=${encodeURIComponent(exit)}`),
  ipTest: (body: IpTestAsk) => call<{ report: IpReport }>("POST", "iptest", body),
  ipTestLast: (from: string, to: string) =>
    call<{ iptest: IpSaved | null }>("GET", `iptest/last?entry=${encodeURIComponent(from)}&exit=${encodeURIComponent(to)}`),
  speedtestStart: (name: string, seconds: number, streams: number, udp: boolean) =>
    call<SpeedStart>("POST", "tunnels/speedtest/start", { name, seconds, streams, udp }),
  speedtestStop: (name: string, id: string) => call<{ ok: boolean }>("POST", "tunnels/speedtest/stop", { name, id }),
  speedtestPoll: (name: string, id: string, after: number) => call<SpeedPoll>("POST", "tunnels/speedtest/poll", { name, id, after }),
  speedtest: (name: string, seconds: number, streams: number, udp: boolean) =>
    call<SpeedResult>("POST", "tunnels/speedtest", { name, seconds, streams, udp }),
  backup: (passphrase: string) => call<{ data: string }>("POST", "backup", { passphrase }),
  restore: (passphrase: string, data: string, replace: boolean) => call<{ servers: number; restart: boolean }>("POST", "restore", { passphrase, data, replace }),
  networks: () => call<{ networks: Network[]; links: Link[] }>("GET", "networks"),
  createNetwork: (name: string, cidr: string, kind: LinkKind = "gre", port?: number) =>
    call<Network>("POST", "networks", { name, cidr, kind, ...(kind === "vxlan" && port ? { port } : {}) }),
  deleteNetwork: (id: string) => call<object>("POST", "networks/delete", { id }),
  createLinks: (network: string, servers: string[], hub?: string) => call<{ op: string }>("POST", "networks/links", { network, servers, hub }),
  deleteLink: (id: string) => call<object>("POST", "networks/links/delete", { id }),
  setAddress: (id: string, addr: string) => call<object>("POST", "servers/address", { id, addr }),
  update: () => call<UpdateStatus>("GET", "update"),
  checkUpdate: () => call<UpdateStatus>("POST", "update/check", {}),
  updateSettings: (body: { channel?: "stable" | "beta"; auto?: boolean }) => call<UpdateStatus>("POST", "update/settings", body),
  telegram: () => call<TelegramView>("GET", "telegram"),
  telegramSet: (body: TelegramChange) => call<TelegramView>("POST", "telegram", body),
  telegramPair: () => call<TelegramView>("POST", "telegram/pair", {}),
  telegramRemoveChat: (id: number) => call<TelegramView>("POST", "telegram/chats/remove", { id }),
  telegramTest: () => call<{ ok: boolean; bot?: string; error?: string }>("POST", "telegram/test", {}),
  proxy: () => call<ProxyView>("GET", "proxy"),
  proxySet: (body: ProxyChange) => call<ProxyView>("POST", "proxy", body),
  metrics: () => call<MetricsView>("GET", "metrics"),
  metricsSet: (action: "enable" | "disable" | "regenerate") => call<MetricsView>("POST", "metrics", { action }),
  applyUpdate: (confirm_major: boolean) => call<{ op: string }>("POST", "update/apply", { confirm_major }),
  updateServers: (restart_tunnels: boolean) => call<{ op: string }>("POST", "update/servers", { restart_tunnels }),
  newLink: () => call<{ token: string; valid_for: number }>("POST", "links"),
};
