import type { MuxSpec } from "./api";

/** The transports a person chooses from. `tcp` with mux on is the core's `tcpmux`; with mux off, plain `tcp`. */
export const TRANSPORTS = [
  "auto",
  "tcp",
  "stealth",
  "ws",
  "wss",
  "wsmux",
  "wssmux",
  "quic",
  "kcp",
  "udp",
  "faketcp",
  "icmp",
  "naive",
  "xhttp",
  "reality",
  "l3",
] as const;

/** Transports that need root (raw sockets or a TUN device). The wizard warns when one is picked. */
export const ROOT_ONLY = ["faketcp", "icmp", "l3"];

/** Transports whose own encryption is the tunnel's, so `encryption = "none"` is refused. */
export const ENCRYPTION_FORCED = ["stealth", "udp", "faketcp", "icmp", "l3"];

/** The managed-helper transports (a sing-box / Xray process carries the tunnel). */
export const HELPER_TRANSPORTS = ["naive", "xhttp", "reality"];

/** Transports where mux can be turned off (`auto`, `quic`, the `*mux` twins and the KCP
 *  carriers always multiplex or do not multiplex at all). */
export const MUX_OPTIONAL = ["tcp", "ws", "wss", "kcp", "stealth"];

/** A tunnel's core transport (and mux settings) as the form shows them: a transport and whether mux is on. */
export function splitTransport(core: string, mux?: MuxSpec | null): { transport: string; mux: boolean } {
  if (core === "tcpmux") return { transport: "tcp", mux: true };
  if (core === "tcp") return { transport: "tcp", mux: false };
  return { transport: core, mux: mux?.enabled ?? true };
}

/** The form's transport and mux switch as the core's transport, and the `enabled` to write (left out where the default is right). */
export function joinTransport(transport: string, mux: boolean): { core: string; enabled?: boolean } {
  if (transport === "tcp") return { core: mux ? "tcpmux" : "tcp" };
  if (!mux && MUX_OPTIONAL.includes(transport)) return { core: transport, enabled: false };
  return { core: transport };
}

/** The ports a management link uses on `port` (TCP and UDP, and the next one), for a firewall: all of them for auto, else the one transport's. */
export function linkPorts(port: number, transport: string): string {
  if (transport === "auto") return `TCP ${port}, UDP ${port}, TCP ${port + 1}, UDP ${port + 1}`;
  if (transport === "kcp") return `UDP ${port}`;
  if (transport === "quic") return `UDP ${port + 1}`;
  if (transport === "wss") return `TCP ${port + 1}`;
  return `TCP ${port}`;
}

/** Whether `host` and `port` can be where the panel dials a server (reverse): an IP address or a host name, and a port with one after it. */
export function reverseOk(host: string, port: string): boolean {
  const h = host.trim();
  return /^[A-Za-z0-9.\-:\[\]]{1,253}$/.test(h) && /^\d{1,5}$/.test(port.trim()) && +port >= 1 && +port <= 65534;
}

/** `host:port`, an IPv6 address in brackets. */
export const hostPort = (host: string, port: number | string) => (host.includes(":") && !host.startsWith("[") ? `[${host}]:${port}` : `${host}:${port}`);

/** The transport as a list shows it: `tcpmux` is just tcp, and an auto tunnel says what it uses now. */
export function transportLabel(core: string, via?: string | null): string {
  if (core === "auto") return via ? `auto → ${via.replace(/tcpmux/g, "tcp")}` : "auto";
  if (core === "l3") return "L3 / GRE";
  return core === "tcpmux" ? "tcp" : core === "tcp" ? "tcp · no mux" : core;
}
