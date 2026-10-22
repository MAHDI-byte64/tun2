import { useEffect, useState } from "react";
import { ApiError, api } from "./api";
import type { ServerInfo, TunnelCopy } from "./api";
import { Checklist, opError, useOp } from "./ops";
import { useApp } from "./store";
import { Card, Icon, useAgo } from "./ui";

/** The tunnels the panel keeps a copy of that no server lists any more (a reinstalled server, a file removed by
 * hand): each can be made again from its copy, on the servers it was on or on others, or forgotten. */
export function MissingTunnels({ servers, copies, onChanged }: { servers: ServerInfo[]; copies: TunnelCopy[]; onChanged: () => void }) {
  const { t, toast } = useApp();
  const ago = useAgo();
  const missing = copies.filter((c) => !c.present);
  const [picking, setPicking] = useState<TunnelCopy | null>(null);
  const [entry, setEntry] = useState("");
  const [exit, setExit] = useState("");
  const [opId, setOpId] = useState<string | null>(null);
  const [opName, setOpName] = useState("");
  const [busy, setBusy] = useState("");
  const op = useOp(opId);
  const online = servers.filter((s) => s.online);
  const known = (id: string) => servers.some((s) => s.id === id);
  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? t("ms.goneServer");

  useEffect(() => {
    if (op && op.state !== "running") onChanged();
  }, [op?.state]); // eslint-disable-line react-hooks/exhaustive-deps

  if (missing.length === 0) return null;

  const start = (c: TunnelCopy) => {
    // The servers it was on, when they are still here and online; else the admin picks.
    const ok = (id: string) => servers.some((s) => s.id === id && s.online);
    if (ok(c.entry) && ok(c.exit)) {
      void recreate(c, c.entry, c.exit);
      return;
    }
    setEntry(ok(c.entry) ? c.entry : (online.find((s) => s.id !== c.exit)?.id ?? ""));
    setExit(ok(c.exit) ? c.exit : (online.find((s) => s.id !== c.entry && s.id !== entry)?.id ?? ""));
    setPicking(c);
  };
  const recreate = async (c: TunnelCopy, entryId: string, exitId: string) => {
    setBusy(c.name);
    try {
      const { op } = await api.recreateTunnel({ name: c.name, entry: entryId, exit: exitId });
      setOpName(c.name);
      setOpId(op);
      setPicking(null);
    } catch (e) {
      toast(e instanceof ApiError ? t("tun.failed", { why: opError(t, e.code) }) : String(e));
    } finally {
      setBusy("");
    }
  };
  const forget = async (c: TunnelCopy) => {
    setBusy(c.name);
    try {
      await api.forgetTunnelCopy(c.name);
      toast(t("ms.forgotten", { name: c.name }), "ok");
      onChanged();
    } catch (e) {
      toast(String(e));
    } finally {
      setBusy("");
    }
  };

  return (
    <Card title={t("ms.title")} sub={t("ms.sub")}>
      <ul className="ms-list">
        {missing.map((c) => (
          <li key={c.name} className="ms-row">
            <div className="ms-what">
              <b className="mono">{c.name}</b>
              <span className="muted small">
                {t("ms.where", { entry: serverName(c.entry), exit: serverName(c.exit) })} · {t("ms.updated", { ago: ago(Math.max(0, Date.now() / 1000 - c.updated)) })}
                {c.source === "server" && ` · ${t("ms.fromServers")}`}
              </span>
            </div>
            <div className="ar-row">
              <button className="btn btn-primary btn-sm" type="button" disabled={busy !== "" || online.length < 2} onClick={() => start(c)}>
                <Icon name="plus" size={16} />
                {t("ms.recreate")}
              </button>
              <button className="btn btn-ghost btn-sm" type="button" disabled={busy !== ""} onClick={() => void forget(c)}>
                <Icon name="trash" size={16} />
                {t("ms.forget")}
              </button>
            </div>
          </li>
        ))}
      </ul>
      {picking && (
        <div className="ms-pick">
          <p className="small">{t("ms.pickText", { name: picking.name })}</p>
          <div className="ar-row" style={{ flexWrap: "wrap" }}>
            <label className="field">
              <span className="label">{t("tun.side.entry")}</span>
              <select className="text" value={entry} onChange={(e) => setEntry(e.target.value)} aria-label={t("tun.side.entry")}>
                {online.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="label">{t("tun.side.exit")}</span>
              <select className="text" value={exit} onChange={(e) => setExit(e.target.value)} aria-label={t("tun.side.exit")}>
                {online.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn btn-primary btn-sm" type="button" disabled={!entry || !exit || entry === exit || busy !== ""} onClick={() => void recreate(picking, entry, exit)}>
              <Icon name="check" size={16} />
              {t("ms.recreate")}
            </button>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setPicking(null)}>
              {t("ms.cancel")}
            </button>
          </div>
          {(!known(picking.entry) || !known(picking.exit)) && <p className="muted small">{t("ms.goneHint")}</p>}
        </div>
      )}
      {op && (
        <div className="ms-op">
          <p className="small">{t("ms.making", { name: opName })}</p>
          <Checklist op={op} />
          {op.state === "done" && <p className="ok small">{t("tun.done")}</p>}
          {op.state === "failed" && <p className="err small">{t("tun.failed", { why: opError(t, op.error ?? "") })}</p>}
        </div>
      )}
    </Card>
  );
}
