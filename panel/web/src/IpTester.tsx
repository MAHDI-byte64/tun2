import { useEffect, useMemo, useState } from "react";
import { ApiError, api } from "./api";
import type { IpReport, ServerInfo } from "./api";
import { copyText } from "./clipboard";
import { useApp } from "./store";
import { Card, Empty, Icon } from "./ui";
import { SPOOF_SHAPES } from "./transport";
import { parseSpoofPool } from "./TransportOptions";

/** A backend error code turned into a friendly message. */
function reason(t: (k: string, v?: Record<string, string>) => string, error: string, name: (id: string) => string): string {
  const [head, arg] = error.split(":");
  switch (head) {
    case "same_server":
      return t("ipt.sameServer");
    case "bad_input":
      return t("ipt.badInput");
    case "offline":
      return t("ipt.offline", { name: name(arg ?? "") });
    case "not_ipv4":
      return t("ipt.notIpv4", { name: name(arg ?? "") });
    case "no_address":
      return t("ipt.noAddr", { name: name(arg ?? "") });
    case "sender":
      return t("ipt.senderErr", { why: error.slice(head.length + 1) });
    case "receiver":
      return t("ipt.receiverErr", { why: error.slice(head.length + 1) });
    default:
      return error;
  }
}

export function IpTesterPage({ servers, loaded }: { servers: ServerInfo[]; loaded: boolean }) {
  const { t, num, toast } = useApp();
  const usable = useMemo(() => servers.filter((s) => s.online || s.local), [servers]);
  const name = (id: string) => servers.find((s) => s.id === id)?.name ?? id;

  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [shape, setShape] = useState<string>("udp");
  const [sources, setSources] = useState("");
  const [loss, setLoss] = useState("20");
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<IpReport | null>(null);
  const [when, setWhen] = useState<number | null>(null);
  const [error, setError] = useState("");

  // Pick the first two distinct servers by default.
  useEffect(() => {
    if (!from && usable[0]) setFrom(usable[0].id);
  }, [usable.length]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!to && usable.find((s) => s.id !== from)) setTo(usable.find((s) => s.id !== from)!.id);
  }, [usable.length, from]); // eslint-disable-line react-hooks/exhaustive-deps

  // Show the last saved run for this pair until a new one is run.
  useEffect(() => {
    if (!from || !to || from === to) return;
    let alive = true;
    void api
      .ipTestLast(from, to)
      .then((r) => {
        if (!alive) return;
        if (r.iptest) {
          setReport(r.iptest.report);
          setWhen(r.iptest.created);
        } else {
          setReport(null);
          setWhen(null);
        }
        setError("");
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [from, to]);

  const poolCount = parseSpoofPool(sources).length;
  const canRun = !!from && !!to && from !== to && poolCount > 0 && !running;

  const run = async () => {
    setError("");
    if (from === to) return setError(t("ipt.sameServer"));
    if (poolCount === 0) return setError(t("ipt.needSources"));
    setRunning(true);
    setReport(null);
    try {
      const r = await api.ipTest({
        from,
        to,
        shape,
        sources: parseSpoofPool(sources),
        loss: Math.min(100, Math.max(0, +loss || 0)),
      });
      setReport(r.report);
      setWhen(Math.floor(Date.now() / 1000));
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : String(e);
      setError(reason(t, msg, name));
    } finally {
      setRunning(false);
    }
  };

  const copyUsable = async () => {
    if (!report) return;
    const ok = report.results.filter((r) => r.ok).map((r) => r.ip);
    if (!ok.length) return;
    if (await copyText(ok.join("\n"))) toast(t("ipt.copied"), "ok");
  };

  return (
    <div className="page is-on">
      <div className="page-band">
        <h1 className="page-title">{t("page.iptester")}</h1>
      </div>
      <p className="muted small" style={{ margin: "0 0 var(--sp-4)" }}>
        {t("ipt.lead")}
      </p>

      <Card title={t("ipt.setup")}>
        <div className="grid-2">
          <div className="field">
            <label htmlFor="ipt-from">{t("ipt.from")}</label>
            <select id="ipt-from" className="select" value={from} onChange={(e) => setFrom(e.target.value)} disabled={!loaded || running}>
              {usable.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="ipt-to">{t("ipt.to")}</label>
            <select id="ipt-to" className="select" value={to} onChange={(e) => setTo(e.target.value)} disabled={!loaded || running}>
              {usable.map((s) => (
                <option key={s.id} value={s.id} disabled={s.id === from}>
                  {s.name}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="grid-2">
          <div className="field">
            <label htmlFor="ipt-shape">{t("ipt.shape")}</label>
            <select id="ipt-shape" className="select mono" value={shape} onChange={(e) => setShape(e.target.value)} disabled={running}>
              {SPOOF_SHAPES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="ipt-loss">{t("ipt.loss")}</label>
            <input id="ipt-loss" className="text mono" dir="ltr" inputMode="numeric" value={loss} onChange={(e) => setLoss(e.target.value.trim())} disabled={running} />
            <span className="help">{t("ipt.lossHelp")}</span>
          </div>
        </div>
        <div className="field">
          <label htmlFor="ipt-sources">{t("ipt.sources")}</label>
          <textarea
            id="ipt-sources"
            className="text mono"
            rows={4}
            dir="ltr"
            spellCheck={false}
            placeholder={"203.0.113.0/24\n198.51.100.1-198.51.100.50"}
            value={sources}
            onChange={(e) => setSources(e.target.value)}
            disabled={running}
          />
          <span className="help">{poolCount > 0 ? t("ipt.sourcesCount", { n: String(poolCount) }) : t("ipt.sourcesHelp")}</span>
        </div>
        {error && <p className="help warn-text">{error}</p>}
        <div style={{ marginTop: "var(--sp-4)" }}>
          <button className="btn btn-primary" type="button" onClick={run} disabled={!canRun}>
            <Icon name={running ? "refresh" : "iptester"} size={16} />
            {running ? t("ipt.running") : t("ipt.run")}
          </button>
        </div>
      </Card>

      {report && (
        <Card
          title={t("ipt.result")}
          sub={t("ipt.resultSub", { usable: String(report.usable), total: String(report.results.length), shape: report.shape })}
          actions={
            report.usable > 0 ? (
              <button className="btn btn-sm btn-ghost" type="button" onClick={copyUsable}>
                <Icon name="copy" size={15} />
                {t("ipt.copy")}
              </button>
            ) : undefined
          }
        >
          {report.results.length === 0 ? (
            <Empty icon="iptester" title={t("ipt.none")} text={t("ipt.noneHelp")} />
          ) : (
            <table className="plain-table">
              <thead>
                <tr>
                  <th>{t("ipt.col.ip")}</th>
                  <th>{t("ipt.col.arrival")}</th>
                  <th>{t("ipt.col.status")}</th>
                </tr>
              </thead>
              <tbody>
                {report.results.map((r) => (
                  <tr key={r.ip}>
                    <td className="mono" dir="ltr">
                      {r.ip}
                    </td>
                    <td className="mono">
                      {num(r.received)}/{num(report.expect)}
                    </td>
                    <td>
                      <span className={`badge ${r.ok ? "water" : "danger"}`}>{r.ok ? t("ipt.ok") : t("ipt.fail")}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {when && (
            <p className="help" style={{ marginTop: "var(--sp-3)" }}>
              {t("ipt.ran", { when: new Date(when * 1000).toLocaleString() })}
            </p>
          )}
        </Card>
      )}
    </div>
  );
}
