import { useEffect, useState } from "react";
import { api } from "./api";
import type { MetricsView } from "./api";
import { useApp } from "./store";
import { Card, CopyValue, Icon, Seg } from "./ui";

/** Settings > Metrics: the Prometheus endpoint under the panel's secret path, its token and a scrape config to paste. */
export function MetricsSection() {
  const { t, toast } = useApp();
  const [view, setView] = useState<MetricsView | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .metrics()
      .then((v) => alive && setView(v))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  if (!view) return null;

  // The page lives at /SECRET/; the endpoint is beside it.
  const base = location.pathname.endsWith("/") ? location.pathname : location.pathname.replace(/[^/]*$/, "");
  const path = `${base}metrics`;
  const url = `${location.origin}${path}`;
  const sample = ["scrape_configs:", "  - job_name: kariz", "    scheme: https", `    metrics_path: ${path}`, `    bearer_token: ${view.token}`, "    tls_config:", "      insecure_skip_verify: true", "    static_configs:", `      - targets: ["${location.host}"]`].join("\n");

  const act = async (action: "enable" | "disable" | "regenerate") => {
    setBusy(true);
    try {
      setView(await api.metricsSet(action));
      toast(t(action === "regenerate" ? "mt.regenerated" : "mt.saved"), "ok");
    } catch (e) {
      toast(String(e));
    } finally {
      setBusy(false);
    }
  };

  const row = (title: string, text: string, control: React.ReactNode) => (
    <div className="set-row">
      <div>
        <h3>{title}</h3>
        {text && <p>{text}</p>}
      </div>
      <div className="ctl">{control}</div>
    </div>
  );

  return (
    <Card title={t("set.metrics")} sub={t("mt.intro")}>
      {row(
        t("mt.enable"),
        t("mt.enableText"),
        <Seg
          value={view.enabled ? "on" : "off"}
          options={[
            ["on", t("mt.on")],
            ["off", t("mt.off")],
          ]}
          onChange={(v) => {
            if ((v === "on") !== view.enabled && !busy) void act(v === "on" ? "enable" : "disable");
          }}
        />,
      )}
      {view.enabled && (
        <>
          {row(t("mt.url"), t("mt.urlText"), <CopyValue what={t("mt.url")} value={url} />)}
          {row(
            t("mt.token"),
            t("mt.tokenText"),
            <div className="ar-row" style={{ flexWrap: "wrap" }}>
              <CopyValue what={t("mt.token")} value={view.token} />
              <button className="btn btn-ghost btn-sm" type="button" disabled={busy} onClick={() => void act("regenerate")}>
                <Icon name="refresh" size={16} />
                {t("mt.regen")}
              </button>
            </div>,
          )}
          <div className="set-row">
            <div>
              <h3>{t("mt.sample")}</h3>
              <p>{t("mt.sampleText")}</p>
              <pre className="mono small mt-sample" dir="ltr" tabIndex={0} aria-label={t("mt.sample")}>
                {sample}
              </pre>
            </div>
            <div className="ctl">
              <CopyValue what={t("mt.sample")} value={sample} label={t("mt.copySample")} />
            </div>
          </div>
        </>
      )}
    </Card>
  );
}
