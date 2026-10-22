import { useEffect, useState } from "react";
import { ApiError, api } from "./api";
import type { ProxyView, ServerInfo } from "./api";
import { useApp } from "./store";
import { Card, Icon, Seg } from "./ui";

type Form = {
  enabled: boolean;
  addr: string;
  username: string;
  password: string;
  panel_internet: boolean;
};

/** Settings > Proxy: the SOCKS5 proxy the panel reaches the servers switched to it through (and,
 * when asked, the internet for updates). Which servers go through it is chosen per server. */
export function ProxySection({ servers }: { servers: ServerInfo[] }) {
  const { t, toast } = useApp();
  const [view, setView] = useState<ProxyView | null>(null);
  const [form, setForm] = useState<Form>({ enabled: false, addr: "", username: "", password: "", panel_internet: false });
  const [pwTouched, setPwTouched] = useState(false);
  const [busy, setBusy] = useState(false);

  const adopt = (v: ProxyView) => {
    setView(v);
    setForm({ enabled: v.enabled, addr: v.addr, username: v.username, password: "", panel_internet: v.panel_internet });
    setPwTouched(false);
  };

  useEffect(() => {
    let alive = true;
    api
      .proxy()
      .then((v) => alive && adopt(v))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const errorText = (e: unknown) => (e instanceof ApiError ? (t(`px.err.${e.code}`) !== `px.err.${e.code}` ? t(`px.err.${e.code}`) : e.code) : String(e));

  if (!view) return null;

  const set = (patch: Partial<Form>) => setForm((f) => ({ ...f, ...patch }));
  const through = servers.filter((s) => s.reverse?.via_proxy).map((s) => s.name);

  const save = async () => {
    setBusy(true);
    try {
      const body: Parameters<typeof api.proxySet>[0] = {
        enabled: form.enabled,
        addr: form.addr.trim(),
        username: form.username.trim(),
        panel_internet: form.panel_internet,
      };
      if (pwTouched) body.password = form.password;
      adopt(await api.proxySet(body));
      toast(t("px.saved"), "ok");
    } catch (e) {
      toast(errorText(e));
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
    <Card title={t("set.proxy")} sub={t("px.intro")}>
      {row(
        t("px.enable"),
        t("px.enableText"),
        <Seg
          value={form.enabled ? "on" : "off"}
          options={[
            ["on", t("px.on")],
            ["off", t("px.off")],
          ]}
          onChange={(v) => set({ enabled: v === "on" })}
        />,
      )}
      {form.enabled && (
        <>
          {row(
            t("px.addr"),
            t("px.addrText"),
            <input
              className="text mono"
              dir="ltr"
              autoComplete="off"
              spellCheck={false}
              placeholder="127.0.0.1:1080"
              aria-label={t("px.addr")}
              value={form.addr}
              onChange={(e) => set({ addr: e.target.value })}
              style={{ width: "100%", maxWidth: 320 }}
            />,
          )}
          {row(
            t("px.auth"),
            t("px.authText"),
            <div style={{ display: "grid", gap: "var(--sp-3)", justifyItems: "start", width: "100%", maxWidth: 320 }}>
              <input className="text mono" dir="ltr" autoComplete="off" spellCheck={false} placeholder={t("px.username")} aria-label={t("px.username")} value={form.username} onChange={(e) => set({ username: e.target.value })} style={{ width: "100%" }} />
              <input
                className="text mono"
                dir="ltr"
                type="password"
                autoComplete="new-password"
                placeholder={view.has_password && !pwTouched ? "••••••••" : t("px.password")}
                aria-label={t("px.password")}
                value={form.password}
                onChange={(e) => {
                  setPwTouched(true);
                  set({ password: e.target.value });
                }}
                style={{ width: "100%" }}
              />
            </div>,
          )}
          {row(
            t("px.internet"),
            t("px.internetText"),
            <label className="check">
              <input type="checkbox" checked={form.panel_internet} onChange={(e) => set({ panel_internet: e.target.checked })} /> {t("px.internetCheck")}
            </label>,
          )}
          {row(t("px.servers"), through.length ? t("px.usedBy", { list: through.join("، ") }) : t("px.usedByNone"), <span />)}
        </>
      )}
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "var(--sp-4)" }}>
        <button className="btn btn-primary btn-sm" type="button" disabled={busy} onClick={() => void save()}>
          <Icon name="check" size={18} />
          {t("px.save")}
        </button>
      </div>
    </Card>
  );
}
