import { useEffect, useState } from "react";
import { ApiError, api } from "./api";
import type { QuotaRow } from "./api";
import { useApp } from "./store";
import { CopyValue, Icon, Seg, useAgo } from "./ui";

export const GB = 1024 ** 3;
export const TB = 1024 ** 4;
/** The smallest limit the panel takes: a megabyte. */
export const MIN_LIMIT = 1024 * 1024;
export const MAX_LIMIT = 1024 ** 5;
/** The most days a limit can run, or be extended by, at once. */
export const MAX_DAYS = 3650;

type Unit = "GB" | "TB";
type Reset = "manual" | "monthly";
type Duration = "none" | "days" | "until";

/** What the limit form holds, as typed. */
export interface QuotaForm {
  amount: string;
  unit: Unit;
  reset: Reset;
  day: string;
  duration: Duration;
  days: string;
  /** `YYYY-MM-DD`. */
  until: string;
}

export const emptyQuotaForm = (): QuotaForm => ({ amount: "", unit: "GB", reset: "manual", day: "1", duration: "none", days: "30", until: "" });

/** What a form asks for: the volume (0: time alone), the day of the month it resets on (0: by hand), and the end
 * (days from now, or a time); null when it is not a valid limit. */
export function quotaOf(f: QuotaForm): { limit_bytes: number; reset_day: number; days?: number; expires_at?: number } | null {
  const n = Number(f.amount.replace(",", "."));
  const hasAmount = f.amount.trim() !== "";
  if (hasAmount && (!Number.isFinite(n) || n <= 0)) return null;
  const limit_bytes = hasAmount ? Math.round(n * (f.unit === "GB" ? GB : TB)) : 0;
  if (hasAmount && (limit_bytes < MIN_LIMIT || limit_bytes > MAX_LIMIT)) return null;
  const day = f.reset === "monthly" ? Number(f.day) : 0;
  if (!Number.isInteger(day) || day < 0 || day > 28 || (f.reset === "monthly" && day < 1)) return null;
  const out: { limit_bytes: number; reset_day: number; days?: number; expires_at?: number } = { limit_bytes, reset_day: day };
  if (f.duration === "days") {
    const d = Number(f.days);
    if (!Number.isInteger(d) || d < 1 || d > MAX_DAYS) return null;
    out.days = d;
  } else if (f.duration === "until") {
    const at = Date.parse(`${f.until}T23:59:59Z`) / 1000;
    if (!Number.isFinite(at) || at <= Date.now() / 1000 || at > Date.now() / 1000 + MAX_DAYS * 86400) return null;
    out.expires_at = Math.round(at);
  }
  if (!hasAmount && f.duration === "none") return null;
  return out;
}

/** A saved limit, as the form shows it: in TB when it is a round number of hundredths of one. */
export function formOf(q: QuotaRow): QuotaForm {
  const hundredths = (q.limit_bytes * 100) / TB;
  const tb = q.limit_bytes >= TB && Math.abs(hundredths - Math.round(hundredths)) < 1e-6;
  const unit: Unit = tb ? "TB" : "GB";
  const amount = q.limit_bytes > 0 ? String(Number((q.limit_bytes / (tb ? TB : GB)).toPrecision(10))) : "";
  const until = q.expires_at > 0 ? new Date(q.expires_at * 1000).toISOString().slice(0, 10) : "";
  return { amount, unit, reset: q.reset_day > 0 ? "monthly" : "manual", day: String(q.reset_day || 1), duration: q.expires_at > 0 ? "until" : "none", days: "30", until };
}

/** "12.3 GB" style parts, in the units the rest of the panel uses. */
export function fmtBytes(n: number): { value: number; unit: string; decimals: number } {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return { value: v, unit: units[i], decimals: i === 0 || v >= 100 ? 0 : 1 };
}

/** Days until the limit ends (0 when it has), or null without an end. */
export function daysLeft(q?: QuotaRow | null): number | null {
  if (!q || !(q.expires_at > 0)) return null;
  return Math.max(0, Math.ceil((q.expires_at - Date.now() / 1000) / 86400));
}

/** Over its limit or past its end: the panel refuses to start it until the usage is reset, the limit raised or
 * the end extended. */
export function quotaExhausted(q?: QuotaRow | null): boolean {
  if (!q) return false;
  return (q.limit_bytes > 0 && q.used >= q.limit_bytes) || (q.expires_at > 0 && Date.now() / 1000 >= q.expires_at);
}

/** Stopped by its limit (the volume or the end), and still over it. */
export function quotaStopped(q?: QuotaRow | null): boolean {
  return quotaExhausted(q) && !!q && (q.stopped > 0 || q.expired > 0);
}

/** The usage against the limit: a bar and the numbers, and the days left when the limit has an end. */
export function QuotaBar({ q }: { q: QuotaRow }) {
  const { t, num } = useApp();
  const used = fmtBytes(q.used);
  const limit = fmtBytes(q.limit_bytes);
  const pct = Math.min(100, q.pct);
  const left = daysLeft(q);
  const tone = q.limit_bytes > 0 && q.used >= q.limit_bytes ? "over" : q.pct >= 80 ? "near" : "";
  const timeTone = left === 0 ? "over" : left !== null && left <= 3 ? "near" : "";
  return (
    <div className={`qt-bar ${tone}`} title={q.limit_bytes > 0 ? t("qt.pct", { pct: num(Math.round(q.pct)) }) : t("qt.timeOnly")}>
      {q.limit_bytes > 0 && (
        <span className="t-bar" aria-hidden="true">
          <i style={{ width: `${Math.max(1, pct)}%` }} />
        </span>
      )}
      <span className="qt-text" dir="ltr">
        {q.limit_bytes > 0 ? t("qt.ofLimit", { used: `${num(used.value, used.decimals)} ${used.unit}`, limit: `${num(limit.value, limit.decimals)} ${limit.unit}` }) : `${num(used.value, used.decimals)} ${used.unit}`}
      </span>
      {left !== null && <span className={`qt-days ${timeTone}`}>{left === 0 ? t("qt.timeUp") : t("qt.daysLeft", { n: num(left) })}</span>}
    </div>
  );
}

/** The limit's fields: the amount with its unit, when the usage resets, and when the limit ends. */
export function QuotaFields({ id, form, onChange }: { id: string; form: QuotaForm; onChange: (f: QuotaForm) => void }) {
  const { t } = useApp();
  const set = (patch: Partial<QuotaForm>) => onChange({ ...form, ...patch });
  return (
    <div className="qt-form">
      <div className="field">
        <label htmlFor={`${id}-amount`}>{t("qt.amount")}</label>
        <div className="ar-row">
          <input id={`${id}-amount`} className="text mono" dir="ltr" inputMode="decimal" placeholder="100" value={form.amount} onChange={(e) => set({ amount: e.target.value })} style={{ width: 120 }} />
          <Seg<Unit>
            value={form.unit}
            options={[
              ["GB", t("qt.unit.GB")],
              ["TB", t("qt.unit.TB")],
            ]}
            onChange={(unit) => set({ unit })}
          />
        </div>
        {form.duration !== "none" && <span className="help">{t("qt.amountOptional")}</span>}
      </div>
      <div className="field">
        <span className="label">{t("qt.reset")}</span>
        <div className="ar-row">
          <Seg<Reset>
            value={form.reset}
            options={[
              ["manual", t("qt.reset.manual")],
              ["monthly", t("qt.reset.monthly")],
            ]}
            onChange={(reset) => set({ reset })}
          />
          {form.reset === "monthly" && (
            <input id={`${id}-day`} className="text mono" dir="ltr" inputMode="numeric" aria-label={t("qt.day")} value={form.day} onChange={(e) => set({ day: e.target.value.trim() })} style={{ width: 64 }} />
          )}
        </div>
        <span className="help">{form.reset === "monthly" ? t("qt.dayHelp") : t("qt.manualHelp")}</span>
      </div>
      <div className="field">
        <span className="label">{t("qt.duration")}</span>
        <div className="ar-row" style={{ flexWrap: "wrap" }}>
          <Seg<Duration>
            value={form.duration}
            options={[
              ["none", t("qt.duration.none")],
              ["days", t("qt.duration.days")],
              ["until", t("qt.duration.until")],
            ]}
            onChange={(duration) => set({ duration })}
          />
          {form.duration === "days" && (
            <input id={`${id}-days`} className="text mono" dir="ltr" inputMode="numeric" aria-label={t("qt.days")} value={form.days} onChange={(e) => set({ days: e.target.value.trim() })} style={{ width: 72 }} />
          )}
          {form.duration === "until" && <input id={`${id}-until`} className="text mono" dir="ltr" type="date" aria-label={t("qt.until")} value={form.until} onChange={(e) => set({ until: e.target.value })} />}
        </div>
        <span className="help">{t("qt.durationHelp")}</span>
      </div>
    </div>
  );
}

/** The tunnel page's Traffic limit tab: the limit, the usage, the buttons, and the renter's page. */
export function QuotaBlock({ tunnel, metered, oldAgent, onChanged }: { tunnel: string; metered: boolean; oldAgent: boolean; onChanged: () => void }) {
  const { t, lang, num, toast, digitsOf } = useApp();
  const ago = useAgo();
  const [row, setRow] = useState<QuotaRow | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [form, setForm] = useState<QuotaForm>(emptyQuotaForm());
  const [extendBy, setExtendBy] = useState("30");
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // The list is read again every few seconds, for the usage; the form is filled in from it once.
  useEffect(() => {
    let alive = true;
    let first = true;
    const read = async () => {
      try {
        const { quotas } = await api.quotas();
        if (!alive) return;
        const mine = quotas.find((q) => q.name === tunnel) ?? null;
        setRow(mine);
        if (first) {
          first = false;
          if (mine) {
            setForm(formOf(mine));
            setTitle(mine.share?.title ?? "");
          }
          setLoaded(true);
        }
      } catch {
        if (alive && first) setLoaded(true);
      }
    };
    void read();
    const id = setInterval(read, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [tunnel]);

  const reread = async () => {
    try {
      const { quotas } = await api.quotas();
      setRow(quotas.find((q) => q.name === tunnel) ?? null);
    } catch {
      /* the next poll */
    }
    onChanged();
  };

  const wanted = quotaOf(form);
  const run = async (what: () => Promise<unknown>, done: string) => {
    setError("");
    setBusy(true);
    try {
      await what();
      toast(t(done), "ok");
      await reread();
    } catch (e) {
      setError(e instanceof ApiError && e.code === "bad_input" ? t("qt.badInput") : t("qt.failed"));
    } finally {
      setBusy(false);
    }
  };
  const save = () => {
    if (!wanted) {
      setError(t("qt.badInput"));
      return;
    }
    void run(() => api.setQuota({ name: tunnel, ...wanted }), "qt.saved");
  };
  const extend = () => {
    const d = Number(extendBy);
    if (!Number.isInteger(d) || d < 1 || d > MAX_DAYS) {
      setError(t("qt.badInput"));
      return;
    }
    void run(() => api.extendQuota(tunnel, d), "qt.extended");
  };

  const when = (unix: number) =>
    digitsOf(
      new Date(unix * 1000).toLocaleString(lang === "fa" ? "fa-IR-u-nu-latn" : "en-GB", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    );
  const date = (unix: number) => digitsOf(new Date(unix * 1000).toLocaleDateString(lang === "fa" ? "fa-IR-u-nu-latn" : "en-GB", { year: "numeric", month: "short", day: "numeric" }));

  if (!loaded) return <p className="muted small">…</p>;
  const left = daysLeft(row);
  const shareUrl = row?.share ? `${location.origin}/s/${row.share.token}` : "";

  return (
    <div className="qt-block">
      {!metered && <p className="banner info small">{t("qt.notMetered")}</p>}
      {metered && oldAgent && <p className="banner info small">{t("qt.oldAgent")}</p>}
      {row && (
        <dl className="ar-state qt-state">
          <div>
            <dt>{t("qt.used")}</dt>
            <dd>
              <QuotaBar q={row} />
            </dd>
          </div>
          {row.next_reset != null && (
            <div>
              <dt>{t("qt.nextReset")}</dt>
              <dd>{when(row.next_reset)}</dd>
            </div>
          )}
          {row.expires_at > 0 && (
            <div>
              <dt>{t("qt.ends")}</dt>
              <dd className={left === 0 ? "err" : undefined}>
                {date(row.expires_at)} · {left === 0 ? t("qt.timeUp") : t("qt.daysLeft", { n: num(left ?? 0) })}
              </dd>
            </div>
          )}
          {row.expired > 0 && (
            <div>
              <dt>{t("qt.expiredAt")}</dt>
              <dd className="err">{ago(Math.max(0, Date.now() / 1000 - row.expired))}</dd>
            </div>
          )}
          {quotaStopped(row) && row.expired === 0 && (
            <div>
              <dt>{t("qt.stoppedAt")}</dt>
              <dd className="err">{ago(Math.max(0, Date.now() / 1000 - row.stopped))}</dd>
            </div>
          )}
          {row.start_due && (
            <div>
              <dt />
              <dd className="muted">{t("qt.startDue")}</dd>
            </div>
          )}
        </dl>
      )}
      {!row && <p className="muted small">{t("qt.none")}</p>}
      <QuotaFields id="qt" form={form} onChange={setForm} />
      {error && (
        <span className="err" role="alert">
          {error}
        </span>
      )}
      <div className="ar-row" style={{ marginTop: "var(--sp-3)", flexWrap: "wrap" }}>
        <button className="btn btn-primary btn-sm" type="button" disabled={busy || !metered} onClick={save}>
          <Icon name="check" size={16} />
          {t("qt.save")}
        </button>
        {row && (
          <>
            <button className="btn btn-ghost btn-sm" type="button" disabled={busy} onClick={() => void run(() => api.resetQuota(tunnel), "qt.resetDone")}>
              <Icon name="restart" size={16} />
              {t("qt.resetUsage")}
            </button>
            <button className="btn btn-ghost btn-sm" type="button" disabled={busy} onClick={() => void run(() => api.deleteQuota(tunnel), "qt.removed")}>
              <Icon name="trash" size={16} />
              {t("qt.remove")}
            </button>
            {row.limit_bytes > 0 && <span className="muted small">{t("qt.pct", { pct: num(Math.round(row.pct)) })}</span>}
          </>
        )}
      </div>
      {row && (
        <div className="qt-extend ar-row" style={{ marginTop: "var(--sp-3)", flexWrap: "wrap" }}>
          <label className="small" htmlFor="qt-extend">
            {t("qt.extendBy")}
          </label>
          <input id="qt-extend" className="text mono" dir="ltr" inputMode="numeric" value={extendBy} onChange={(e) => setExtendBy(e.target.value.trim())} style={{ width: 72 }} />
          <span className="small">{t("qt.extendDays")}</span>
          <button className="btn btn-ghost btn-sm" type="button" disabled={busy} onClick={extend}>
            <Icon name="clock" size={16} />
            {t("qt.extend")}
          </button>
        </div>
      )}
      {row && (
        <div className="qt-share">
          <h4>{t("qt.share")}</h4>
          <p className="muted small">{t("qt.shareHelp")}</p>
          <div className="ar-row" style={{ flexWrap: "wrap" }}>
            <input id="qt-share-title" className="text" placeholder={t("qt.shareTitle")} aria-label={t("qt.shareTitle")} value={title} onChange={(e) => setTitle(e.target.value)} style={{ width: 220 }} />
            <button className="btn btn-primary btn-sm" type="button" disabled={busy} onClick={() => void run(() => api.shareQuota(tunnel, title), "qt.shareMade")}>
              <Icon name="link" size={16} />
              {row.share ? t("qt.shareNew") : t("qt.shareMake")}
            </button>
            {row.share && (
              <button className="btn btn-ghost btn-sm" type="button" disabled={busy} onClick={() => void run(() => api.unshareQuota(tunnel), "qt.shareRevoked")}>
                <Icon name="trash" size={16} />
                {t("qt.shareRevoke")}
              </button>
            )}
          </div>
          {row.share && (
            <div className="ar-row" style={{ marginTop: "var(--sp-2)", flexWrap: "wrap" }}>
              <CopyValue what={t("qt.share")} value={shareUrl} />
              <span className="muted small">{t("qt.shareViews", { n: num(row.share.views) })}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
