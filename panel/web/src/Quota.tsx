import { useEffect, useState } from "react";
import { ApiError, api } from "./api";
import type { QuotaRow } from "./api";
import { useApp } from "./store";
import { Icon, Seg, useAgo } from "./ui";

export const GB = 1024 ** 3;
export const TB = 1024 ** 4;
/** The smallest limit the panel takes: a megabyte. */
export const MIN_LIMIT = 1024 * 1024;
export const MAX_LIMIT = 1024 ** 5;

type Unit = "GB" | "TB";
type Reset = "manual" | "monthly";

/** What the limit form holds, as typed. */
export interface QuotaForm {
  amount: string;
  unit: Unit;
  reset: Reset;
  day: string;
}

export const emptyQuotaForm = (): QuotaForm => ({ amount: "", unit: "GB", reset: "manual", day: "1" });

/** The limit a form asks for (bytes, and the day of the month it resets on; 0: by hand), or null when it is not a valid one. */
export function quotaOf(f: QuotaForm): { limit_bytes: number; reset_day: number } | null {
  const n = Number(f.amount.replace(",", "."));
  if (!f.amount.trim() || !Number.isFinite(n) || n <= 0) return null;
  const limit_bytes = Math.round(n * (f.unit === "GB" ? GB : TB));
  if (limit_bytes < MIN_LIMIT || limit_bytes > MAX_LIMIT) return null;
  const day = f.reset === "monthly" ? Number(f.day) : 0;
  if (!Number.isInteger(day) || day < 0 || day > 28 || (f.reset === "monthly" && day < 1)) return null;
  return { limit_bytes, reset_day: day };
}

/** A saved limit, as the form shows it. */
export function formOf(q: QuotaRow): QuotaForm {
  const tb = q.limit_bytes >= TB && q.limit_bytes % (TB / 100) === 0;
  const unit: Unit = tb ? "TB" : "GB";
  const amount = q.limit_bytes / (tb ? TB : GB);
  return { amount: String(Math.round(amount * 100) / 100), unit, reset: q.reset_day > 0 ? "monthly" : "manual", day: String(q.reset_day || 1) };
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

/** Stopped by its limit, and still over it: it will not start until the usage is reset or the limit raised. */
export function quotaStopped(q?: QuotaRow | null): boolean {
  return !!q && q.limit_bytes > 0 && q.stopped > 0 && q.used >= q.limit_bytes;
}

/** The usage against the limit: a bar and the numbers. */
export function QuotaBar({ q }: { q: QuotaRow }) {
  const { t, num } = useApp();
  const used = fmtBytes(q.used);
  const limit = fmtBytes(q.limit_bytes);
  const pct = Math.min(100, q.pct);
  const tone = q.used >= q.limit_bytes ? "over" : q.pct >= 80 ? "near" : "";
  return (
    <div className={`qt-bar ${tone}`} title={t("qt.pct", { pct: num(Math.round(q.pct)) })}>
      <span className="t-bar" aria-hidden="true">
        <i style={{ width: `${Math.max(1, pct)}%` }} />
      </span>
      <span className="qt-text" dir="ltr">
        {t("qt.ofLimit", { used: `${num(used.value, used.decimals)} ${used.unit}`, limit: `${num(limit.value, limit.decimals)} ${limit.unit}` })}
      </span>
    </div>
  );
}

/** The limit's fields: the amount with its unit, and when the usage resets. */
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
    </div>
  );
}

/** The tunnel page's Traffic limit tab: the limit, the usage, and the buttons. */
export function QuotaBlock({ tunnel, metered, oldAgent, onChanged }: { tunnel: string; metered: boolean; oldAgent: boolean; onChanged: () => void }) {
  const { t, lang, num, toast, digitsOf } = useApp();
  const ago = useAgo();
  const [row, setRow] = useState<QuotaRow | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [form, setForm] = useState<QuotaForm>(emptyQuotaForm());
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
          if (mine) setForm(formOf(mine));
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

  const when = (unix: number) =>
    digitsOf(
      new Date(unix * 1000).toLocaleString(lang === "fa" ? "fa-IR-u-nu-latn" : "en-GB", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    );

  if (!loaded) return <p className="muted small">…</p>;

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
          {quotaStopped(row) && (
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
            <span className="muted small">{t("qt.pct", { pct: num(Math.round(row.pct)) })}</span>
          </>
        )}
      </div>
    </div>
  );
}
