import { useApp } from "./store";
import { Icon } from "./ui";

/** The sealed-QUIC switch of a `quic` tunnel, and what it sends: nothing for another transport. */
export const obfsOf = (value: boolean, transport: string): boolean | undefined => (transport === "quic" && value ? true : undefined);

/** The fixed send rate of a `quic` tunnel, in Mbit/s: a positive number, or nothing. */
export const bandwidthOf = (rate: string, transport: string): number | undefined => {
  if (transport !== "quic") return undefined;
  const n = parseInt(rate, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
};

/**
 * The `[tunnel.quic]` options of a QUIC tunnel: seal every UDP packet with a key from the token
 * (`obfs`), so a network that filters QUIC does not recognise it; and an optional fixed send rate
 * (`congestion = "fixed"`), which holds that rate and treats loss as noise — for a lossy path you
 * control, where loss-based control would collapse.
 */
export function QuicObfs({
  obfs,
  onObfs,
  rate,
  onRate,
}: {
  obfs: boolean;
  onObfs: (v: boolean) => void;
  rate: string;
  onRate: (v: string) => void;
}) {
  const { t } = useApp();
  return (
    <div className="field quic-obfs">
      <span className="label">{t("obfs.title")}</span>
      <label className="check">
        <input type="checkbox" checked={obfs} onChange={(e) => onObfs(e.target.checked)} /> {t("obfs.label")}
      </label>
      <span className="help">{t("obfs.help")}</span>
      {!obfs && (
        <span className="help warn-text" role="status">
          <Icon name="alert" size={14} /> {t("obfs.off")}
        </span>
      )}
      <label className="label qrate-label" htmlFor="quic-rate">
        {t("qrate.title")}
      </label>
      <input
        id="quic-rate"
        className="input qrate"
        type="number"
        min="1"
        max="100000"
        inputMode="numeric"
        placeholder={t("qrate.placeholder")}
        value={rate}
        onChange={(e) => onRate(e.target.value.replace(/[^0-9]/g, ""))}
      />
      <span className="help">{t("qrate.help")}</span>
      {rate !== "" && (
        <span className="help warn-text" role="status">
          <Icon name="alert" size={14} /> {t("qrate.warn")}
        </span>
      )}
    </div>
  );
}
