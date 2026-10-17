import { ENCRYPTION_FORCED } from "./transport";
import { useApp } from "./store";
import { Icon } from "./ui";

export const CIPHERS = ["auto", "aes-256-gcm", "chacha20-poly1305", "none"] as const;
export type Cipher = (typeof CIPHERS)[number];

/** The cipher to send: nothing for `auto`, and nothing for QUIC (always TLS 1.3). */
export const cipherOf = (value: string, transport: string): string | undefined => (value === "auto" || transport === "quic" ? undefined : value);

/** Whether a transport seals nothing of its own, so the tunnel's encryption is mandatory (`none` is refused). */
const noneForbidden = (transport: string) => ENCRYPTION_FORCED.includes(transport);

/** Whether the choice may go on: no encryption has to be confirmed, and is refused outright where it is mandatory. */
export const cipherReady = (value: string, transport: string, ack: boolean) => {
  if (transport === "quic") return true;
  if (value !== "none") return true;
  if (noneForbidden(transport)) return false;
  return ack;
};

/** The cipher of a tunnel: the recommended automatic choice, AES, ChaCha, or none (with a warning and a confirmation). */
export function EncryptionChoice({
  value,
  onChange,
  transport,
  ack,
  onAck,
}: {
  value: string;
  onChange: (v: Cipher) => void;
  transport: string;
  ack: boolean;
  onAck: (v: boolean) => void;
}) {
  const { t } = useApp();
  const quic = transport === "quic";
  const forbidNone = noneForbidden(transport);
  return (
    <div className="field enc-choice">
      <span className="label">{t("enc.title")}</span>
      <div className="tiles" role="radiogroup" aria-label={t("enc.title")}>
        {CIPHERS.map((c) => (
          <button
            key={c}
            type="button"
            role="radio"
            aria-checked={!quic && value === c}
            aria-disabled={quic || (c === "none" && forbidNone)}
            className={`tile ${c === "none" ? "is-risk" : ""}`}
            onClick={() => !quic && !(c === "none" && forbidNone) && onChange(c)}
          >
            <span className="t1">
              {t(`enc.${c}`)}
              {c === "auto" && <span className="badge water">{t("enc.recommended")}</span>}
            </span>
            <span className="t2">{t(`enc.${c}.d`)}</span>
            <span className="tick">
              <Icon name="check" size={14} />
            </span>
          </button>
        ))}
      </div>
      {quic && <span className="help">{t("enc.quic")}</span>}
      {!quic && forbidNone && <span className="help">{t("enc.required")}</span>}
      {!quic && transport === "wss" && value !== "none" && <span className="help">{t("enc.tls")}</span>}
      {!quic && !forbidNone && value === "none" && (
        <div className="enc-warn" role="alert">
          <Icon name="alert" size={18} />
          <div>
            <p>{t(transport === "wss" ? "enc.noneWarn.tls" : "enc.noneWarn")}</p>
            <label className="check">
              <input type="checkbox" checked={ack} onChange={(e) => onAck(e.target.checked)} /> {t("enc.noneAck")}
            </label>
          </div>
        </div>
      )}
    </div>
  );
}
