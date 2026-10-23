import type { ManualBundle as Bundle } from "./api";
import { useApp } from "./store";
import { CodeBlock, Icon } from "./ui";

/**
 * The config, certificate and commands for a tunnel side the panel could not reach, shown once
 * after the tunnel is made. The operator copies these to the server and runs the commands.
 */
export function ManualBundle({ bundle, serverName }: { bundle: Bundle; serverName: (id: string) => string }) {
  const { t } = useApp();
  const name = (s: string) => `/etc/kariz/${s}`;
  return (
    <div className="manual-bundle">
      <p className="banner info">
        <Icon name="info" size={16} /> {t("manual.lead", { server: serverName(bundle.server) })}
      </p>
      <p className="warn-text small" role="status">
        <Icon name="alert" size={14} /> {t("manual.once")}
      </p>

      <h4 className="manual-h">{t("manual.file")}</h4>
      <CodeBlock text={bundle.config} />

      {bundle.cert && (
        <>
          <h4 className="manual-h">{name("NAME.crt").replace("NAME", "…")}</h4>
          <CodeBlock text={bundle.cert} />
        </>
      )}
      {bundle.key && (
        <>
          <h4 className="manual-h">{name("NAME.key").replace("NAME", "…")}</h4>
          <CodeBlock text={bundle.key} />
        </>
      )}

      <h4 className="manual-h">{t("manual.commands")}</h4>
      <CodeBlock text={bundle.commands} />

      <p className="muted small">{t("manual.then")}</p>
    </div>
  );
}
