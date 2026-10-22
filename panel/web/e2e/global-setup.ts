import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { exe, freePort, waitForPort, writeStack } from "./stack";

// A real panel in a folder of its own: its settings, its database, tunnels run as child
// processes (no systemd needed), and the `kariz` program that goes with `kariz-panel`.
export default async function globalSetup() {
  const bin = path.resolve(process.env.KARIZ_PANEL_BIN ?? `../../target/debug/kariz-panel${exe}`);
  if (!fs.existsSync(bin)) throw new Error(`build kariz-panel first (cargo build -p kariz -p kariz-panel): ${bin}`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kariz-e2e-"));
  const cfg = path.join(root, "panel.toml");
  const port = await freePort();
  execFileSync(bin, ["init", "-c", cfg, "--data-dir", path.join(root, "data"), "--port", String(port)]);
  const kariz = path.join(root, "kariz");
  fs.mkdirSync(kariz);
  const text = fs
    .readFileSync(cfg, "utf8")
    .replace(/^kariz_dir = .*$/m, `kariz_dir = ${JSON.stringify(kariz)}`)
    .replace(/^services = .*$/m, 'services = "process"');
  // The panel's own server allows the terminal (the terminal test opens one on it).
  const withTerminal = /^terminal = /m.test(text) ? text.replace(/^terminal = .*$/m, "terminal = true") : `${text}\nterminal = true\n`;
  fs.writeFileSync(cfg, withTerminal);
  const secret = /^path = "(.*)"$/m.exec(text)?.[1];
  if (!secret) throw new Error("no secret path in the settings");
  const log = fs.openSync(path.join(root, "panel.log"), "a");
  const child = spawn(bin, ["serve", "-c", cfg], { stdio: ["ignore", log, log] });
  await waitForPort(port);
  writeStack({ base: `https://127.0.0.1:${port}/${secret}/`, cfg, bin, root, pids: [child.pid ?? 0] });
}
