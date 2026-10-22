import fs from "node:fs";
import { readStack, removeStack } from "./stack";

export default async function globalTeardown() {
  try {
    const s = readStack();
    for (const pid of s.pids) {
      try {
        process.kill(pid);
      } catch {
        // already gone
      }
    }
    // Some time for the processes to let go of their files before the folder goes.
    await new Promise((r) => setTimeout(r, 1000));
    // KARIZ_E2E_KEEP=1 leaves the panel's folder (its log, the daemons' logs) for a look.
    if (!process.env.KARIZ_E2E_KEEP) fs.rmSync(s.root, { recursive: true, force: true });
  } finally {
    removeStack();
  }
}
