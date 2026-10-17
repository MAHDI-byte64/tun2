//! Runs a helper process under Kariz's control: in its own process group, restarted with a
//! cancellable one-second backoff if it crashes, and — together with its owner-only
//! configuration directory — torn down when the supervisor is dropped (RAII). Dropping the
//! [`HelperListener`](super::HelperListener) or [`HelperDialer`](super::HelperDialer) that
//! owns it kills the whole group and removes the directory.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::Pid;
use tokio::process::Command;
use tokio::task::JoinHandle;

/// What to run, rebuilt fresh on each (re)start.
#[derive(Clone)]
pub struct Spawn {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Extra environment variables (e.g. `SSL_CERT_FILE` for NaiveProxy).
    pub envs: Vec<(String, String)>,
    /// Working directory; the helper's configuration lives here.
    pub dir: PathBuf,
}

impl Spawn {
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        // The helper's own logs are noise in normal operation; set KARIZ_HELPER_STDERR=1
        // to surface them while diagnosing.
        let stderr = if std::env::var_os("KARIZ_HELPER_STDERR").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        cmd.args(&self.args)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .kill_on_drop(true);
        // Its own process group, so teardown can kill any children it spawns too.
        cmd.process_group(0);
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        cmd
    }
}

/// Owns a running helper and restarts it on exit. On drop it stops restarting, kills the
/// process group, and removes the configuration directory.
pub struct Supervisor {
    dir: PathBuf,
    stopped: Arc<AtomicBool>,
    pgid: Arc<AtomicI32>,
    task: Option<JoinHandle<()>>,
}

impl Supervisor {
    /// Starts the helper and the restart loop. Must be called from within a Tokio runtime.
    pub fn start(spawn: Spawn) -> Self {
        let dir = spawn.dir.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let pgid = Arc::new(AtomicI32::new(0));
        let task = tokio::spawn(run(spawn, Arc::clone(&stopped), Arc::clone(&pgid)));
        Self {
            dir,
            stopped,
            pgid,
            task: Some(task),
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let pgid = self.pgid.load(Ordering::SeqCst);
        if pgid > 0 {
            // Signal the group (pgid == the leader's pid, set by process_group(0)), then
            // reap it so no zombie is left behind if the runtime is shutting down and the
            // restart task's own wait never resumes.
            let _ = killpg(Pid::from_raw(pgid), Signal::SIGKILL);
            for _ in 0..200 {
                match waitpid(Pid::from_raw(-pgid), Some(WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn run(spawn: Spawn, stopped: Arc<AtomicBool>, pgid: Arc<AtomicI32>) {
    while !stopped.load(Ordering::SeqCst) {
        let mut child = match spawn.command().spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(error = %e, program = %spawn.program.display(), "could not start the helper");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        // Record the group id before the first await so teardown can always find it.
        if let Some(id) = child.id() {
            pgid.store(id as i32, Ordering::SeqCst);
        }
        let status = child.wait().await;
        pgid.store(0, Ordering::SeqCst);
        if stopped.load(Ordering::SeqCst) {
            return;
        }
        tracing::warn!(?status, program = %spawn.program.display(), "helper exited; restarting");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
