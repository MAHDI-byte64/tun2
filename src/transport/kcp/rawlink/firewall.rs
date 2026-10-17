//! A tagged, RAII set of iptables rules.
//!
//! The raw-packet carriers need a few narrow iptables rules while they run (faketcp drops
//! the kernel's RSTs on its port and marks it NOTRACK; icmp suppresses the kernel's
//! automatic echo replies and accepts its own echoes). The rules must come back out when
//! the tunnel stops, even on an unclean exit of the tunnel task.
//!
//! [`FirewallRules`] installs its rules on construction and removes them on [`Drop`]. Each
//! rule is tagged with a comment so it is easy to spot in `iptables -S` and to remove
//! exactly. If `iptables` is missing or cannot be run (not root), installation logs a
//! warning and does nothing: the carrier still works, less cleanly, rather than failing.

use std::process::Command;

use tracing::{debug, warn};

/// One iptables rule: a table, a chain and the match/target arguments.
#[derive(Debug, Clone)]
pub struct Rule {
    /// `filter`, `raw` or `mangle`.
    table: &'static str,
    /// `INPUT`, `OUTPUT`, `PREROUTING`, ...
    chain: String,
    /// The match and target arguments, e.g. `["-p", "tcp", "--sport", "1234", "-j", "DROP"]`.
    spec: Vec<String>,
}

impl Rule {
    /// A rule in `table`/`chain` with the given match/target `spec`.
    pub fn new(table: &'static str, chain: &str, spec: &[&str]) -> Self {
        Self {
            table,
            chain: chain.to_owned(),
            spec: spec.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// A set of iptables rules that are installed now and removed on drop.
#[derive(Debug)]
pub struct FirewallRules {
    /// `iptables` or `ip6tables`.
    command: &'static str,
    /// The comment every rule carries, so it can be found and removed exactly.
    tag: String,
    rules: Vec<Rule>,
    /// Whether the rules were actually installed (false when iptables is unavailable).
    installed: bool,
}

impl FirewallRules {
    /// Installs `rules` (IPv4, `iptables`), each tagged with `tag`.
    pub fn install(tag: impl Into<String>, rules: Vec<Rule>) -> Self {
        Self::install_with("iptables", tag, rules)
    }

    /// Installs `rules` using `command` (`iptables` or `ip6tables`), each tagged with `tag`.
    pub fn install_with(command: &'static str, tag: impl Into<String>, rules: Vec<Rule>) -> Self {
        let mut this = Self {
            command,
            tag: tag.into(),
            rules,
            installed: false,
        };
        // Clear any stale copy first, so a restart does not stack duplicates, then insert.
        let mut ok = true;
        for rule in &this.rules {
            let _ = this.run("-D", rule);
            match this.run("-I", rule) {
                Ok(true) => {}
                Ok(false) => ok = false,
                Err(e) => {
                    warn!(error = %e, command, "could not run iptables; firewall rules not installed");
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            // Roll back whatever did go in, so a half-installed set does not linger.
            for rule in &this.rules {
                let _ = this.run("-D", rule);
            }
        }
        this.installed = ok;
        this
    }

    /// Whether the rules are currently installed.
    pub fn is_installed(&self) -> bool {
        self.installed
    }

    /// Runs one `iptables` operation (`-I`, `-D`, `-C`) for `rule`, returning whether it
    /// succeeded. A spawn error (iptables missing) is an [`Err`]; a non-zero exit is
    /// `Ok(false)`.
    fn run(&self, op: &str, rule: &Rule) -> std::io::Result<bool> {
        let mut cmd = Command::new(self.command);
        cmd.arg("-t")
            .arg(rule.table)
            .arg(op)
            .arg(&rule.chain)
            .args(&rule.spec)
            .args(["-m", "comment", "--comment", &self.tag]);
        let output = cmd.output()?;
        if !output.status.success() {
            debug!(
                command = self.command,
                op,
                chain = %rule.chain,
                status = ?output.status.code(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "iptables operation did not succeed"
            );
        }
        Ok(output.status.success())
    }
}

impl Drop for FirewallRules {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        for rule in &self.rules {
            // Removing again is harmless; errors (already gone) are ignored.
            let _ = self.run("-D", rule);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True when `iptables -S` can be run (root, iptables present). The tests skip with a
    /// printed reason otherwise, unless `KARIZ_REQUIRE_IPTABLES=1` forces a failure.
    fn iptables_ready() -> bool {
        let ok = Command::new("iptables")
            .arg("-S")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok && std::env::var("KARIZ_REQUIRE_IPTABLES").as_deref() == Ok("1") {
            panic!("iptables is required (KARIZ_REQUIRE_IPTABLES=1) but could not be run");
        }
        ok
    }

    /// Reads the current `iptables -S` output as one string.
    fn dump() -> String {
        let out = Command::new("iptables").arg("-S").output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn rules_appear_on_install_and_are_gone_after_drop() {
        if !iptables_ready() {
            eprintln!("skipping: iptables could not be run (needs root and iptables)");
            return;
        }
        let tag = format!("kariz-test-{}", std::process::id());
        let rules = vec![
            Rule::new(
                "filter",
                "OUTPUT",
                &["-p", "tcp", "--dport", "59999", "-j", "DROP"],
            ),
            Rule::new(
                "raw",
                "OUTPUT",
                &["-p", "tcp", "--sport", "59999", "-j", "NOTRACK"],
            ),
        ];
        {
            let fw = FirewallRules::install(tag.clone(), rules);
            assert!(fw.is_installed(), "rules should install as root");
            assert!(dump().contains(&tag), "the tag should show in iptables -S");
        }
        // Dropped: the rules must be gone.
        assert!(
            !dump().contains(&tag),
            "the tag should be gone after the rule set is dropped"
        );
    }

    #[test]
    fn install_is_idempotent() {
        if !iptables_ready() {
            eprintln!("skipping: iptables could not be run (needs root and iptables)");
            return;
        }
        let tag = format!("kariz-test-idem-{}", std::process::id());
        let rule = Rule::new(
            "filter",
            "OUTPUT",
            &["-p", "tcp", "--dport", "59998", "-j", "DROP"],
        );
        let _first = FirewallRules::install(tag.clone(), vec![rule.clone()]);
        let second = FirewallRules::install(tag.clone(), vec![rule]);
        assert!(second.is_installed());
        // Exactly one rule carries the tag, not two.
        let count = dump().lines().filter(|l| l.contains(&tag)).count();
        assert_eq!(count, 1, "a second install must not stack a duplicate rule");
        drop(second);
        assert!(!dump().contains(&tag));
    }
}
