# The manager script

`scripts/kariz.sh` installs Kariz and its [web panel](panel.md) on a Linux server with systemd,
and connects a server to a panel. After the first run it is also the `kariz-manager` command.

**Tunnels are not made here.** Servers, tunnels, private networks, backups and updates of the
other servers are all done in the web panel. The manager is only the way to get Kariz onto a
server and the panel running; from then on you work in the browser.

## Install

As root, on each server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh)
```

The first time on a server it installs the Kariz core by itself, then asks what else this
server is for: only the core (tunnels are made from a panel on another server), the web panel
here as well, or a connection to a panel that exists. Every run after that opens a menu, with
the server's name and its IPv4 and IPv6 addresses at the top, and below it what runs here (the
core, the web panel and the agent, each with a green dot when it is running).

In a terminal, **move with the arrow keys** (or `j` / `k`) and press **Enter**; a number jumps
to its item (`1` then `0` reaches 10), and `q` or Esc leaves. The line under the list says what
the highlighted item does. Each item opens its own cleared screen with the title on top and ends
with "Press any key"; Ctrl+C in it comes back to the menu. Questions with options (how to sign
in to the panel, which log) are lists to move in the same way. Without a terminal (a pipe, a
script) the menu and the questions are numbered and read as lines.

| | |
|---|---|
| **1** Install or update Kariz | finds your CPU (x86_64, aarch64 or armv7), downloads the latest release, checks its SHA-256 and its signature, and installs `kariz`, `kariz-panel`, the systemd units and the `kariz-manager` command |
| **2** Status and addresses | what runs on this server, its addresses and the panel's address |
| **3** to **7** Web panel | install the panel here, make a login link, set the admin password, change the domain or IP and its certificate, remove the panel |
| **8**, **9** Agent | connect this server to a panel with a join code, or disconnect it |
| **10** Live logs | follow the panel's or the agent's log |
| **11** Uninstall Kariz | stops and removes what it installed |

If GitHub limits your downloads (many servers behind one address), set `GITHUB_TOKEN` to any
personal access token before running the script: it is used only to lift that limit.

Other ways to install:

```bash
kariz-manager install --version v1.0.0        # a specific release
kariz-manager install --binary ./kariz        # a binary you built yourself
```

## The usual path

1. On the server that will hold the panel: run the one-liner, choose **3** (Install the web panel here). It
   prints the panel's address and a one-time login link.
2. Open the link in a browser and sign in. From here on, work in the panel:
   [Using the panel](using-the-panel.md).
3. On every other server: run the one-liner and choose **8** (Connect to a panel), and paste the join
   code the panel gave you (Servers, Add server). That server now shows up in the panel.
4. Make tunnels in the panel, between any two of its servers.

## Commands

The menu and the commands do the same things:

```bash
kariz-manager install [--version vX.Y.Z] [--binary PATH]   # Kariz (and the panel program)
kariz-manager update [--version vX.Y.Z]                    # a new release; what runs is restarted
kariz-manager uninstall [--yes]                            # --yes also deletes the configs

kariz-manager panel install [--port N] [--host H] [--name NAME]   # the panel on this server: address, certificate, a login link; asks what to call this server (default: its host name)
kariz-manager panel name [NAME]                    # rename this server in the panel
kariz-manager panel link [--host H]                 # another one-time login link
kariz-manager panel password [--stdin | --random]  # a new admin password (asked twice, hidden)
kariz-manager panel status | logs                   # the service, its address / follow the log
kariz-manager panel cert [--domain D | --ip A]      # a new domain or IP address, with its certificate
kariz-manager panel heal                            # a certificate for this server's new IP address (a timer runs it)
kariz-manager panel uninstall [--yes]

kariz-manager --agent kz1_... [--yes]               # connect this server to a panel (the code is from the panel)
kariz-manager agent status | logs | remove
kariz-manager status                                # what runs here and this server's addresses
```

A server that already has an agent can be joined to another panel with a new code: the manager
says so, asks (`--yes` skips the question), removes the old agent, and starts the new one in its
place. The old panel keeps listing that server as offline until you remove it there.

## Update and uninstall

Opening the menu (and `kariz-manager status`) looks for a newer release. If one is out and the
core, the panel or the agent here is older, it says which and asks whether to update all of them
now. Joining a panel with `--agent CODE` updates an older program first, because an old agent
can refuse what a newer panel sends. `KARIZ_NO_UPDATE_CHECK=1` turns the look off. `update` also
fetches the `kariz-manager` script of the release it installed (unless you install from files of
your own).

`install` and `update` check the release's **signature** (from 0.11, a release without a valid
one is not installed; older releases have none and are accepted with a warning) and its
SHA-256. `update` restarts what runs: every tunnel, the panel and the agent, so they use the
new binary. Once a server is connected to a panel, the panel can update it (and itself) with a
button: [Updating from the panel](panel.md#updating).

The manager script updates itself too, in three ways:

- The panel and the agent put the `kariz-manager` of their own release in place each time they
  start, when the one there is missing or different. An update from the panel restarts them, so
  a server that is only ever updated from the panel gets the menu of its new release too.
- `update` (and the *Install or update* item) fetches the `kariz-manager` of the release it
  installed (from main, if that release has no tag yet) and, when it replaces the one that is open
  in the menu, the menu opens again as the new one. If the download fails it says so and the old
  script stays.
- A copy of the script you run from a file (a new one you copied to the server) is installed as
  `kariz-manager` at once, even when the core is up to date. Run the file once and the
  `kariz-manager` command is the new script from then on.

To fetch it by hand:

```bash
curl -fsSL -o /usr/local/bin/kariz-manager \
    https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh
chmod +x /usr/local/bin/kariz-manager
```

`uninstall` removes Kariz from the server completely: every tunnel, the agent (its service, its
identity and the private network links it made), the web panel if there is one, and the
programs. It lists what it will remove and asks once, then asks whether the tunnel configs and
the panel's data (tokens, servers, certificate) go too; `--yes` answers yes to everything. A
server that is connected to a panel keeps showing there as offline until you remove it in the
panel. `agent remove` removes only the agent.

## Logs

Kariz logs go to the journal, with systemd's priority for each line. The panel shows them in
its Logs page; on the server:

```bash
journalctl -u kariz@main -f                 # follow one tunnel
journalctl -u kariz@main -p warning         # only warnings and errors
journalctl -u kariz-panel -f                # the panel
journalctl -u kariz-agent -f                # the agent
```

## Good to know

- It needs root, systemd, and `curl` or `wget`.
- Tunnels are ordinary Kariz configs in `/etc/kariz/<name>.toml`, run by the service
  `kariz@<name>`; the panel's agent writes them. You can read them, and the
  [configuration reference](configuration.md) explains every setting, but change them in the
  panel so both sides stay in step.
- The service unit is `systemd/kariz@.service`.
