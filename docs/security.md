# Security

## The token

The token is the only secret. Anyone who has it can use the tunnel, and anyone without
it cannot. Generate it with `kariz token`, keep it out of shared places, and change it
on both sides if it leaks. It never travels over the network: the handshake proves
each side knows it without sending it.

## What protects the traffic

- **Handshake:** mutual authentication with the token, plus an X25519 key exchange, so
  recorded traffic stays safe even if the token leaks later (forward secrecy).
  - The hello has no fixed bytes and no fixed length.
  - Replayed hellos are rejected.
- **Records:** everything after the handshake is AES-256-GCM or ChaCha20-Poly1305, with
  lengths encrypted too and one key per direction. A changed, reordered or replayed
  record ends the connection.
- **`quic`:** mutual TLS 1.3 with keys derived from the token. There are no certificate
  files, and a wrong token fails the handshake in both directions.
- **`kcp`:** every UDP packet is sealed with a key from the token, so the port answers
  nothing else. That key has no forward secrecy of its own. The handshake and records
  run inside it as over TCP, and UDP packets beside KCP are sealed with keys from the
  same handshake.

## What others can see

- **Failed handshakes:** a connection that fails the handshake is not closed at once
  but drained for a random 5-30 s, so its timing reveals little.
- **WebSocket requests:** a request that is not a valid upgrade on the configured path
  gets the `404` page of a stock nginx.
- **TLS and QUIC handshakes** are those of rustls and quinn. They do not look like a
  browser's, and a plain HTTP request to a `wss` port gets a TLS error rather than a web
  page.
- **Behind a CDN, TLS ends at the CDN.** The tunnel's own encryption still keeps the
  contents from the CDN.

## Updates

Releases are signed with an Ed25519 key. `kariz-manager` and the panel check the
signature, and the panel's agents check it again on their own servers, so a copy of a release that
was tampered with, or that another key signed, is not installed even if it comes from the right
address. The panel's update swaps the programs with a rollback, and never runs a file whose
signature does not verify.

## Settings that weaken it

`kariz check` and the startup log warn about each:

- `encryption = "none"`: authenticates, but the traffic is readable on the wire. Use it
  only inside another encrypted layer. The panel offers it as *No encryption*, in red, and asks
  you to confirm it; the choice is also *Automatic* (recommended), *AES-256-GCM* and
  *ChaCha20-Poly1305*.
- `tls.insecure = true`: the `wss` dialer accepts any certificate. Prefer
  `tls.pin_sha256`.

## Running it

- The systemd unit runs Kariz with `NoNewPrivileges` and only the capabilities it needs
  (binding ports below 1024).
- Keep the config file readable by root only (`chmod 600`), since it holds the token.
- The panel's web terminal (2.10.0) is a root shell on a server, opened from the browser. It
  is off on every server until `terminal = true` is set in that server's `agent.toml`
  (`panel.toml` for the panel's own server): switch it on only where the panel's users may
  have a shell, and remember that the panel's password and login links then open it.
- Report security problems privately to the maintainer rather than in a public issue.
