//! Generates the helper programs' configuration (sing-box / Xray JSON, NaiveProxy
//! config.json). These are pure functions: they take the validated settings and the
//! Kariz-owned internal loopback target and return the file contents, so they can be unit
//! tested without spawning anything.
//!
//! The acceptor's helper server forwards only to the internal target (a route rule rejects
//! every other destination); the dialer's helper client exposes a local SOCKS5 inbound
//! that only reaches that same target. Kariz runs its own handshake, record encryption and
//! mux inside the resulting stream.

use std::net::SocketAddr;

use serde_json::{json, Value};

use crate::config::HelperConfig;

/// The sing-box server that runs the `naive` inbound, forwarding authenticated traffic to
/// `internal`. `public` is the user-facing `host:port`; `cert`/`key` are absolute PEM paths.
pub fn singbox_naive_server(
    public: &SocketAddr,
    username: &str,
    password: &str,
    cert: &str,
    key: &str,
    internal: &SocketAddr,
) -> String {
    let config = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "naive",
            "listen": public.ip().to_string(),
            "listen_port": public.port(),
            "users": [{"username": username, "password": password}],
            "tls": {"enabled": true, "certificate_path": cert, "key_path": key}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        // Only the Kariz internal listener is reachable; anything else is dropped.
        "route": {"rules": [
            {"ip_cidr": [format!("{}/32", internal.ip())], "port": [internal.port()], "outbound": "direct"},
            {"action": "reject"}
        ]}
    });
    pretty(&config)
}

/// NaiveProxy client `config.json`: a local SOCKS5 inbound on `socks`, tunnelling to the
/// HTTPS proxy at `proxy_url`. `resolver` maps the TLS name to the dialed address when they
/// differ (e.g. a self-signed name in front of an IP). The CA, if any, is passed out of
/// band as `SSL_CERT_FILE`.
pub fn naive_client(socks: &SocketAddr, proxy_url: &str, resolver: Option<&str>) -> String {
    let mut config = json!({
        "listen": format!("socks://{socks}"),
        "proxy": proxy_url,
    });
    if let Some(rules) = resolver {
        config["host-resolver-rules"] = json!(rules);
    }
    pretty(&config)
}

/// The Xray server for `xhttp` (VLESS over XHTTP, HTTP/2 stream-up, TLS) or `reality`
/// (VLESS + REALITY + Vision). `h` is the validated helper table. `internal` is the Kariz
/// loopback listener; `cert`/`key` are absolute PEM paths for `xhttp`.
pub fn xray_server(
    reality: bool,
    public: &SocketAddr,
    h: &HelperConfig,
    cert: &str,
    key: &str,
    internal: &SocketAddr,
) -> String {
    let uuid = h.uuid.as_deref().unwrap_or_default();
    let client = if reality {
        json!({"id": uuid, "flow": "xtls-rprx-vision"})
    } else {
        json!({"id": uuid})
    };
    let stream = if reality {
        json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "target": h.target.as_deref().unwrap_or_default(),
                "serverNames": [h.server_name.as_deref().unwrap_or_default()],
                "privateKey": h.private_key.as_deref().unwrap_or_default(),
                "shortIds": [h.short_id.as_deref().unwrap_or_default()]
            }
        })
    } else {
        let mut xhttp = json!({"path": h.path.as_deref().unwrap_or_default(), "mode": "stream-up"});
        if let Some(host) = h.host.as_deref().filter(|s| !s.is_empty()) {
            xhttp["host"] = json!(host);
        }
        json!({
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": cert, "keyFile": key}]},
            "xhttpSettings": xhttp
        })
    };
    let config = json!({
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": public.ip().to_string(),
            "port": public.port(),
            "protocol": "vless",
            "settings": {"clients": [client], "decryption": "none"},
            "streamSettings": stream
        }],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": [internal.ip().to_string()], "port": internal.port().to_string(), "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "block"}
        ]}
    });
    pretty(&config)
}

/// The Xray client for `xhttp` or `reality`: a local SOCKS5 inbound on `socks` whose only
/// routed destination is `internal`, tunnelled to the VLESS server at `address`. `ca`, when
/// set (xhttp only), is the absolute PEM path the server certificate is verified against.
pub fn xray_client(
    reality: bool,
    socks: &SocketAddr,
    address: &str,
    port: u16,
    h: &HelperConfig,
    ca: Option<&str>,
    internal: &SocketAddr,
) -> String {
    let uuid = h.uuid.as_deref().unwrap_or_default();
    let server_name = h.server_name.as_deref().unwrap_or_default();
    let user = if reality {
        json!({"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"})
    } else {
        json!({"id": uuid, "encryption": "none"})
    };
    let stream = if reality {
        json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": server_name,
                "publicKey": h.public_key.as_deref().unwrap_or_default(),
                "shortId": h.short_id.as_deref().unwrap_or_default(),
                "fingerprint": "chrome"
            }
        })
    } else {
        let mut tls = json!({"serverName": server_name, "allowInsecure": false});
        if let Some(ca) = ca {
            tls["certificates"] = json!([{"usage": "verify", "certificateFile": ca}]);
        }
        let mut xhttp = json!({"path": h.path.as_deref().unwrap_or_default(), "mode": "stream-up"});
        if let Some(host) = h.host.as_deref().filter(|s| !s.is_empty()) {
            xhttp["host"] = json!(host);
        }
        json!({
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": tls,
            "xhttpSettings": xhttp
        })
    };
    let config = json!({
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": socks.ip().to_string(),
            "port": socks.port(),
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": false}
        }],
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
                "streamSettings": stream
            },
            {"protocol": "blackhole", "tag": "block"}
        ],
        // The SOCKS inbound reaches only the reverse target; everything else is dropped.
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": [internal.ip().to_string()], "port": internal.port().to_string(), "outboundTag": "proxy"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "block"}
        ]}
    });
    pretty(&config)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("JSON values always serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internal() -> SocketAddr {
        "127.0.0.1:45678".parse().unwrap()
    }

    #[test]
    fn naive_server_restricts_to_the_internal_target() {
        let public = "0.0.0.0:443".parse().unwrap();
        let text = singbox_naive_server(&public, "u", "p", "/c.pem", "/k.pem", &internal());
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["inbounds"][0]["type"], "naive");
        assert_eq!(v["inbounds"][0]["listen_port"], 443);
        assert_eq!(v["inbounds"][0]["users"][0]["username"], "u");
        assert_eq!(v["inbounds"][0]["tls"]["certificate_path"], "/c.pem");
        // The last route rule rejects anything but the internal target.
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap()["action"], "reject");
        assert_eq!(rules[0]["port"][0], 45678);
    }

    #[test]
    fn naive_client_maps_the_name_when_asked() {
        let socks = "127.0.0.1:0".parse().unwrap();
        let text = naive_client(
            &socks,
            "https://u:p@tunnel.example:443",
            Some("MAP tunnel.example 203.0.113.1"),
        );
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["listen"], "socks://127.0.0.1:0");
        assert_eq!(v["proxy"], "https://u:p@tunnel.example:443");
        assert_eq!(v["host-resolver-rules"], "MAP tunnel.example 203.0.113.1");
    }

    #[test]
    fn xhttp_server_and_client_match_on_path_and_name() {
        let h = HelperConfig {
            uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
            path: Some("/secret".into()),
            server_name: Some("tunnel.example".into()),
            ..HelperConfig::default()
        };
        let server = xray_server(
            false,
            &"0.0.0.0:443".parse().unwrap(),
            &h,
            "/c.pem",
            "/k.pem",
            &internal(),
        );
        let sv: Value = serde_json::from_str(&server).unwrap();
        assert_eq!(sv["inbounds"][0]["streamSettings"]["network"], "xhttp");
        assert_eq!(
            sv["inbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/secret"
        );
        assert_eq!(
            sv["inbounds"][0]["settings"]["clients"][0]["id"],
            h.uuid.as_deref().unwrap()
        );

        let client = xray_client(
            false,
            &"127.0.0.1:0".parse().unwrap(),
            "203.0.113.1",
            443,
            &h,
            Some("/ca.pem"),
            &internal(),
        );
        let cv: Value = serde_json::from_str(&client).unwrap();
        assert_eq!(cv["inbounds"][0]["protocol"], "socks");
        assert_eq!(
            cv["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
            "tunnel.example"
        );
        assert_eq!(
            cv["outbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
                ["certificateFile"],
            "/ca.pem"
        );
        assert_eq!(
            cv["outbounds"][0]["settings"]["vnext"][0]["address"],
            "203.0.113.1"
        );
    }

    #[test]
    fn reality_carries_vision_and_keys() {
        let h = HelperConfig {
            uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
            server_name: Some("cover.example".into()),
            short_id: Some("abcd".into()),
            private_key: Some("priv".into()),
            public_key: Some("pub".into()),
            target: Some("cover.example:443".into()),
            ..HelperConfig::default()
        };
        let server = xray_server(
            true,
            &"0.0.0.0:443".parse().unwrap(),
            &h,
            "",
            "",
            &internal(),
        );
        let sv: Value = serde_json::from_str(&server).unwrap();
        let rs = &sv["inbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(sv["inbounds"][0]["streamSettings"]["security"], "reality");
        assert_eq!(rs["privateKey"], "priv");
        assert_eq!(rs["target"], "cover.example:443");
        assert_eq!(
            sv["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );

        let client = xray_client(
            true,
            &"127.0.0.1:0".parse().unwrap(),
            "203.0.113.1",
            443,
            &h,
            None,
            &internal(),
        );
        let cv: Value = serde_json::from_str(&client).unwrap();
        let rc = &cv["outbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(rc["publicKey"], "pub");
        assert_eq!(rc["fingerprint"], "chrome");
        assert_eq!(
            cv["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }
}
