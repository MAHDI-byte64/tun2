//! The panel's HTTPS server. It answers only under the secret path; everything else
//! gets the same 404 page a plain nginx gives, so a scanner learns nothing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rust_embed::RustEmbed;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Service;
use tracing::{debug, info};

use crate::config::Config;
use crate::db::Db;

/// The web app, built into the binary (see build.rs for the placeholder).
#[derive(RustEmbed)]
#[folder = "web/dist"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub hub: std::sync::Arc<crate::hub::Hub>,
    /// Where agents connect, if the panel takes them (for the join codes).
    pub agent_port: Option<u16>,
    /// How many password checks (which cost real CPU and memory) run at once. Each panel has its
    /// own, so a flood of tries cannot make this panel unusable, and two panels in one process
    /// (the tests) do not take each other's turns.
    pub login_gate: Arc<Semaphore>,
}

impl AppState {
    /// A panel with no agent listener and no tunnels of its own directory (tests, and
    /// panels set up before agents existed).
    pub fn new(db: Db) -> Self {
        let hub = crate::hub::Hub::new(db.clone(), std::path::PathBuf::from("/etc/kariz"));
        Self {
            db,
            hub,
            agent_port: None,
            login_gate: Arc::new(Semaphore::new(4)),
        }
    }
}

/// The nginx 404 page.
const NOT_FOUND: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n\
                         <center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n\
                         </body>\r\n</html>\r\n";

pub(crate) fn not_found() -> Response<Body> {
    let mut response = Response::new(Body::from(NOT_FOUND));
    *response.status_mut() = StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    headers.insert(header::SERVER, HeaderValue::from_static("nginx"));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    response
}

/// The panel's routes, all under `/<path>/`.
pub fn router(path: &str, state: AppState) -> Router {
    // Without the closing slash the page's relative addresses (`./api/...`, `./assets/...`)
    // would point outside the secret path and the app would not load: send it to the slash.
    let slash = format!("/{path}/");
    let public = crate::share::routes(state.clone());
    let inner = Router::new()
        .route(
            "/",
            get(move || {
                let slash = slash.clone();
                async move { axum::response::Redirect::permanent(&slash) }
            }),
        )
        .route("/api/version", get(version))
        // Prometheus reads this with its token (Settings → Metrics); off, it is a 404.
        .route("/metrics", get(crate::metrics::serve))
        // The web terminal: a WebSocket to a server's shell (where its agent allows it).
        .route("/api/terminal", get(crate::terminal::open))
        .merge(crate::api::routes())
        .route("/api/{*rest}", get(|| async { not_found() }))
        .fallback(get(asset))
        .with_state(state);
    Router::new()
        // `nest` does not hand the address with a trailing slash to the inner router,
        // and that is the address of the panel's front page.
        .route(
            &format!("/{path}/"),
            get(|| async { asset(Uri::from_static("/")).await }),
        )
        .nest(&format!("/{path}"), inner)
        // The renter's pages: links of their own, outside the secret path.
        .merge(public)
        .fallback(|| async { not_found() })
        // The front page is served by the outer router, so the headers go on all of it.
        .layer(axum::middleware::from_fn(security_headers))
}

/// Headers every answer of the panel carries (an answer that sets one itself keeps its own).
/// The plain 404 of an unknown address is left alone: it must look like nginx's.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response<Body> {
    let mut response = next.run(request).await;
    if response
        .headers()
        .get(header::SERVER)
        .is_some_and(|v| v == "nginx")
    {
        return response;
    }
    let headers = response.headers_mut();
    let mut put = |name: header::HeaderName, value: &'static str| {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    };
    // Answers of the API are never kept, and are never a page.
    put(header::CACHE_CONTROL, "no-store");
    put(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    put(header::REFERRER_POLICY, "no-referrer");
    put(header::X_FRAME_OPTIONS, "DENY");
    put(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    put(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    put(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    put(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    put(
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    );
    response
}

async fn version(State(_): State<AppState>) -> impl IntoResponse {
    Json(json!({ "name": "kariz-panel", "version": crate::version() }))
}

/// A file of the web app, or its index page for a path the app handles itself.
async fn asset(uri: Uri) -> Response<Body> {
    let wanted = uri.path().trim_start_matches('/');
    let file = if wanted.is_empty() {
        "index.html"
    } else {
        wanted
    };
    let (name, found) = match Assets::get(file) {
        Some(found) => (file, found),
        // A path with a file extension is a missing file; anything else is a page of
        // the app (it draws itself from the address).
        None if !file.rsplit('/').next().unwrap_or("").contains('.') => {
            match Assets::get("index.html") {
                Some(index) => ("index.html", index),
                None => return not_found(),
            }
        }
        None => return not_found(),
    };
    let mime = mime_of(name);
    let mut response = Response::new(Body::from(found.data.into_owned()));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    // Built files carry a hash in their name and never change; the page itself must
    // always be fetched again.
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // The app loads nothing from anywhere else, and cannot be framed.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; \
             img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; \
             worker-src 'none'; manifest-src 'none'; frame-ancestors 'none'; base-uri 'none'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn mime_of(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff2" => "font/woff2",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// How much a connection may cost the panel before it has said anything useful. Someone
/// who opens connections and sends nothing must not be able to use up the panel's sockets.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The TLS handshake must be done in this long.
    pub handshake: Duration,
    /// A request's headers must arrive in this long.
    pub headers: Duration,
    /// At most this many connections at once; another is closed at once.
    pub connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            headers: Duration::from_secs(15),
            connections: 512,
        }
    }
}

/// Serves `app` over TLS on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, config: &Config, app: Router) -> Result<()> {
    serve_with(listener, config, app, Limits::default()).await
}

pub async fn serve_with(
    listener: TcpListener,
    config: &Config,
    app: Router,
    limits: Limits,
) -> Result<()> {
    let load = || {
        kariz::transport::tls::acceptor(&config.cert(), &config.key())
            .context("failed to load the certificate")
    };
    // The certificate can be replaced while the panel runs: SIGHUP loads it again, and
    // the connections after that use the new one.
    let acceptor = std::sync::Arc::new(std::sync::Mutex::new(load()?));
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut hup) = signal(SignalKind::hangup()) {
            let (shared, cert, key) = (acceptor.clone(), config.cert(), config.key());
            tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    match kariz::transport::tls::acceptor(&cert, &key) {
                        Ok(a) => {
                            *shared.lock().unwrap_or_else(|e| e.into_inner()) = a;
                            info!("the certificate was loaded again");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "the new certificate was not loaded; keeping the old one")
                        }
                    }
                }
            });
        }
    }
    let local = listener.local_addr()?;
    info!(address = %local, path = %config.path, "the panel is listening");
    let room = Arc::new(Semaphore::new(limits.connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = room.clone().try_acquire_owned() else {
            debug!(%peer, "too many connections; this one is closed");
            continue;
        };
        let acceptor = acceptor.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let app = app.clone();
        tokio::spawn(async move {
            serve_connection(acceptor, stream, peer, app, limits, permit).await;
        });
    }
}

async fn serve_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    app: Router,
    limits: Limits,
    _permit: OwnedSemaphorePermit,
) {
    let tls = match tokio::time::timeout(limits.handshake, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return debug!(%peer, error = %e, "TLS handshake failed"),
        Err(_) => return debug!(%peer, "TLS handshake took too long"),
    };
    let service = hyper::service::service_fn(move |mut request: axum::http::Request<Incoming>| {
        let mut app = app.clone();
        // The handlers see who is asking (for the lockout and the session list).
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        async move { app.call(request).await }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.headers);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));
    // With upgrades: the web terminal is a WebSocket.
    if let Err(e) = builder
        .serve_connection_with_upgrades(TokioIo::new(tls), service)
        .await
    {
        debug!(%peer, error = %e, "connection ended with an error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn get_path(path: &str) -> (StatusCode, String, Option<String>) {
        let app = router("k-7f3a9c", AppState::new(Db::in_memory().unwrap()));
        let response = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned(), cache)
    }

    async fn headers_of(path: &str) -> (StatusCode, axum::http::HeaderMap) {
        let app = router("k-7f3a9c", AppState::new(Db::in_memory().unwrap()));
        let response = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        (response.status(), response.headers().clone())
    }

    #[tokio::test]
    async fn every_answer_under_the_secret_path_is_hardened_and_the_404_stays_nginx() {
        for path in [
            "/k-7f3a9c/api/version",
            "/k-7f3a9c/api/session",
            "/k-7f3a9c/",
        ] {
            let (status, h) = headers_of(path).await;
            assert!(status.is_success(), "{path} {status}");
            let get = |n: &str| h.get(n).map(|v| v.to_str().unwrap().to_owned());
            assert_eq!(
                get("x-content-type-options").as_deref(),
                Some("nosniff"),
                "{path}"
            );
            assert_eq!(get("x-frame-options").as_deref(), Some("DENY"), "{path}");
            assert_eq!(
                get("referrer-policy").as_deref(),
                Some("no-referrer"),
                "{path}"
            );
            assert!(get("strict-transport-security").is_some(), "{path}");
            assert_eq!(
                get("cross-origin-opener-policy").as_deref(),
                Some("same-origin")
            );
            assert!(get("permissions-policy").unwrap().contains("camera=()"));
            let csp = get("content-security-policy").unwrap();
            assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        }
        // The API is never cached; a page never gets a script from anywhere else.
        let (_, h) = headers_of("/k-7f3a9c/api/version").await;
        assert_eq!(h.get("cache-control").unwrap(), "no-store");
        assert!(h
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'none'"));
        let (_, h) = headers_of("/k-7f3a9c/").await;
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        for part in [
            "script-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(csp.contains(part), "{csp}");
        }
        // Anything else is the plain nginx 404, with nothing that gives the panel away.
        let (status, h) = headers_of("/admin").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(h.get("server").unwrap(), "nginx");
        assert!(h.get("strict-transport-security").is_none());
        assert!(h.get("x-frame-options").is_none());
    }

    #[tokio::test]
    async fn only_the_secret_path_answers() {
        for path in [
            "/",
            "/login",
            "/api/version",
            "/k-other/",
            "/k-7f3a9cc/",
            "/admin",
        ] {
            let (status, body, _) = get_path(path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(body.contains("<center>nginx</center>"), "{path}: {body}");
        }
        // No closing slash: on to the slash, where the page's relative addresses work.
        let (status, headers) = headers_of("/k-7f3a9c").await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(headers.get("location").unwrap(), "/k-7f3a9c/");
        for path in ["/k-7f3a9c/", "/k-7f3a9c/servers"] {
            let (status, body, cache) = get_path(path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.contains("Kariz"), "{path}");
            assert_eq!(cache.as_deref(), Some("no-store"), "{path}");
        }
    }

    #[tokio::test]
    async fn the_api_and_missing_files() {
        let (status, body, _) = get_path("/k-7f3a9c/api/version").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["name"], "kariz-panel");
        // An unknown API path and a missing file are 404s, not the app's page.
        for path in ["/k-7f3a9c/api/nothing", "/k-7f3a9c/assets/missing.js"] {
            assert_eq!(get_path(path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
    }
}
