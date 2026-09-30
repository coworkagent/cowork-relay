use crate::{
    config::authority,
    runtime::{HostLease, Runtime, Socket, StreamLease, TICKET_SECONDS},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, Version, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::{interval, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};

type Reply = Response<Full<Bytes>>;
use crate::protocol::{CONTROL_LIMIT, FRAME_LIMIT, PROTOCOL, WEBSOCKET_PROTOCOL};
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(runtime: Arc<Runtime>, listener: TcpListener) -> Result<()> {
    let acceptor = TlsAcceptor::from(runtime.config.tls()?);
    let permits = Arc::new(Semaphore::new(runtime.config.limits.sockets));
    let admissions = Arc::new(Semaphore::new(64));
    loop {
        let (stream, peer) = tokio::select! {
            _ = runtime.shutdown.cancelled() => break,
            value = listener.accept() => value?,
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let permit = Arc::new(permit);
        let Ok(admission) = admissions.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let relay = runtime.clone();
        let acceptor = acceptor.clone();
        runtime.tasks.spawn(async move {
            let _admission = admission;
            let _ = stream.set_nodelay(true);
            let operation = async {
                let tls = timeout(HEADER_TIMEOUT, acceptor.accept(stream)).await??;
                let service_relay = relay.clone();
                let service = service_fn(move |req| {
                    let relay = service_relay.clone();
                    let permit = permit.clone();
                    async move {
                        Ok::<_, Infallible>(
                            route(relay, req, peer, permit)
                                .await
                                .unwrap_or_else(|_| error(StatusCode::FORBIDDEN, "relay.denied")),
                        )
                    }
                });
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .max_headers(32)
                    .max_buf_size(16 * 1024)
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT)
                    .serve_connection(TokioIo::new(tls), service)
                    .with_upgrades()
                    .await?;
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! { _ = relay.shutdown.cancelled() => {}, _ = operation => {} }
        });
    }
    Ok(())
}

fn error(status: StatusCode, code: &str) -> Reply {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("connection", "close")
        .body(Full::new(Bytes::from(format!("{{\"code\":\"{code}\"}}"))))
        .expect("Static response headers")
}
fn single<'a>(req: &'a Request<Incoming>, name: &str) -> Result<Option<&'a str>> {
    let mut all = req.headers().get_all(name).iter();
    let first = all.next().map(|v| v.to_str()).transpose()?;
    ensure!(all.next().is_none(), "Duplicate header");
    Ok(first)
}
fn credentials(req: &Request<Incoming>, client: bool) -> Result<(String, String)> {
    let (name, other, scheme, delimiter) = if client {
        ("proxy-authorization", "authorization", "Basic ", ':')
    } else {
        ("authorization", "proxy-authorization", "Bearer ", '.')
    };
    ensure!(
        single(req, other)?.is_none(),
        "Unexpected authentication header"
    );
    let header = single(req, name)?
        .context("Authentication required")?
        .strip_prefix(scheme)
        .context("Invalid authentication scheme")?;
    ensure!(header.len() <= 256, "Invalid credential length");
    let value = if client {
        let bytes = STANDARD.decode(header)?;
        ensure!(
            STANDARD.encode(&bytes) == header,
            "Noncanonical credentials"
        );
        String::from_utf8(bytes)?
    } else {
        header.to_string()
    };
    let (id, secret) = value.split_once(delimiter).context("Invalid credentials")?;
    Ok((id.into(), secret.into()))
}
fn websocket(req: &Request<Incoming>) -> Result<Reply> {
    ensure!(
        single(req, "upgrade")?.is_some_and(|v| v.eq_ignore_ascii_case("websocket")),
        "Expected WebSocket"
    );
    ensure!(
        single(req, "connection")?.is_some_and(|v| v
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))),
        "Expected upgrade"
    );
    ensure!(
        single(req, "sec-websocket-version")? == Some("13")
            && single(req, "sec-websocket-protocol")? == Some(WEBSOCKET_PROTOCOL)
            && single(req, "sec-websocket-extensions")?.is_none(),
        "Unsupported WebSocket options"
    );
    let key = single(req, "sec-websocket-key")?.context("Missing WebSocket key")?;
    let raw = STANDARD.decode(key)?;
    ensure!(
        raw.len() == 16 && STANDARD.encode(&raw) == key,
        "Invalid WebSocket key"
    );
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-accept", derive_accept_key(key.as_bytes()))
        .header("sec-websocket-protocol", WEBSOCKET_PROTOCOL)
        .body(Full::new(Bytes::new()))?)
}
fn ws_config(control: bool) -> WebSocketConfig {
    let limit = if control { CONTROL_LIMIT } else { FRAME_LIMIT };
    WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(FRAME_LIMIT * 2)
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit))
}

async fn route(
    runtime: Arc<Runtime>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Reply> {
    ensure!(req.version() == Version::HTTP_11, "HTTP/1.1 required");
    for name in ["cookie", "origin", "referer", "transfer-encoding", "expect"] {
        ensure!(single(&req, name)?.is_none(), "Forbidden header");
    }
    ensure!(
        single(&req, "content-length")?.is_none_or(|v| v == "0"),
        "Request bodies are forbidden"
    );
    ensure!(req.uri().query().is_none(), "Queries are forbidden");
    let host = single(&req, "host")?.context("Missing Host")?.to_string();
    if req.method() == Method::CONNECT {
        let target = req
            .uri()
            .authority()
            .context("Missing CONNECT authority")?
            .as_str()
            .to_string();
        let target_id = target
            .strip_suffix(".cowork.invalid:443")
            .context("Invalid CONNECT target")?;
        ensure!(
            req.uri().scheme().is_none()
                && crate::store::valid_id(target_id)
                && (host == target || format!("{host}:443") == target),
            "Invalid CONNECT target"
        );
        ensure!(
            single(&req, "upgrade")?.is_none() && single(&req, "x-cowork-ticket")?.is_none(),
            "Invalid CONNECT headers"
        );
        if single(&req, "proxy-authorization")?.is_none() {
            ensure!(
                single(&req, "authorization")?.is_none(),
                "Unexpected authentication header"
            );
            let mut reply = error(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "relay.authentication_required",
            );
            reply.headers_mut().insert(
                "proxy-authenticate",
                hyper::header::HeaderValue::from_static("Basic realm=\"Cowork Relay\""),
            );
            return Ok(reply);
        }
        let (id, secret) = credentials(&req, true)?;
        let (lease, attached) = match runtime.connect(&id, &secret, &target, peer) {
            Ok(value) => value,
            Err(_) => return Ok(error(StatusCode::FORBIDDEN, "relay.unavailable")),
        };
        let attachment = tokio::select! {
            _ = lease.cancel.cancelled() => return Ok(error(StatusCode::FORBIDDEN,"relay.unavailable")),
            result = timeout(Duration::from_secs(TICKET_SECONDS),attached) => match result {
                Ok(Ok(value)) => value,
                _ => return Ok(error(StatusCode::SERVICE_UNAVAILABLE,"relay.unavailable")),
            },
        };
        let upgrade = hyper::upgrade::on(&mut req);
        runtime.tasks.spawn(async move {
            let (ws, _host_permit) = attachment;
            let _client_permit = permit;
            let operation = async {
                let upgraded = timeout(HEADER_TIMEOUT, upgrade).await??;
                pump(TokioIo::new(upgraded), ws, &lease).await
            };
            tokio::select! { _ = lease.cancel.cancelled() => {}, _ = operation => {} }
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))?);
    }
    let (relay_authority, _) = authority(&runtime.config.origin)?;
    ensure!(
        host == relay_authority
            && req.method() == Method::GET
            && req.uri().scheme().is_none()
            && req.uri().authority().is_none(),
        "Invalid request target"
    );
    if req.uri().path() == "/health/live" {
        ensure!(
            single(&req, "authorization")?.is_none()
                && single(&req, "proxy-authorization")?.is_none()
                && single(&req, "x-cowork-ticket")?.is_none(),
            "Unexpected credentials"
        );
        return Ok(error(StatusCode::OK, "relay.live"));
    }
    let response = websocket(&req)?;
    let (id, secret) = credentials(&req, false)?;
    let path = req.uri().path().to_string();
    if path == "/relay/v1/control" {
        ensure!(
            single(&req, "x-cowork-ticket")?.is_none(),
            "Unexpected ticket"
        );
        let (lease, rx) = runtime.host(&id, &secret, peer)?;
        let upgrade = hyper::upgrade::on(&mut req);
        runtime.tasks.spawn(async move {
            let _permit = permit;
            let operation = async {
                let upgraded = timeout(HEADER_TIMEOUT, upgrade).await??;
                let ws = WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    Role::Server,
                    Some(ws_config(true)),
                )
                .await;
                control(ws, &lease, rx).await
            };
            tokio::select! { _ = lease.cancel.cancelled() => {}, _ = operation => {} }
        });
        return Ok(response);
    }
    if let Some(connection_id) = path.strip_prefix("/relay/v1/data/") {
        let ticket = single(&req, "x-cowork-ticket")?.context("Missing ticket")?;
        let (sender, cancel) = runtime.redeem(&id, &secret, connection_id, ticket)?;
        let upgrade = hyper::upgrade::on(&mut req);
        runtime.tasks.spawn(async move {
            let operation = async {
                let upgraded = timeout(HEADER_TIMEOUT,upgrade).await??;
                let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded),Role::Server,Some(ws_config(false))).await;
                sender.send((ws,permit)).map_err(|_|anyhow::anyhow!("Client disconnected"))?;
                Ok::<(),anyhow::Error>(())
            };
            tokio::select! { _ = cancel.cancelled() => {}, result = operation => { if result.is_err() { cancel.cancel(); } } }
        });
        return Ok(response);
    }
    bail!("Unknown route")
}

async fn control(
    mut socket: Socket,
    lease: &HostLease,
    mut rx: mpsc::Receiver<serde_json::Value>,
) -> Result<()> {
    timeout(HEADER_TIMEOUT,socket.send(Message::Text(serde_json::json!({"type":"ready","protocol":PROTOCOL,"epoch":lease.epoch,"hostId":lease.id}).to_string().into()))).await??;
    let mut tick = interval(Duration::from_secs(30));
    let mut last_pong = Instant::now();
    let mut challenge = Vec::new();
    loop {
        tokio::select! {
            _ = tick.tick() => {
                ensure!(last_pong.elapsed() < Duration::from_secs(90), "Host heartbeat expired");
                challenge = uuid::Uuid::new_v4().as_bytes().to_vec();
                timeout(HEADER_TIMEOUT,socket.send(Message::Ping(challenge.clone().into()))).await??;
            }
            message = rx.recv() => match message {
                Some(message) => timeout(HEADER_TIMEOUT,socket.send(Message::Text(message.to_string().into()))).await??,
                None => break,
            },
            message = socket.next() => match message {
                Some(Ok(Message::Pong(bytes))) if bytes.as_ref() == challenge => last_pong = Instant::now(),
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {},
                Some(Ok(Message::Close(_))) | None => break,
                _ => bail!("Invalid host control message"),
            }
        }
    }
    Ok(())
}

async fn pump(
    client: TokioIo<hyper::upgrade::Upgraded>,
    ws: Socket,
    lease: &StreamLease,
) -> Result<()> {
    let (mut read_client, mut write_client) = tokio::io::split(client);
    let (mut to_host, mut from_host) = ws.split();
    let started = Instant::now();
    let activity = AtomicU64::new(0);
    let upload = async {
        let mut buffer = vec![0u8; FRAME_LIMIT];
        loop {
            let size = read_client.read(&mut buffer).await?;
            if size == 0 {
                break;
            }
            timeout(
                Duration::from_secs(30),
                to_host.send(Message::Binary(Bytes::copy_from_slice(&buffer[..size]))),
            )
            .await??;
            activity.store(started.elapsed().as_secs(), Ordering::Relaxed);
            lease
                .counters
                .to_host
                .fetch_add(size as u64, Ordering::Relaxed);
        }
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        while let Some(message) = from_host.next().await {
            match message? {
                Message::Binary(bytes) => {
                    timeout(Duration::from_secs(30), write_client.write_all(&bytes)).await??;
                    activity.store(started.elapsed().as_secs(), Ordering::Relaxed);
                    lease
                        .counters
                        .to_client
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => break,
                _ => bail!("Expected binary TLS stream"),
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let idle = async {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            ensure!(
                started
                    .elapsed()
                    .as_secs()
                    .saturating_sub(activity.load(Ordering::Relaxed))
                    < 90,
                "Stream idle timeout"
            );
            ensure!(
                started.elapsed() < Duration::from_secs(3600),
                "Stream lifetime exceeded"
            );
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { value = upload => value, value = download => value, value = idle => value }
}
