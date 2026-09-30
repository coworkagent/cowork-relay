use crate::{
    config::Config,
    store::{Device, Registry, Role, now, random_secret, secret_hash, valid_id, valid_secret},
};
use anyhow::{Context, Result, ensure};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub type Socket = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;
pub type Attachment = (Socket, Arc<OwnedSemaphorePermit>);
pub const TICKET_SECONDS: u64 = crate::protocol::TICKET_SECONDS as u64;

pub struct Runtime {
    pub config: Config,
    pub certificate_status: Mutex<serde_json::Value>,
    pub shutdown: CancellationToken,
    pub core: Mutex<Core>,
    pub tasks: tokio_util::task::TaskTracker,
}

pub struct Core {
    pub registry: Registry,
    hosts: HashMap<String, Host>,
    streams: HashMap<String, Stream>,
}
struct Host {
    epoch: String,
    generation: u64,
    peer: SocketAddr,
    connected_at: u64,
    cancel: CancellationToken,
    tx: mpsc::Sender<serde_json::Value>,
}
struct Stream {
    id: String,
    host_id: String,
    client_id: String,
    host_generation: u64,
    client_generation: u64,
    epoch: String,
    ticket_hash: String,
    expires_at: u64,
    attached: bool,
    created_at: u64,
    client_peer: SocketAddr,
    cancel: CancellationToken,
    attach: Option<oneshot::Sender<Attachment>>,
    counters: Arc<Counters>,
}
#[derive(Default)]
pub struct Counters {
    pub to_host: AtomicU64,
    pub to_client: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    pub id: String,
    pub host_id: String,
    pub client_id: String,
    pub client_peer: SocketAddr,
    pub created_at: u64,
    pub attached: bool,
    pub to_host_bytes: u64,
    pub to_client_bytes: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub device: Device,
    pub online: bool,
    pub source_address: Option<SocketAddr>,
    pub connected_at: Option<u64>,
    pub connections: usize,
}

pub struct HostLease {
    runtime: Arc<Runtime>,
    pub id: String,
    pub epoch: String,
    pub cancel: CancellationToken,
}
impl Drop for HostLease {
    fn drop(&mut self) {
        if let Ok(mut core) = self.runtime.core.lock()
            && core
                .hosts
                .get(&self.id)
                .is_some_and(|h| h.epoch == self.epoch)
        {
            core.kick(&self.id);
        }
    }
}
pub struct StreamLease {
    runtime: Arc<Runtime>,
    pub id: String,
    pub cancel: CancellationToken,
    pub counters: Arc<Counters>,
}
impl Drop for StreamLease {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut core) = self.runtime.core.lock() {
            core.streams.remove(&self.id);
        }
    }
}

impl Core {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            hosts: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    pub fn list(&self) -> Result<Vec<DeviceView>> {
        Ok(self
            .registry
            .list()?
            .into_iter()
            .map(|device| {
                let host = self.hosts.get(&device.id);
                let streams: Vec<_> = self
                    .streams
                    .values()
                    .filter(|s| s.host_id == device.id || s.client_id == device.id)
                    .collect();
                let connections = streams.len();
                DeviceView {
                    online: host.is_some() || connections > 0,
                    source_address: host
                        .map(|h| h.peer)
                        .or_else(|| streams.first().map(|s| s.client_peer)),
                    connected_at: host
                        .map(|h| h.connected_at)
                        .or_else(|| streams.iter().map(|s| s.created_at).min()),
                    device,
                    connections,
                }
            })
            .collect())
    }
    pub fn connections(&self) -> Vec<ConnectionView> {
        self.streams
            .values()
            .map(|s| ConnectionView {
                id: s.id.clone(),
                host_id: s.host_id.clone(),
                client_id: s.client_id.clone(),
                client_peer: s.client_peer,
                created_at: s.created_at,
                attached: s.attached,
                to_host_bytes: s.counters.to_host.load(Ordering::Relaxed),
                to_client_bytes: s.counters.to_client.load(Ordering::Relaxed),
            })
            .collect()
    }
    pub fn kick(&mut self, id: &str) -> usize {
        let mut affected = 0;
        if let Some(host) = self.hosts.remove(id) {
            host.cancel.cancel();
            affected += 1;
        }
        self.streams.retain(|_, s| {
            if s.host_id == id || s.client_id == id {
                s.cancel.cancel();
                affected += 1;
                false
            } else {
                true
            }
        });
        affected
    }
    pub fn close_all(&mut self) {
        for (_, host) in self.hosts.drain() {
            host.cancel.cancel();
        }
        for (_, stream) in self.streams.drain() {
            stream.cancel.cancel();
        }
    }
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<Device> {
        let result = self.registry.set_enabled(id, enabled);
        if result.is_err() {
            self.close_all();
        } else {
            self.kick(id);
        }
        result
    }
    pub fn reap(&mut self) {
        if self.registry.renew_due(crate::store::now()).is_err() {
            self.close_all();
            return;
        }
        let invalid: Vec<_> = self
            .hosts
            .iter()
            .filter(|(id, host)| {
                self.registry
                    .active(id)
                    .is_none_or(|d| d.generation != host.generation)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in invalid {
            self.kick(&id);
        }
        self.streams.retain(|_, s| {
            let live = !s.cancel.is_cancelled()
                && self
                    .registry
                    .active(&s.host_id)
                    .is_some_and(|d| d.generation == s.host_generation)
                && self
                    .registry
                    .active(&s.client_id)
                    .is_some_and(|d| d.generation == s.client_generation)
                && (s.attached || s.expires_at > now());
            if !live {
                s.cancel.cancel();
            }
            live
        });
    }
}

impl Runtime {
    pub fn new(config: Config, registry: Registry) -> Arc<Self> {
        Arc::new(Self {
            certificate_status: Mutex::new(
                serde_json::json!({"expiresAt":config.certificate_expiry().ok(),"autoRenew":config.automatic_certificate_renewal()}),
            ),
            config,
            shutdown: CancellationToken::new(),
            core: Mutex::new(Core::new(registry)),
            tasks: tokio_util::task::TaskTracker::new(),
        })
    }
    pub fn host(
        self: &Arc<Self>,
        id: &str,
        secret: &str,
        peer: SocketAddr,
    ) -> Result<(HostLease, mpsc::Receiver<serde_json::Value>)> {
        let mut core = self
            .core
            .lock()
            .map_err(|_| anyhow::anyhow!("State unavailable"))?;
        let d = core
            .registry
            .authenticate(id, secret)
            .context("Access denied")?;
        ensure!(
            d.role == Role::Host && !self.shutdown.is_cancelled(),
            "Access denied"
        );
        ensure!(
            core.hosts.contains_key(id) || core.hosts.len() < self.config.limits.hosts,
            "Capacity reached"
        );
        core.kick(id);
        let epoch = Uuid::new_v4().to_string();
        let cancel = self.shutdown.child_token();
        let (tx, rx) = mpsc::channel(64);
        core.hosts.insert(
            id.into(),
            Host {
                epoch: epoch.clone(),
                generation: d.generation,
                peer,
                connected_at: now(),
                cancel: cancel.clone(),
                tx,
            },
        );
        Ok((
            HostLease {
                runtime: self.clone(),
                id: id.into(),
                epoch,
                cancel,
            },
            rx,
        ))
    }
    pub fn connect(
        self: &Arc<Self>,
        id: &str,
        secret: &str,
        target: &str,
        peer: SocketAddr,
    ) -> Result<(StreamLease, oneshot::Receiver<Attachment>)> {
        let mut core = self
            .core
            .lock()
            .map_err(|_| anyhow::anyhow!("State unavailable"))?;
        let d = core
            .registry
            .authenticate(id, secret)
            .context("Access denied")?;
        ensure!(
            d.role == Role::Client && !self.shutdown.is_cancelled(),
            "Access denied"
        );
        let host_id = d.host_id.context("Access denied")?;
        ensure!(
            target == format!("{host_id}.cowork.invalid:443"),
            "Access denied"
        );
        let host_device = core.registry.active(&host_id).context("Access denied")?;
        let host = core.hosts.get(&host_id).context("Target unavailable")?;
        ensure!(
            !host.cancel.is_cancelled() && host.generation == host_device.generation,
            "Target unavailable"
        );
        let l = &self.config.limits;
        ensure!(
            core.streams.len() < l.streams
                && core
                    .streams
                    .values()
                    .filter(|s| s.host_id == host_id)
                    .count()
                    < l.streams_per_host
                && core.streams.values().filter(|s| s.client_id == id).count()
                    < l.streams_per_client,
            "Capacity reached"
        );
        let epoch = host.epoch.clone();
        let cancel = host.cancel.child_token();
        let connection_id = Uuid::new_v4().to_string();
        let ticket = random_secret();
        let expires_at = now() + TICKET_SECONDS;
        host.tx.try_send(serde_json::json!({"type":"open","epoch":epoch,"connectionId":connection_id,"ticket":ticket,"expiresAt":expires_at})).context("Target unavailable")?;
        let counters = Arc::new(Counters::default());
        let (tx, rx) = oneshot::channel();
        core.streams.insert(
            connection_id.clone(),
            Stream {
                id: connection_id.clone(),
                host_id,
                client_id: id.into(),
                host_generation: host_device.generation,
                client_generation: d.generation,
                epoch,
                ticket_hash: secret_hash(&connection_id, &ticket),
                expires_at,
                attached: false,
                created_at: now(),
                client_peer: peer,
                cancel: cancel.clone(),
                attach: Some(tx),
                counters: counters.clone(),
            },
        );
        Ok((
            StreamLease {
                runtime: self.clone(),
                id: connection_id,
                cancel,
                counters,
            },
            rx,
        ))
    }
    pub fn redeem(
        &self,
        id: &str,
        secret: &str,
        connection_id: &str,
        ticket: &str,
    ) -> Result<(oneshot::Sender<Attachment>, CancellationToken)> {
        ensure!(
            valid_id(connection_id) && valid_secret(ticket),
            "Access denied"
        );
        let mut core = self
            .core
            .lock()
            .map_err(|_| anyhow::anyhow!("State unavailable"))?;
        let d = core
            .registry
            .authenticate(id, secret)
            .context("Access denied")?;
        ensure!(
            d.role == Role::Host && !self.shutdown.is_cancelled(),
            "Access denied"
        );
        let host = core.hosts.get(id).context("Access denied")?;
        let stream = core.streams.get(connection_id).context("Access denied")?;
        ensure!(
            stream.host_id == id
                && stream.epoch == host.epoch
                && stream.host_generation == d.generation
                && stream.expires_at > now()
                && !stream.cancel.is_cancelled()
                && bool::from(
                    stream
                        .ticket_hash
                        .as_bytes()
                        .ct_eq(secret_hash(connection_id, ticket).as_bytes())
                ),
            "Access denied"
        );
        ensure!(
            core.registry
                .active(&stream.client_id)
                .is_some_and(|c| c.generation == stream.client_generation),
            "Access denied"
        );
        let stream = core
            .streams
            .get_mut(connection_id)
            .context("Access denied")?;
        let sender = stream.attach.take().context("Access denied")?;
        stream.attached = true;
        Ok((sender, stream.cancel.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::init_ip;
    #[tokio::test]
    async fn tickets_are_scoped_single_use_and_invalidated_by_host_replacement() -> Result<()> {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        let config = init_ip(&dir, "127.0.0.1".parse()?, 8443, "127.0.0.1:8443".parse()?)?;
        let mut store = Registry::open(&dir)?;
        let (a, sa) = store.add("A".into(), Role::Host, "group".into(), None, 30)?;
        let (b, sb) = store.add("B".into(), Role::Host, "group".into(), None, 30)?;
        let (c, sc) = store.add(
            "C".into(),
            Role::Client,
            "group".into(),
            Some(a.id.clone()),
            30,
        )?;
        let runtime = Runtime::new(config, store);
        let peer = "127.0.0.1:1234".parse()?;
        let (host, mut messages) = runtime.host(&a.id, &sa, peer)?;
        let (_other, _) = runtime.host(&b.id, &sb, peer)?;
        assert!(
            runtime
                .connect(&c.id, &sc, &format!("{}.cowork.invalid:443", b.id), peer)
                .is_err()
        );
        let (stream, _) =
            runtime.connect(&c.id, &sc, &format!("{}.cowork.invalid:443", a.id), peer)?;
        let message = messages.recv().await.context("Missing open")?;
        let ticket = message["ticket"].as_str().context("Missing ticket")?;
        assert!(runtime.redeem(&b.id, &sb, &stream.id, ticket).is_err());
        assert!(runtime.redeem(&a.id, &sa, &stream.id, ticket).is_ok());
        assert!(runtime.redeem(&a.id, &sa, &stream.id, ticket).is_err());
        let (_replacement, _) = runtime.host(&a.id, &sa, peer)?;
        assert!(host.cancel.is_cancelled());
        assert!(stream.cancel.is_cancelled());
        assert!(runtime.redeem(&a.id, &sa, &stream.id, ticket).is_err());
        drop(host);
        assert!(runtime.core.lock().unwrap().hosts.contains_key(&a.id));
        runtime.core.lock().unwrap().set_enabled(&c.id, false)?;
        assert!(
            runtime
                .connect(&c.id, &sc, &format!("{}.cowork.invalid:443", a.id), peer)
                .is_err()
        );
        Ok(())
    }
}
