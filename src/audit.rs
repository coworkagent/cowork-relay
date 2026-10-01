use serde_json::{Value, json};
use std::{
    io::Write,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(30);
const SAMPLES: u64 = 4;
const KINDS: usize = 8;

#[derive(Clone, Copy)]
pub enum Kind {
    SocketCapacity,
    AdmissionCapacity,
    TlsRejected,
    TlsTimeout,
    HttpRejected,
    RequestRejected,
    AuthenticationRequired,
    TargetUnavailable,
}

const ALL_KINDS: [Kind; KINDS] = [
    Kind::SocketCapacity,
    Kind::AdmissionCapacity,
    Kind::TlsRejected,
    Kind::TlsTimeout,
    Kind::HttpRejected,
    Kind::RequestRejected,
    Kind::AuthenticationRequired,
    Kind::TargetUnavailable,
];

impl Kind {
    fn code(self) -> &'static str {
        match self {
            Self::SocketCapacity => "socket_capacity",
            Self::AdmissionCapacity => "admission_capacity",
            Self::TlsRejected => "tls_rejected",
            Self::TlsTimeout => "tls_timeout",
            Self::HttpRejected => "http_rejected",
            Self::RequestRejected => "request_rejected",
            Self::AuthenticationRequired => "authentication_required",
            Self::TargetUnavailable => "target_unavailable",
        }
    }
}

struct Event {
    kind: Kind,
    peer: IpAddr,
    at: u64,
}

type Counts = [AtomicU64; KINDS];

pub struct Audit {
    sender: SyncSender<Event>,
    counts: Arc<Counts>,
}

impl Audit {
    pub fn start() -> Arc<Self> {
        let (sender, receiver) = sync_channel(32);
        let counts = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
        let writer_counts = counts.clone();
        // 文件写入放在独立线程；日志管道阻塞或关闭不影响连接处理。
        let _ = std::thread::Builder::new()
            .name("relay-audit".into())
            .spawn(move || write_events(receiver, writer_counts));
        Arc::new(Self { sender, counts })
    }

    pub fn record(&self, kind: Kind, peer: IpAddr) {
        // 固定数量计数器与有界样本，不按外来 IP 分配内存，也不决定请求是否放行。
        let previous = self.counts[kind as usize].fetch_add(1, Ordering::Relaxed);
        if previous < SAMPLES {
            let _ = self.sender.try_send(Event {
                kind,
                peer,
                at: crate::store::now(),
            });
        }
    }
}

fn event_value(event: Event) -> Value {
    json!({"event":"relay.security","reason":event.kind.code(),
        "sourceIp":event.peer.to_string(),"at":event.at,
        "message":{"en":"Relay connection or request rejected","zh-CN":"中继连接或请求被拒绝"}})
}

fn summary(counts: &Counts) -> Option<Value> {
    let values: serde_json::Map<String, Value> = ALL_KINDS
        .iter()
        .filter_map(|kind| {
            let count = counts[*kind as usize].swap(0, Ordering::Relaxed);
            (count > 0).then(|| (kind.code().into(), json!(count)))
        })
        .collect();
    (!values.is_empty()).then(|| {
        json!({"event":"relay.security.summary","at":crate::store::now(),"counts":values,
            "message":{"en":"Rejected connection and request totals","zh-CN":"连接与请求拒绝次数汇总"}})
    })
}

fn emit(value: Value) {
    // 只序列化固定分类、服务器时间和 socket 来源；不接收路径、头、凭据或错误文本。
    let line = format!("{value}\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
}

fn write_events(receiver: Receiver<Event>, counts: Arc<Counts>) {
    let mut deadline = Instant::now() + WINDOW;
    loop {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) => emit(event_value(event)),
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(value) = summary(&counts) {
                    emit(value);
                }
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() >= deadline {
            if let Some(value) = summary(&counts) {
                emit(value);
            }
            deadline = Instant::now() + WINDOW;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_log_consumer_never_blocks_recording_and_counts_every_attempt() {
        let (sender, receiver) = sync_channel(1);
        let counts = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
        let audit = Audit { sender, counts };
        let peer = "127.0.0.1".parse().unwrap();
        for _ in 0..100_000 {
            audit.record(Kind::RequestRejected, peer);
        }
        assert_eq!(receiver.try_iter().count(), 1);
        let value = summary(&audit.counts).unwrap();
        assert_eq!(value["counts"]["request_rejected"], 100_000);
        assert!(summary(&audit.counts).is_none());
        audit.record(Kind::RequestRejected, peer);
        let event = event_value(receiver.try_recv().unwrap());
        assert_eq!(event["sourceIp"], "127.0.0.1");
        assert_eq!(event.as_object().unwrap().len(), 5);
        assert!(event["message"]["en"].is_string());
        assert!(event["message"]["zh-CN"].is_string());
        drop(receiver);
        audit.record(Kind::TlsRejected, peer);
        assert_eq!(summary(&audit.counts).unwrap()["counts"]["tls_rejected"], 1);
    }
}
