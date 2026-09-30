use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use cowork_relay::{
    admin::{self, Command},
    config::{self, Config},
    runtime::Runtime,
    store::{Registry, Role, write_new_private},
    transport,
};
use std::{
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
enum Language {
    #[value(name = "en")]
    En,
    #[value(name = "zh-CN")]
    Zh,
}
impl Language {
    fn text(self, en: &'static str, zh: &'static str) -> &'static str {
        match self {
            Self::En => en,
            Self::Zh => zh,
        }
    }
}
#[derive(Parser)]
#[command(
    version,
    about = "Self-hosted Cowork connection relay / 可自部署的 Cowork 连接中继"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Private state directory (0700) / 私有状态目录（0700）"
    )]
    data_dir: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "en",
        help = "Output language / 输出语言"
    )]
    lang: Language,
    #[arg(
        long,
        global = true,
        help = "Machine-readable JSON / 输出机器可读 JSON"
    )]
    json: bool,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    #[command(
        about = "Renew the generated IP certificate while stopped / 停服后续签自动生成的 IP 证书"
    )]
    RenewIp,
    #[command(about = "Generate an IP certificate and private CA / 生成 IP 证书和私有 CA")]
    InitIp {
        #[arg(long, help = "Reachable relay IP / 可访问的中继 IP")]
        ip: IpAddr,
        #[arg(
            long,
            default_value = "8443",
            help = "Public HTTPS port / 公网 HTTPS 端口"
        )]
        port: u16,
        #[arg(
            long,
            default_value = "127.0.0.1:8443",
            help = "Listener IP:port / 监听 IP:端口"
        )]
        listen: SocketAddr,
    },
    #[command(about = "Use an existing HTTPS domain certificate / 使用现有的 HTTPS 域名证书")]
    InitDomain {
        #[arg(long, help = "HTTPS origin without path / 不带路径的 HTTPS 地址")]
        origin: String,
        #[arg(
            long,
            default_value = "127.0.0.1:8443",
            help = "Listener IP:port / 监听 IP:端口"
        )]
        listen: SocketAddr,
        #[arg(long, help = "Full certificate chain PEM / 完整证书链 PEM")]
        certificate: PathBuf,
        #[arg(long, help = "Private key PEM (0600) / 私钥 PEM（0600）")]
        private_key: PathBuf,
    },
    #[command(about = "Export public trust metadata / 导出公开的证书信任信息")]
    TrustExport {
        #[arg(long, help = "New output file / 新的输出文件")]
        out: PathBuf,
    },
    #[command(
        about = "Run the TLS relay and local administration socket / 运行 TLS 中继与本机管理接口"
    )]
    Serve,
    #[command(about = "Show running relay status / 查看运行状态")]
    Status,
    #[command(about = "Manage registered devices / 管理已登记设备")]
    Devices {
        #[command(subcommand)]
        command: Devices,
    },
    #[command(about = "List active and pending streams / 列出当前与等待中的连接")]
    Connections,
}
#[derive(Subcommand)]
enum Devices {
    #[command(about = "List devices, status and connections / 列出设备、状态与连接数")]
    List,
    #[command(about = "Inspect one device / 查看单个设备")]
    Inspect { id: String },
    #[command(about = "Register a host computer / 登记电脑端设备")]
    AddHost {
        #[arg(long)]
        name: String,
        #[arg(long)]
        group: String,
        #[arg(long, default_value = "30")]
        days: u64,
        #[arg(
            long,
            help = "New private credential file (0600) / 新的私有凭据文件（0600）"
        )]
        credential_out: PathBuf,
    },
    #[command(about = "Register a client scoped to one computer / 登记仅可连接指定电脑的客户端")]
    AddClient {
        #[arg(long)]
        name: String,
        #[arg(long)]
        group: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "30")]
        days: u64,
        #[arg(
            long,
            help = "New private credential file (0600) / 新的私有凭据文件（0600）"
        )]
        credential_out: PathBuf,
    },
    #[command(about = "Disconnect now; reconnection remains allowed / 立即断开，仍允许重新连接")]
    Kick { id: String },
    #[command(about = "Persistently block a device and disconnect it / 持久禁用设备并断开连接")]
    Disable { id: String },
    #[command(about = "Re-enable the existing unexpired credential / 重新启用原有且未过期的凭据")]
    Enable { id: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli).await {
        eprintln!("{}: {error}", cli.lang.text("Operation failed", "操作失败"));
        std::process::exit(1);
    }
}

async fn run(cli: &Cli) -> Result<()> {
    let directory = cli
        .data_dir
        .as_deref()
        .context("--data-dir is required / 必须指定 --data-dir")?;
    let output = match &cli.command {
        Action::RenewIp => config::renew_ip(directory)?.public_trust()?,
        Action::InitIp { ip, port, listen } => {
            config::init_ip(directory, *ip, *port, *listen)?.public_trust()?
        }
        Action::InitDomain {
            origin,
            listen,
            certificate,
            private_key,
        } => config::init_domain(
            directory,
            origin.clone(),
            *listen,
            certificate.clone(),
            private_key.clone(),
        )?
        .public_trust()?,
        Action::TrustExport { out } => {
            let trust = Config::load(directory)?.public_trust()?;
            write_new_private(out, &serde_json::to_vec_pretty(&trust)?)?;
            serde_json::json!({"path":out})
        }
        Action::Serve => return serve(directory, cli.lang).await,
        Action::Status => admin::request(directory, &Command::Status).await?,
        Action::Connections => admin::request(directory, &Command::Connections).await?,
        Action::Devices { command } => match command {
            Devices::List => admin::request(directory, &Command::Devices).await?,
            Devices::Inspect { id } => {
                admin::request(directory, &Command::Inspect { id: id.clone() }).await?
            }
            Devices::Kick { id } => {
                admin::request(directory, &Command::Kick { id: id.clone() }).await?
            }
            Devices::Disable { id } => {
                admin::request(directory, &Command::Disable { id: id.clone() }).await?
            }
            Devices::Enable { id } => {
                admin::request(directory, &Command::Enable { id: id.clone() }).await?
            }
            Devices::AddHost {
                name,
                group,
                days,
                credential_out,
            } => {
                enroll(
                    directory,
                    Command::Add {
                        name: name.clone(),
                        role: Role::Host,
                        group: group.clone(),
                        host_id: None,
                        days: *days,
                    },
                    credential_out,
                )
                .await?
            }
            Devices::AddClient {
                name,
                group,
                host,
                days,
                credential_out,
            } => {
                enroll(
                    directory,
                    Command::Add {
                        name: name.clone(),
                        role: Role::Client,
                        group: group.clone(),
                        host_id: Some(host.clone()),
                        days: *days,
                    },
                    credential_out,
                )
                .await?
            }
        },
    };
    if !cli.json {
        println!("{}", cli.lang.text("Operation completed", "操作完成"));
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn enroll(directory: &Path, command: Command, out: &Path) -> Result<serde_json::Value> {
    // 先占用全新输出路径，避免登记成功后发现已有文件而覆盖凭据。
    let mut options = fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = options.create_new(true).write(true).mode(0o600).open(out)?;
    let result = admin::request(directory, &command).await;
    let registration = match result {
        Ok(value) => value,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(out);
            return Err(error);
        }
    };
    if let Err(error) = file
        .write_all(&serde_json::to_vec_pretty(&registration)?)
        .and_then(|()| file.sync_all())
    {
        if let Some(id) = registration["device"]["id"].as_str() {
            let _ = admin::request(directory, &Command::Disable { id: id.into() }).await;
        }
        drop(file);
        let _ = fs::remove_file(out);
        return Err(error.into());
    }
    Ok(serde_json::json!({"device":registration["device"],"credentialFile":out}))
}

async fn serve(directory: &Path, lang: Language) -> Result<()> {
    let config = Config::load(directory)?;
    config.tls()?;
    let registry = Registry::open(directory)?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("Cannot bind relay listener")?;
    let admin_listener = admin::bind(directory)?;
    let relay = Runtime::new(config, registry);
    eprintln!(
        "{}: {}",
        lang.text("Relay listening", "中继正在监听"),
        listener.local_addr()?
    );
    let reap_relay = relay.clone();
    relay.tasks.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = reap_relay.shutdown.cancelled() => break,
                _ = tick.tick() => {
                    if let Ok(mut core) = reap_relay.core.lock() { core.reap(); }
                    else { reap_relay.shutdown.cancel(); break; }
                }
            }
        }
    });
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        value = transport::serve(relay.clone(),listener) => value,
        value = admin::serve(relay.clone(),admin_listener) => value,
        value = tokio::signal::ctrl_c() => value.map_err(Into::into),
        _ = terminate.recv() => Ok(()),
        _ = relay.shutdown.cancelled() => Ok(()),
    };
    relay.shutdown.cancel();
    if let Ok(mut core) = relay.core.lock() {
        core.close_all();
    }
    relay.tasks.close();
    let _ = tokio::time::timeout(Duration::from_secs(5), relay.tasks.wait()).await;
    let _ = fs::remove_file(directory.join("admin.sock"));
    result
}
