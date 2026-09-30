use crate::{
    runtime::Runtime,
    store::{MAX_FILE_BYTES, Role, private_directory},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Command {
    Status,
    Devices,
    Connections,
    Inspect {
        id: String,
    },
    Add {
        name: String,
        role: Role,
        group: String,
        host_id: Option<String>,
        days: u64,
        #[serde(default = "enabled_default")]
        auto_renew: bool,
    },
    Renew {
        id: String,
        days: u64,
    },
    AutoRenew {
        id: String,
        enabled: bool,
    },
    Kick {
        id: String,
    },
    Disable {
        id: String,
    },
    Enable {
        id: String,
    },
}

fn enabled_default() -> bool {
    true
}

pub fn bind(directory: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    private_directory(directory)?;
    let path = directory.join("admin.sock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        ensure!(
            meta.file_type().is_socket() && !meta.file_type().is_symlink(),
            "Unsafe admin socket path"
        );
        fs::remove_file(&path)?;
    }
    let socket = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(socket)
}

pub async fn serve(runtime: Arc<Runtime>, listener: UnixListener) -> Result<()> {
    let permits = Arc::new(Semaphore::new(8));
    loop {
        let (mut stream, _) = tokio::select! {
            _ = runtime.shutdown.cancelled() => break,
            result = listener.accept() => result?,
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let relay = runtime.clone();
        runtime.tasks.spawn(async move {
            let _permit = permit;
            let request = async {
                let bytes = read_frame(&mut stream,16 * 1024).await?;
                let command = serde_json::from_slice::<Command>(&bytes)?;
                let reply = match execute(&relay,command) {
                    Ok(value) => serde_json::json!({"ok":true,"result":value}),
                    Err(_) => serde_json::json!({"ok":false,"code":"relay.admin_failed"}),
                };
                write_frame(&mut stream,&serde_json::to_vec(&reply)?).await
            };
            tokio::select! { _ = relay.shutdown.cancelled() => {}, _ = timeout(Duration::from_secs(10),request) => {} }
        });
    }
    Ok(())
}

fn execute(runtime: &Runtime, command: Command) -> Result<serde_json::Value> {
    let mut core = runtime
        .core
        .lock()
        .map_err(|_| anyhow::anyhow!("State unavailable"))?;
    ensure!(!runtime.shutdown.is_cancelled(), "Relay stopping");
    match command {
        Command::Status => Ok(
            serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"protocol":crate::protocol::PROTOCOL,"origin":runtime.config.origin,"devices":core.registry.list()?.len(),"connections":core.connections().len(),"certificate":runtime.certificate_status.lock().ok().map(|value|value.clone())}),
        ),
        Command::Devices => Ok(serde_json::to_value(core.list()?)?),
        Command::Connections => Ok(serde_json::to_value(core.connections())?),
        Command::Inspect { id } => Ok(serde_json::to_value(
            core.list()?
                .into_iter()
                .find(|v| v.device.id == id)
                .context("Unknown device")?,
        )?),
        Command::Add {
            name,
            role,
            group,
            host_id,
            days,
            auto_renew,
        } => {
            let result = core.registry.add(name, role, group, host_id, days);
            let (device, secret) = match result {
                Ok(value) => value,
                Err(error) => {
                    core.reap();
                    return Err(error);
                }
            };
            let device = if auto_renew {
                device
            } else {
                core.registry.set_auto_renew(&device.id, false)?
            };
            let trust = runtime.config.public_trust()?;
            Ok(serde_json::json!({"format":1,"relay":trust,"device":device,"secret":secret}))
        }
        Command::Renew { id, days } => Ok(serde_json::to_value(core.registry.renew(&id, days)?)?),
        Command::AutoRenew { id, enabled } => Ok(serde_json::to_value(
            core.registry.set_auto_renew(&id, enabled)?,
        )?),
        Command::Kick { id } => {
            ensure!(core.registry.device(&id).is_some(), "Unknown device");
            Ok(serde_json::json!({"id":id,"disconnected":core.kick(&id)}))
        }
        Command::Disable { id } => Ok(serde_json::to_value(core.set_enabled(&id, false)?)?),
        Command::Enable { id } => Ok(serde_json::to_value(core.set_enabled(&id, true)?)?),
    }
}

pub async fn request(directory: &Path, command: &Command) -> Result<serde_json::Value> {
    private_directory(directory)?;
    let operation = async {
        let mut socket = UnixStream::connect(directory.join("admin.sock"))
            .await
            .context("Start the relay before running administration commands")?;
        write_frame(&mut socket, &serde_json::to_vec(command)?).await?;
        let response: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut socket, MAX_FILE_BYTES as usize).await?)?;
        ensure!(response["ok"] == true, "Administration request failed");
        Ok(response["result"].clone())
    };
    timeout(Duration::from_secs(10), operation).await?
}

async fn read_frame(stream: &mut (impl AsyncRead + Unpin), maximum: usize) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    ensure!(size > 0 && size <= maximum, "Invalid admin frame");
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FILE_BYTES as usize,
        "Invalid admin frame"
    );
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await?;
    Ok(())
}
