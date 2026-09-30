use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const MAX_DEVICES: usize = 4096;
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn valid_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok_and(|value| {
        value.get_version_num() == 4
            && value.get_variant() == uuid::Variant::RFC4122
            && value.to_string() == id
    })
}
pub fn valid_secret(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}
pub fn secret_hash(id: &str, secret: &str) -> String {
    format!("{:x}", Sha256::digest(format!("{id}\0{secret}").as_bytes()))
}

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .context("Cannot create private directory")?;
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "Unsafe state directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "State directory must have mode 0700"
        );
    }
    Ok(())
}

pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_FILE_BYTES,
        "Unsafe state file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "State files must have mode 0600"
        );
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE_BYTES, "State file too large");
    Ok(bytes)
}

pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("Missing state parent")?;
    private_directory(parent)?;
    if path.symlink_metadata().is_ok() {
        read_private(path)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() as u64 <= MAX_FILE_BYTES, "State limit exceeded");
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    write_new_private(&temporary, &bytes)?;
    let result = fs::rename(&temporary, path).and_then(|()| File::open(parent)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("Cannot persist state")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Host,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub group: String,
    pub host_id: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub generation: u64,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default = "default_renewal_days")]
    pub renewal_days: u64,
}
fn default_renewal_days() -> u64 {
    30
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredDevice {
    device: Device,
    credential_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct State {
    format: u32,
    devices: Vec<StoredDevice>,
}

pub struct Registry {
    path: PathBuf,
    state: State,
    _lock: File,
    faulted: bool,
}
impl Registry {
    pub fn create(directory: &Path) -> Result<()> {
        private_directory(directory)?;
        write_new_private(
            &directory.join("devices.json"),
            &serde_json::to_vec(&State {
                format: 2,
                devices: vec![],
            })?,
        )
    }
    pub fn open(directory: &Path) -> Result<Self> {
        private_directory(directory)?;
        let lock_path = directory.join("state.lock");
        if lock_path.symlink_metadata().is_ok() {
            read_private(&lock_path)?;
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let lock = opts.open(lock_path)?;
        lock.try_lock_exclusive()
            .context("Relay state is already in use")?;
        let path = directory.join("devices.json");
        let mut state: State =
            serde_json::from_slice(&read_private(&path)?).context("Invalid device state")?;
        ensure!(
            (state.format == 1 || state.format == 2) && state.devices.len() <= MAX_DEVICES,
            "Invalid device state"
        );
        let mut ids = std::collections::HashSet::new();
        for entry in &state.devices {
            let d = &entry.device;
            ensure!(
                valid_id(&d.id) && ids.insert(&d.id),
                "Invalid device identity"
            );
            validate_label(&d.name, &d.group)?;
            ensure!(
                d.expires_at > d.created_at
                    && d.generation > 0
                    && (1..=90).contains(&d.renewal_days),
                "Invalid device lifetime"
            );
            ensure!(
                entry.credential_hash.len() == 64
                    && entry
                        .credential_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Invalid credential hash"
            );
            match d.role {
                Role::Host => ensure!(d.host_id.is_none(), "Invalid host registration"),
                Role::Client => ensure!(
                    state
                        .devices
                        .iter()
                        .any(|h| Some(&h.device.id) == d.host_id.as_ref()
                            && h.device.role == Role::Host
                            && h.device.group == d.group),
                    "Invalid client scope"
                ),
            }
        }
        if state.format == 1 {
            // 仅迁移仍有效的旧登记；过期和禁用设备不会获得自动恢复权限。
            for entry in &mut state.devices {
                entry.device.auto_renew = entry.device.enabled && entry.device.expires_at > now();
            }
            state.format = 2;
            atomic_json(&path, &state)?;
        }
        let mut registry = Self {
            path,
            state,
            _lock: lock,
            faulted: false,
        };
        registry.renew_due(now())?;
        Ok(registry)
    }
    fn live(&self) -> Result<()> {
        ensure!(!self.faulted, "Storage unavailable");
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<Device>> {
        self.live()?;
        Ok(self
            .state
            .devices
            .iter()
            .map(|e| e.device.clone())
            .collect())
    }
    pub fn device(&self, id: &str) -> Option<Device> {
        if self.faulted {
            return None;
        }
        self.state
            .devices
            .iter()
            .find(|e| e.device.id == id)
            .map(|e| e.device.clone())
    }
    pub fn active(&self, id: &str) -> Option<Device> {
        let d = self.device(id)?;
        if !d.enabled || d.expires_at <= now() {
            return None;
        }
        if let Some(host) = &d.host_id {
            let h = self.device(host)?;
            if !h.enabled || h.expires_at <= now() || h.role != Role::Host || h.group != d.group {
                return None;
            }
        }
        Some(d)
    }
    pub fn authenticate(&self, id: &str, secret: &str) -> Option<Device> {
        self.identify(id, secret)?;
        self.active(id)
    }
    // 只读状态认证允许查看本设备到期状态，不能据此建立转发连接。
    pub fn identify(&self, id: &str, secret: &str) -> Option<Device> {
        if !valid_id(id) || !valid_secret(secret) {
            return None;
        }
        let entry = self.state.devices.iter().find(|e| e.device.id == id)?;
        if !bool::from(
            entry
                .credential_hash
                .as_bytes()
                .ct_eq(secret_hash(id, secret).as_bytes()),
        ) {
            return None;
        }
        self.device(id)
    }
    fn commit(&mut self, next: State) -> Result<()> {
        self.live()?;
        if let Err(error) = atomic_json(&self.path, &next) {
            self.faulted = true;
            return Err(error);
        }
        self.state = next;
        Ok(())
    }
    pub fn add(
        &mut self,
        name: String,
        role: Role,
        group: String,
        host_id: Option<String>,
        days: u64,
    ) -> Result<(Device, String)> {
        self.live()?;
        validate_label(&name, &group)?;
        ensure!(
            (1..=90).contains(&days) && self.state.devices.len() < MAX_DEVICES,
            "Device limit or expiry invalid"
        );
        match role {
            Role::Host => ensure!(host_id.is_none(), "Hosts cannot have a target"),
            Role::Client => {
                let host = self
                    .active(host_id.as_deref().unwrap_or(""))
                    .context("Host unavailable")?;
                ensure!(
                    host.role == Role::Host && host.group == group,
                    "Invalid target scope"
                );
            }
        }
        let device = Device {
            id: Uuid::new_v4().to_string(),
            name,
            role,
            group,
            host_id,
            enabled: true,
            created_at: now(),
            expires_at: now() + days * 86400,
            generation: 1,
            auto_renew: true,
            renewal_days: days,
        };
        let secret = random_secret();
        let mut next = self.state.clone();
        next.devices.push(StoredDevice {
            device: device.clone(),
            credential_hash: secret_hash(&device.id, &secret),
        });
        self.commit(next)?;
        Ok((device, secret))
    }
    pub fn renew(&mut self, id: &str, days: u64) -> Result<Device> {
        ensure!((1..=90).contains(&days), "Invalid renewal duration");
        let mut next = self.state.clone();
        let device = &mut next
            .devices
            .iter_mut()
            .find(|e| e.device.id == id)
            .context("Unknown device")?
            .device;
        device.expires_at = device.expires_at.max(now() + days * 86400);
        device.renewal_days = days;
        let result = device.clone();
        self.commit(next)?;
        Ok(result)
    }
    pub fn set_auto_renew(&mut self, id: &str, enabled: bool) -> Result<Device> {
        let mut next = self.state.clone();
        let device = &mut next
            .devices
            .iter_mut()
            .find(|e| e.device.id == id)
            .context("Unknown device")?
            .device;
        // 开启策略不代替管理员手动恢复已过期登记。
        ensure!(
            !enabled || (device.enabled && device.expires_at > now()),
            "Device inactive"
        );
        device.auto_renew = enabled;
        let result = device.clone();
        self.commit(next)?;
        Ok(result)
    }
    pub fn renew_due(&mut self, at: u64) -> Result<()> {
        self.live()?;
        let mut next = self.state.clone();
        let mut changed = false;
        for entry in &mut next.devices {
            let device = &mut entry.device;
            let lifetime = device.renewal_days * 86400;
            if device.enabled
                && device.auto_renew
                && device.expires_at.saturating_sub(at) <= (7 * 86400).min(lifetime / 4)
            {
                // 持久策略允许服务停机后续期；禁用状态始终优先。
                device.expires_at = at.checked_add(lifetime).context("Invalid clock")?;
                changed = true;
            }
        }
        if changed {
            self.commit(next)?;
        }
        Ok(())
    }
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<Device> {
        let mut next = self.state.clone();
        let entry = next
            .devices
            .iter_mut()
            .find(|e| e.device.id == id)
            .context("Unknown device")?;
        entry.device.enabled = enabled;
        entry.device.generation = entry
            .device
            .generation
            .checked_add(1)
            .context("Device generation exhausted")?;
        let result = entry.device.clone();
        self.commit(next)?;
        Ok(result)
    }
}
fn validate_label(name: &str, group: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        bail!("Invalid device name");
    }
    ensure!(
        !group.is_empty()
            && group.len() <= 64
            && group
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "Invalid device group"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_credentials_and_disabling_survive_restart() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        }
        Registry::create(root.path())?;
        let mut store = Registry::open(root.path())?;
        let (host, hs) = store.add("电脑".into(), Role::Host, "a".into(), None, 30)?;
        assert!(
            store
                .add(
                    "手机".into(),
                    Role::Client,
                    "b".into(),
                    Some(host.id.clone()),
                    30
                )
                .is_err()
        );
        let (client, cs) = store.add(
            "手机".into(),
            Role::Client,
            "a".into(),
            Some(host.id.clone()),
            30,
        )?;
        assert!(store.authenticate(&host.id, &hs).is_some());
        assert!(store.authenticate(&host.id, &cs).is_none());
        assert!(store.authenticate(&client.id, &cs).is_some());
        let disk = String::from_utf8(read_private(&root.path().join("devices.json"))?)?;
        assert!(!disk.contains(&hs) && !disk.contains(&cs));
        store.set_enabled(&host.id, false)?;
        assert!(store.authenticate(&client.id, &cs).is_none());
        drop(store);
        let mut store = Registry::open(root.path())?;
        assert!(store.authenticate(&host.id, &hs).is_none());
        assert!(store.authenticate(&client.id, &cs).is_none());
        store.set_enabled(&host.id, true)?;
        assert!(store.authenticate(&client.id, &cs).is_some());
        assert!(Registry::open(root.path()).is_err());
        Ok(())
    }
    #[test]
    fn renewal_preserves_scope_and_credentials_and_never_enables_devices() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        }
        Registry::create(root.path())?;
        let mut store = Registry::open(root.path())?;
        let (host, secret) = store.add("Computer".into(), Role::Host, "a".into(), None, 30)?;
        let (client, token) = store.add(
            "Phone".into(),
            Role::Client,
            "a".into(),
            Some(host.id.clone()),
            30,
        )?;
        store.renew_due(now() + 35 * 86400)?;
        assert!(store.device(&host.id).unwrap().expires_at > host.expires_at);
        assert_eq!(
            store.authenticate(&host.id, &secret).unwrap().generation,
            host.generation
        );
        assert_eq!(
            store.authenticate(&client.id, &token).unwrap().host_id,
            client.host_id
        );
        store.set_auto_renew(&client.id, false)?;
        let fixed = store.device(&client.id).unwrap().expires_at;
        store.set_enabled(&host.id, false)?;
        let disabled = store.device(&host.id).unwrap();
        store.renew_due(now() + 100 * 86400)?;
        assert_eq!(
            store.device(&host.id).unwrap().expires_at,
            disabled.expires_at
        );
        assert_eq!(store.device(&client.id).unwrap().expires_at, fixed);
        store.renew(&host.id, 90)?;
        assert!(!store.device(&host.id).unwrap().enabled);
        assert!(store.authenticate(&host.id, &secret).is_none());
        assert!(store.identify(&host.id, &secret).is_some());
        drop(store);
        let store = Registry::open(root.path())?;
        assert!(!store.device(&client.id).unwrap().auto_renew);
        assert!(!store.device(&host.id).unwrap().enabled);
        Ok(())
    }
    #[test]
    fn corrupt_state_never_rebuilds_or_accepts_credentials() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        }
        write_new_private(&root.path().join("devices.json"), b"{broken")?;
        assert!(Registry::open(root.path()).is_err());
        assert_eq!(read_private(&root.path().join("devices.json"))?, b"{broken");
        Ok(())
    }
}
