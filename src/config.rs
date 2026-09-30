use crate::store::{Registry, atomic_json, private_directory, read_private, write_new_private};
use anyhow::{Context, Result, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{ServerConfig, pki_types::CertificateDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use time::{Duration, OffsetDateTime};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    pub format: u32,
    #[serde(default = "default_certificate_renewal")]
    pub auto_renew_certificate: bool,
    pub origin: String,
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub trust_certificate: Option<PathBuf>,
    pub limits: Limits,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Limits {
    pub sockets: usize,
    pub hosts: usize,
    pub streams: usize,
    pub streams_per_host: usize,
    pub streams_per_client: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sockets: 512,
            hosts: 128,
            streams: 256,
            streams_per_host: 32,
            streams_per_client: 8,
        }
    }
}

pub fn authority(origin: &str) -> Result<(String, String)> {
    let uri: hyper::Uri = origin.parse()?;
    ensure!(
        uri.scheme_str() == Some("https") && uri.path() == "/" && uri.query().is_none(),
        "Expected an HTTPS origin"
    );
    let a = uri.authority().context("Missing authority")?;
    ensure!(
        !a.as_str().contains('@') && a.port_u16() != Some(0),
        "Invalid authority"
    );
    let host = a.host().trim_start_matches('[').trim_end_matches(']');
    ensure!(
        host.is_ascii()
            && !host.is_empty()
            && host == host.to_ascii_lowercase()
            && !host.ends_with('.'),
        "Invalid origin host"
    );
    rustls::pki_types::ServerName::try_from(host.to_string()).context("Invalid origin host")?;
    let host_authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    ensure!(
        a.as_str() == host_authority
            || a.port_u16()
                .is_some_and(|port| port > 0 && a.as_str() == format!("{host_authority}:{port}")),
        "Invalid origin port"
    );
    ensure!(
        origin == format!("https://{a}"),
        "Origin must have no path or trailing slash"
    );
    Ok((a.to_string(), host.to_string()))
}

fn read_certificate(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= 64 * 1024,
        "Invalid certificate file"
    );
    Ok(fs::read(path)?)
}

fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !chain.is_empty() && chain.len() <= 8,
        "Invalid certificate chain"
    );
    Ok(chain)
}

fn default_certificate_renewal() -> bool {
    true
}

impl Config {
    pub fn load(directory: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_private(&directory.join("config.json"))?)?;
        ensure!(config.format == 1, "Unsupported configuration");
        authority(&config.origin)?;
        let l = &config.limits;
        ensure!(
            (8..=4096).contains(&l.sockets)
                && (1..=1024).contains(&l.hosts)
                && (1..=2048).contains(&l.streams),
            "Invalid capacity limits"
        );
        ensure!(
            (1..=l.streams).contains(&l.streams_per_host)
                && (1..=l.streams_per_host).contains(&l.streams_per_client),
            "Invalid stream limits"
        );
        ensure!(
            config.certificate.is_absolute()
                && config.private_key.is_absolute()
                && config
                    .trust_certificate
                    .as_ref()
                    .is_none_or(|p| p.is_absolute()),
            "Certificate paths must be absolute"
        );
        Ok(config)
    }

    pub fn tls(&self) -> Result<Arc<ServerConfig>> {
        let (_, host) = authority(&self.origin)?;
        let chain = certificates(&read_certificate(&self.certificate)?)?;
        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(chain[0].as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid leaf certificate"))?;
        ensure!(
            leaf.validity().is_valid(),
            "Certificate is expired or not yet valid"
        );
        let san = leaf
            .subject_alternative_name()?
            .context("Certificate requires Subject Alternative Name")?;
        let ip = host.parse::<IpAddr>().ok();
        let matches = san.value.general_names.iter().any(|name| match (name, ip) {
            (GeneralName::IPAddress(bytes), Some(IpAddr::V4(ip))) => *bytes == ip.octets(),
            (GeneralName::IPAddress(bytes), Some(IpAddr::V6(ip))) => *bytes == ip.octets(),
            (GeneralName::DNSName(dns), None) => {
                let dns = dns.to_ascii_lowercase();
                dns == host
                    || dns.strip_prefix("*.").is_some_and(|suffix| {
                        host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
                    })
            }
            _ => false,
        });
        ensure!(
            matches,
            "Certificate SAN does not match the configured origin"
        );
        let key_bytes = read_private(&self.private_key)?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
            .context("Missing private key")?;
        let mut tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(chain, key)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.max_early_data_size = 0;
        Ok(Arc::new(tls))
    }

    pub fn public_trust(&self) -> Result<serde_json::Value> {
        let ca = self
            .trust_certificate
            .as_ref()
            .map(|p| read_certificate(p))
            .transpose()?;
        let fingerprint = ca
            .as_ref()
            .map(|pem| -> Result<String> {
                let certs = certificates(pem)?;
                ensure!(certs.len() == 1, "Expected one trust anchor");
                Ok(format!("{:x}", Sha256::digest(certs[0].as_ref())))
            })
            .transpose()?;
        Ok(
            serde_json::json!({"format":1,"origin":self.origin,"trust":if ca.is_some(){"private-ca"}else{"system"},"caCertificatePem":ca.map(String::from_utf8).transpose()?,"caSha256":fingerprint}),
        )
    }
}

pub fn init_ip(directory: &Path, ip: IpAddr, port: u16, listen: SocketAddr) -> Result<Config> {
    ensure!(
        port > 0 && !ip.is_unspecified() && !ip.is_multicast(),
        "Invalid public IP or port"
    );
    prepare(directory)?;
    let directory = fs::canonicalize(directory)?;
    let now = OffsetDateTime::now_utc();
    let mut ca = CertificateParams::new(vec![])?;
    ca.distinguished_name
        .push(DnType::CommonName, "Cowork Relay private CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = now - Duration::minutes(5);
    ca.not_after = now + Duration::days(3650);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca.self_signed(&ca_key)?;
    let ca_key_pem = ca_key.serialize_pem();
    let issuer = Issuer::new(ca, ca_key);
    let mut leaf = CertificateParams::new(vec![ip.to_string()])?;
    leaf.distinguished_name
        .push(DnType::CommonName, "Cowork Relay");
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.not_before = now - Duration::minutes(5);
    leaf.not_after = now + Duration::days(365);
    let key = KeyPair::generate()?;
    let cert = leaf.signed_by(&key, &issuer)?;
    write_new_private(&directory.join("ca.pem"), ca_cert.pem().as_bytes())?;
    write_new_private(&directory.join("ca-key.pem"), ca_key_pem.as_bytes())?;
    write_new_private(&directory.join("server.pem"), cert.pem().as_bytes())?;
    write_new_private(
        &directory.join("server-key.pem"),
        key.serialize_pem().as_bytes(),
    )?;
    let origin = format!("https://{}", SocketAddr::new(ip, port));
    save_initial(
        &directory,
        Config {
            format: 1,
            auto_renew_certificate: true,
            origin,
            listen,
            certificate: directory.join("server.pem"),
            private_key: directory.join("server-key.pem"),
            trust_certificate: Some(directory.join("ca.pem")),
            limits: Limits::default(),
        },
    )
}

pub fn init_domain(
    directory: &Path,
    origin: String,
    listen: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
) -> Result<Config> {
    let (_, host) = authority(&origin)?;
    ensure!(
        host.parse::<IpAddr>().is_err(),
        "Use init-ip for an IP origin"
    );
    let config = Config {
        format: 1,
        auto_renew_certificate: true,
        origin,
        listen,
        certificate: fs::canonicalize(certificate)?,
        private_key: fs::canonicalize(private_key)?,
        trust_certificate: None,
        limits: Limits::default(),
    };
    config.tls()?;
    prepare(directory)?;
    save_initial(directory, config)
}

fn prepare(directory: &Path) -> Result<()> {
    private_directory(directory)?;
    ensure!(
        fs::read_dir(directory)?.next().is_none(),
        "Initialization requires an empty private directory"
    );
    Ok(())
}

pub fn renew_ip(directory: &Path) -> Result<Config> {
    // 持有设备状态锁，避免运行中的服务观察到不完整的证书切换。
    let _registry = Registry::open(directory)?;
    renew_ip_locked(directory)
}

fn renew_ip_locked(directory: &Path) -> Result<Config> {
    let directory = fs::canonicalize(directory)?;
    let mut config = Config::load(&directory)?;
    let (_, host) = authority(&config.origin)?;
    host.parse::<IpAddr>()
        .context("Only generated IP certificates can be renewed here")?;
    let ca_pem = read_certificate(
        config
            .trust_certificate
            .as_ref()
            .context("Missing private CA")?,
    )?;
    let ca_chain = certificates(&ca_pem)?;
    ensure!(ca_chain.len() == 1, "Invalid private CA");
    let (_, ca) = x509_parser::certificate::X509Certificate::from_der(ca_chain[0].as_ref())
        .map_err(|_| anyhow::anyhow!("Invalid private CA"))?;
    let now = OffsetDateTime::now_utc();
    let expires = ca.validity().not_after.to_datetime();
    ensure!(
        ca.is_ca() && ca.validity().is_valid() && expires > now + Duration::days(1),
        "CA is invalid or requires replacement"
    );
    let key = KeyPair::from_pem(&String::from_utf8(read_private(
        &directory.join("ca-key.pem"),
    )?)?)?;
    ensure!(
        ca.public_key().subject_public_key.data.as_ref() == key.public_key_raw(),
        "CA key does not match the trust anchor"
    );
    let issuer = Issuer::from_ca_cert_pem(&String::from_utf8(ca_pem)?, key)?;
    let mut params = CertificateParams::new(vec![host])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Cowork Relay");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::minutes(5);
    params.not_after = (now + Duration::days(365)).min(expires);
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, &issuer)?;
    let generation = uuid::Uuid::new_v4();
    config.certificate = directory.join(format!("server-{generation}.pem"));
    config.private_key = directory.join(format!("server-{generation}-key.pem"));
    write_new_private(&config.certificate, certificate.pem().as_bytes())?;
    write_new_private(&config.private_key, key.serialize_pem().as_bytes())?;
    config.tls()?;
    atomic_json(&directory.join("config.json"), &config)?;
    Ok(config)
}
// 仅持有登记锁的服务调用；只更新叶证书，不自动更换信任根或路由。
pub fn maintain_certificate(
    directory: &Path,
    expected: &Config,
    expected_trust: &serde_json::Value,
) -> Result<Config> {
    let mut config = Config::load(directory)?;
    ensure!(
        config.origin == expected.origin
            && config.listen == expected.listen
            && config.public_trust()? == *expected_trust,
        "Relay identity changed; restart required"
    );
    if config.automatic_certificate_renewal()
        && config.certificate_expiry()? <= crate::store::now() + 30 * 86400
    {
        let ca = certificates(&read_certificate(
            config.trust_certificate.as_ref().context("Missing CA")?,
        )?)?;
        let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(ca[0].as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid CA"))?;
        ensure!(
            certificate.validity().not_after.timestamp()
                > (crate::store::now() + 31 * 86400) as i64,
            "CA expires soon; administrator must replace trust registration"
        );
        config = renew_ip_locked(directory)?;
    }
    config.tls()?;
    Ok(config)
}

impl Config {
    pub fn automatic_certificate_renewal(&self) -> bool {
        self.auto_renew_certificate
            && self.trust_certificate.is_some()
            && authority(&self.origin).is_ok_and(|(_, host)| host.parse::<IpAddr>().is_ok())
    }

    pub fn certificate_expiry(&self) -> Result<u64> {
        let chain = certificates(&read_certificate(&self.certificate)?)?;
        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(chain[0].as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid leaf certificate"))?;
        Ok(u64::try_from(leaf.validity().not_after.timestamp())?)
    }
}

fn save_initial(directory: &Path, config: Config) -> Result<Config> {
    config.tls()?;
    Registry::create(directory)?;
    write_new_private(
        &directory.join("config.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewal_preserves_trust_and_requires_exclusive_access() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("state");
        let initial = init_ip(&path, "127.0.0.1".parse()?, 8443, "127.0.0.1:8443".parse()?)?;
        let trust = initial.public_trust()?;
        let store = Registry::open(&path)?;
        assert!(renew_ip(&path).is_err());
        drop(store);
        let renewed = renew_ip(&path)?;
        assert_eq!(renewed.public_trust()?, trust);
        assert_ne!(renewed.private_key, initial.private_key);
        assert_ne!(
            read_private(&renewed.private_key)?,
            read_private(&initial.private_key)?
        );
        assert_eq!(Config::load(&path)?.certificate, renewed.certificate);
        renewed.tls()?;
        Ok(())
    }
    #[test]
    fn automatic_certificate_renewal_keeps_root_and_respects_opt_out() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("state");
        let mut config = init_ip(&path, "127.0.0.1".parse()?, 8443, "127.0.0.1:8443".parse()?)?;
        let trust = config.public_trust()?;
        let _registry = Registry::open(&path)?;
        let ca = String::from_utf8(read_private(&path.join("ca.pem"))?)?;
        let issuer = Issuer::from_ca_cert_pem(
            &ca,
            KeyPair::from_pem(&String::from_utf8(read_private(&path.join("ca-key.pem"))?)?)?,
        )?;
        let key = KeyPair::from_pem(&String::from_utf8(read_private(&config.private_key)?)?)?;
        let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()])?;
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        fs::write(&config.certificate, params.signed_by(&key, &issuer)?.pem())?;
        config.auto_renew_certificate = false;
        atomic_json(&path.join("config.json"), &config)?;
        assert_eq!(
            maintain_certificate(&path, &config, &trust)?.certificate,
            config.certificate
        );
        config.auto_renew_certificate = true;
        atomic_json(&path.join("config.json"), &config)?;
        let renewed = maintain_certificate(&path, &config, &trust)?;
        assert_ne!(renewed.certificate, config.certificate);
        assert!(renewed.certificate_expiry()? > crate::store::now() + 300 * 86400);
        assert_eq!(renewed.public_trust()?, trust);
        assert_eq!(
            maintain_certificate(&path, &config, &trust)?.certificate,
            renewed.certificate
        );
        let mut changed = trust.clone();
        changed["caSha256"] = serde_json::json!("0".repeat(64));
        assert!(maintain_certificate(&path, &config, &changed).is_err());
        Ok(())
    }
    #[test]
    fn ip_certificates_match_only_the_selected_address_and_export_no_keys() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("state");
        let config = init_ip(&path, "127.0.0.1".parse()?, 8443, "127.0.0.1:8443".parse()?)?;
        config.tls()?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded.origin, "https://127.0.0.1:8443");
        let export = loaded.public_trust()?.to_string();
        assert!(export.contains("CERTIFICATE"));
        assert!(!export.contains("PRIVATE KEY"));
        let mut wrong = config.clone();
        wrong.origin = "https://127.0.0.2:8443".into();
        assert!(wrong.tls().is_err());
        assert!(init_ip(&path, "127.0.0.1".parse()?, 8443, config.listen).is_err());
        Ok(())
    }
    #[test]
    fn origins_reject_ambiguous_and_plaintext_locations() {
        for invalid in [
            "http://example.org",
            "https://example.org/",
            "https://example.org/path",
            "https://a@b",
            "https://EXAMPLE.org",
            "https://example.org:0",
            "https://example.org:abc",
            "https://example.org:65536",
            "https://example.org:0443",
            "https://example.org?token=x",
            "https://example.org#fragment",
        ] {
            assert!(authority(invalid).is_err(), "{invalid}");
        }
        assert!(authority("https://example.org").is_ok());
        assert!(authority("https://[::1]:8443").is_ok());
    }
}
