use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Mutex, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApnsConfig {
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
    pub key_file: PathBuf,
    pub environment: String,
}
impl ApnsConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            [&self.key_id, &self.team_id].iter().all(|s| s.len() == 10
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())),
            "Invalid APNs identity"
        );
        ensure!(
            self.topic.len() <= 128
                && self.topic.split('.').count() >= 2
                && self
                    .topic
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "Invalid APNs topic"
        );
        ensure!(
            matches!(self.environment.as_str(), "sandbox" | "production")
                && self.key_file.is_absolute(),
            "Invalid APNs configuration"
        );
        self.key()?;
        Ok(())
    }
    fn key(&self) -> Result<EcdsaKeyPair> {
        let bytes = crate::store::read_private(&self.key_file)?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(bytes))?
            .context("Missing APNs key")?;
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            key.secret_der(),
            &SystemRandom::new(),
        )
        .map_err(|_| anyhow::anyhow!("Invalid APNs signing key"))
    }
    fn authorization(&self, now: u64) -> Result<String> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg":"ES256","kid":self.key_id}),
        )?);
        let claims =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":self.team_id,"iat":now}))?);
        let unsigned = format!("{header}.{claims}");
        let signature = self
            .key()?
            .sign(&SystemRandom::new(), unsigned.as_bytes())
            .map_err(|_| anyhow::anyhow!("APNs signing unavailable"))?;
        Ok(format!(
            "{unsigned}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

pub struct PushGateway {
    config: Option<ApnsConfig>,
    client: Result<reqwest::Client, reqwest::Error>,
    limits: Mutex<HashMap<String, (u64, u32)>>,
    seen: Mutex<HashMap<String, u64>>,
    permits: tokio::sync::Semaphore,
}
impl PushGateway {
    pub fn new(config: Option<ApnsConfig>) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build(),
            limits: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            permits: tokio::sync::Semaphore::new(16),
        }
    }
    pub fn status(&self) -> Value {
        json!({"available": self.config.is_some() && self.client.is_ok(), "environment":self.config.as_ref().map(|c| &c.environment)})
    }
    fn admit(&self, host: &str, event: &str, token: &str, now: u64, expires: u64) -> Result<bool> {
        let mut limits = self
            .limits
            .lock()
            .map_err(|_| anyhow::anyhow!("State unavailable"))?;
        limits.retain(|_, (at, _)| now.saturating_sub(*at) < 60);
        ensure!(
            limits.contains_key(host) || limits.len() < 1024,
            "Push capacity reached"
        );
        let budget = limits.entry(host.into()).or_insert((now, 0));
        ensure!(budget.1 < 120, "Push rate exceeded");
        budget.1 += 1;
        drop(limits);
        let key = format!("{host}:{event}:{:x}", Sha256::digest(token.as_bytes()));
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| anyhow::anyhow!("State unavailable"))?;
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(&key) {
            return Ok(false);
        }
        ensure!(seen.len() < 8192, "Push capacity reached");
        // 投递结果未知时不自动重发；后续相同事件也不制造重复提醒。
        seen.insert(key, expires);
        Ok(true)
    }
    pub async fn send(&self, host: &str, value: &Value) -> &'static str {
        let Some(config) = &self.config else {
            return "unavailable";
        };
        let Ok(client) = &self.client else {
            return "unavailable";
        };
        let now = crate::store::now();
        let expires = value["expiresAt"].as_u64().unwrap_or(0);
        if value["environment"] != config.environment || expires <= now || expires > now + 300 {
            return "unavailable";
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            return "rate-limited";
        };
        match self.admit(
            host,
            value["eventId"].as_str().unwrap_or_default(),
            value["token"].as_str().unwrap_or_default(),
            now,
            expires,
        ) {
            Ok(false) => return "unavailable",
            Err(_) => return "rate-limited",
            Ok(true) => {}
        }
        let Ok(auth) = config.authorization(now) else {
            return "unavailable";
        };
        let domain = if config.environment == "production" {
            "api.push.apple.com"
        } else {
            "api.sandbox.push.apple.com"
        };
        let token = value["token"].as_str().unwrap_or_default();
        let collapse = format!(
            "{:x}",
            Sha256::digest(format!("{host}:{}:{}", value["hostId"], value["sessionId"]).as_bytes())
        );
        let response = client
            .post(format!("https://{domain}/3/device/{token}"))
            .bearer_auth(auth)
            .header("apns-topic", &config.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", expires)
            .header("apns-collapse-id", collapse)
            .json(&payload(value))
            .send()
            .await;
        let Ok(response) = response else {
            return "unavailable";
        };
        if response.status().is_success() {
            return "accepted";
        }
        if response.status().as_u16() == 410 {
            return "invalid-token";
        }
        if response.status().as_u16() == 400
            && response.content_length().is_some_and(|n| n <= 4096)
            && let Ok(body) = response.json::<Value>().await
            && (body["reason"] == "BadDeviceToken" || body["reason"] == "DeviceTokenNotForTopic")
        {
            return "invalid-token";
        }
        "unavailable"
    }
}

pub fn validate(value: &Value) -> bool {
    // 校验器直接编译固定的规范副本，不维护第二份生产线协议。
    static VALIDATOR: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(include_str!("../vendor/relay/config.schema.json"))
                    .expect("Pinned schema");
            jsonschema::validator_for(&schema["$defs"]["pushRequest"])
                .expect("Pinned push definition")
        })
        .is_valid(value)
}
pub fn payload(value: &Value) -> Value {
    let chinese = value["locale"] == "zh-CN";
    let body = match (value["kind"].as_str(), chinese) {
        (Some("completed"), true) => "任务已完成，轻点查看。",
        (Some("failed"), true) => "任务遇到问题，轻点查看。",
        (_, true) => "有任务需要你处理，轻点查看。",
        (Some("completed"), false) => "Your task is complete. Tap to view.",
        (Some("failed"), false) => "Your task encountered a problem. Tap to view.",
        (_, false) => "A task needs your attention. Tap to view.",
    };
    json!({"aps":{"alert":{"title":"Cowork","body":body},"sound":"default"},"cowork":{"format":1,"hostId":value["hostId"],"sessionId":value["sessionId"],"eventId":value["eventId"]}})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        json!({"token":"a".repeat(64),"environment":"sandbox","locale":"en","kind":"completed","hostId":"host","sessionId":"session","eventId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","expiresAt":1800000000})
    }
    #[test]
    fn provider_signatures_use_configured_identity_and_private_p256_key() -> Result<()> {
        let root = tempfile::tempdir()?;
        let key = rcgen::KeyPair::generate()?;
        let path = root.path().join("apns.p8");
        crate::store::write_new_private(&path, key.serialize_pem().as_bytes())?;
        let config = ApnsConfig {
            key_id: "ABCDEFGHIJ".into(),
            team_id: "0123456789".into(),
            topic: "com.example.test".into(),
            key_file: path,
            environment: "sandbox".into(),
        };
        config.validate()?;
        let signed = config.authorization(1000)?;
        let parts: Vec<_> = signed.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[0])?)?["kid"],
            "ABCDEFGHIJ"
        );
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(claims["iss"], "0123456789");
        assert_eq!(claims["iat"], 1000);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            key.public_key_raw(),
        )
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2])?,
        )
        .map_err(|_| anyhow::anyhow!("Signature mismatch"))?;
        Ok(())
    }
    #[test]
    fn contract_rejects_content_actions_and_arbitrary_targets() {
        let valid = request();
        assert!(validate(&valid));
        for key in ["body", "url", "approval", "topic"] {
            let mut bad = valid.clone();
            bad[key] = json!("untrusted");
            assert!(!validate(&bad));
        }
        let payload = payload(&valid).to_string();
        assert!(!payload.contains(&"a".repeat(64)));
        assert!(!payload.contains("sandbox"));
        assert!(payload.contains("Your task is complete"));
        let mut chinese = valid;
        chinese["locale"] = json!("zh-CN");
        assert!(payload_for_test(&chinese).contains("任务已完成"));
    }
    fn payload_for_test(v: &Value) -> String {
        payload(v).to_string()
    }
    #[test]
    fn rate_and_duplicate_state_are_bounded_and_expire() {
        let gateway = PushGateway::new(None);
        assert!(gateway.admit("host", "one", "token", 100, 200).unwrap());
        assert!(!gateway.admit("host", "one", "token", 100, 200).unwrap());
        assert!(
            gateway
                .admit("host", "one", "other-token", 100, 200)
                .unwrap()
        );
        for i in 0..117 {
            assert!(
                gateway
                    .admit("host", &i.to_string(), "token", 100, 200)
                    .unwrap()
            );
        }
        assert!(gateway.admit("host", "new", "token", 100, 200).is_err());
        assert!(gateway.admit("host", "one", "token", 201, 300).unwrap());
    }
    #[tokio::test]
    async fn absent_provider_never_claims_delivery() {
        let gateway = PushGateway::new(None);
        assert_eq!(gateway.status()["available"], false);
        assert_eq!(gateway.send("host", &request()).await, "unavailable");
    }
}
