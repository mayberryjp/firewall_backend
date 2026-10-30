use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandoConfig {
    pub api_url: String,
    pub sync_enabled: bool,
    pub hosts_import: Option<SandoImportState>,
    pub rules_import: Option<SandoImportState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandoImportState {
    pub source_url: String,
    pub import_count: u32,
    pub last_import_at: DateTime<Utc>,
    pub status: SandoImportStatus,
    pub imported_count: u32,
    pub skipped_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandoImportStatus {
    Succeeded,
    Partial,
}

fn validate_url(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && (value.starts_with("http://") || value.starts_with("https://"))
            && !value.contains('\\')
            && !value.chars().any(|c| c.is_whitespace() || c.is_control()),
        "Sando URL must be an absolute http:// or https:// base URL of 1..2048 bytes without whitespace, control characters or backslashes"
    );
    let (_, remainder) = value
        .split_once("://")
        .context("Sando URL requires an HTTP scheme")?;
    let authority = remainder
        .split('/')
        .next()
        .context("Sando URL requires a host")?;
    ensure!(
        !authority.is_empty() && !authority.contains('@'),
        "Sando URL requires a host without credentials"
    );
    let url = url::Url::parse(value)?;
    ensure!(
        url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.port() != Some(0)
            && url.query().is_none()
            && url.fragment().is_none(),
        "Sando URL requires a host and must not contain credentials, query parameters, fragments or port zero"
    );
    Ok(())
}

impl SandoConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.sync_enabled || !self.api_url.is_empty(),
            "Sando sync requires a configured api_url"
        );
        if !self.api_url.is_empty() {
            validate_url(&self.api_url)?;
        }
        for state in [&self.hosts_import, &self.rules_import]
            .into_iter()
            .flatten()
        {
            validate_url(&state.source_url)?;
            ensure!(
                state.import_count > 0,
                "Sando import_count must be 1..4294967295"
            );
            ensure!(
                (1970..=9999).contains(&state.last_import_at.year()),
                "Sando last_import_at must be an RFC3339 timestamp in years 1970..9999"
            );
            ensure!(
                match state.status {
                    SandoImportStatus::Succeeded => state.skipped_count == 0,
                    SandoImportStatus::Partial =>
                        state.imported_count > 0 && state.skipped_count > 0,
                },
                "Sando succeeded imports require zero skipped items; partial imports require both imported and skipped items"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> SandoConfig {
        serde_json::from_value(json!({
            "api_url":"https://sando.example.test/proxy",
            "hosts_import":{
                "source_url":"http://192.0.2.10:8044",
                "import_count":2,
                "last_import_at":"2026-10-30T00:00:00Z",
                "status":"partial",
                "imported_count":3,
                "skipped_count":1
            }
        }))
        .unwrap()
    }

    #[test]
    fn defaults_and_confirmed_import_records_roundtrip_without_losing_source() {
        assert_eq!(
            serde_json::to_value(SandoConfig::default()).unwrap(),
            json!({"api_url":"","sync_enabled":false,"hosts_import":null,"rules_import":null})
        );
        let config = config();
        config.validate().unwrap();
        assert_eq!(config.rules_import, None);
        assert_eq!(
            serde_json::from_value::<SandoConfig>(serde_json::to_value(&config).unwrap()).unwrap(),
            config
        );
        let mut disconnected = config;
        disconnected.api_url.clear();
        disconnected.validate().unwrap();
        assert_eq!(
            disconnected.hosts_import.unwrap().source_url,
            "http://192.0.2.10:8044"
        );
    }

    #[test]
    fn url_validation_accepts_browser_reachable_bases_not_credentials_or_request_data() {
        for valid in [
            "http://192.0.2.10:8044",
            "https://sando.example.test",
            "https://sando.example.test/proxy/",
            "http://[2001:db8::10]:8044",
        ] {
            validate_url(valid).unwrap();
        }

        for invalid in [
            "",
            "sando.example.test",
            "//sando.example.test",
            "ftp://sando.example.test",
            "http:///sando.example.test",
            "http://user:password@sando.example.test",
            "http://user@sando.example.test",
            "http://sando.example.test:0",
            "http://sando.example.test:65536",
            "http://sando.example.test?token=synthetic",
            "http://sando.example.test#fragment",
            " http://sando.example.test",
            "http://sando.example.test/\n",
            "http://sando.example.test\\path",
        ] {
            assert!(validate_url(invalid).is_err(), "{invalid}");
        }
        assert!(validate_url(&format!("https://sando.example.test/{}", "x".repeat(2048))).is_err());
    }

    #[test]
    fn sync_requires_a_url_and_a_boolean_flag() {
        let mut config = SandoConfig {
            sync_enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.api_url = "https://sando.example.test/proxy".into();
        config.validate().unwrap();
        for invalid in [json!(null), json!("true"), json!(1)] {
            assert!(
                serde_json::from_value::<SandoConfig>(json!({"sync_enabled":invalid})).is_err()
            );
        }
    }

    #[test]
    fn import_records_reject_invalid_types_missing_fields_and_inconsistent_outcomes() {
        let baseline = serde_json::to_value(config()).unwrap();
        for (field, invalid) in [
            ("import_count", json!(0)),
            ("last_import_at", json!("1969-12-31T23:59:59Z")),
            ("status", json!("succeeded")),
            ("imported_count", json!(0)),
            ("skipped_count", json!(0)),
            ("source_url", json!("javascript:alert(1)")),
        ] {
            let mut value = baseline.clone();
            value["hosts_import"][field] = invalid;
            assert!(
                serde_json::from_value::<SandoConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        for (field, invalid) in [
            ("status", json!("failed")),
            ("last_import_at", json!("2026-02-29")),
            ("import_count", json!(-1)),
            ("import_count", json!(4294967296u64)),
            ("import_count", json!("2")),
            ("imported_count", json!(1.5)),
        ] {
            let mut value = baseline.clone();
            value["hosts_import"][field] = invalid;
            assert!(
                serde_json::from_value::<SandoConfig>(value).is_err(),
                "{field}"
            );
        }
        let mut missing = baseline.clone();
        missing["hosts_import"]
            .as_object_mut()
            .unwrap()
            .remove("source_url");
        assert!(serde_json::from_value::<SandoConfig>(missing).is_err());
        let mut success = baseline;
        success["hosts_import"]["status"] = json!("succeeded");
        success["hosts_import"]["skipped_count"] = json!(0);
        success["hosts_import"]["imported_count"] = json!(0);
        serde_json::from_value::<SandoConfig>(success)
            .unwrap()
            .validate()
            .unwrap();
    }
}
