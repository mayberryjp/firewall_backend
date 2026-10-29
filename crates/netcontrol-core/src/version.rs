use anyhow::{Result, ensure};
use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const RELEASE_VERSION: &str = "2026.10.29.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version {
    date: NaiveDate,
    iteration: u32,
}

impl Version {
    pub fn first(date: NaiveDate) -> Result<Self> {
        ensure!(
            (1..=9999).contains(&date.year()),
            "version year must be 0001..9999"
        );
        Ok(Self { date, iteration: 1 })
    }

    pub fn next(self, date: NaiveDate) -> Result<Self> {
        ensure!(
            date >= self.date,
            "UTC clock predates the last configuration version"
        );
        if date > self.date {
            return Self::first(date);
        }
        Ok(Self {
            date,
            iteration: self
                .iteration
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("version iteration exhausted"))?,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}.{:02}.{:02}.{}",
            self.date.year(),
            self.date.month(),
            self.date.day(),
            self.iteration
        )
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        ensure!(input.len() <= 21, "version exceeds 21 bytes");
        let parts: Vec<_> = input.split('.').collect();
        ensure!(
            parts.len() == 4
                && parts[0].len() == 4
                && parts[1].len() == 2
                && parts[2].len() == 2
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
            "version must be yyyy.mm.dd.iteration"
        );
        let date = NaiveDate::from_ymd_opt(parts[0].parse()?, parts[1].parse()?, parts[2].parse()?)
            .ok_or_else(|| anyhow::anyhow!("invalid version date"))?;
        let iteration = parts[3].parse()?;
        let version = Self { date, iteration };
        ensure!(
            date.year() >= 1 && iteration > 0 && version.to_string() == input,
            "version must be canonical yyyy.mm.dd.iteration with iteration 1..4294967295"
        );
        Ok(version)
    }
}

impl TryFrom<String> for Version {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<Version> for String {
    fn from(value: Version) -> Self {
        value.to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareMetadata {
    pub version: Version,
    pub repository: Option<String>,
    pub latest_version: Option<Version>,
    pub update_available: Option<bool>,
    pub last_checked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error: Option<String>,
}

impl Default for SoftwareMetadata {
    fn default() -> Self {
        Self {
            version: RELEASE_VERSION
                .parse()
                .expect("invalid compiled release version"),
            repository: None,
            latest_version: None,
            update_available: None,
            last_checked_at: None,
            error: None,
        }
    }
}

impl SoftwareMetadata {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.latest_version.is_some() == self.update_available.is_some(),
            "incomplete software update result"
        );
        if let Some(latest) = self.latest_version {
            ensure!(
                self.update_available == Some(latest > self.version)
                    && self.last_checked_at.is_some()
                    && self.repository.is_some()
                    && self.error.is_none(),
                "inconsistent software update result"
            );
        }
        if self.error.is_some() {
            ensure!(
                self.last_checked_at.is_some()
                    && self.repository.is_some()
                    && self.latest_version.is_none(),
                "inconsistent software update error"
            );
        }
        if self.repository.is_none() {
            ensure!(
                self.last_checked_at.is_none()
                    && self.latest_version.is_none()
                    && self.error.is_none(),
                "disabled release checking must not contain a result"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_dates_and_numeric_ordering() {
        assert!(RELEASE_VERSION.parse::<Version>().is_ok());
        for invalid in [
            "1.2.3",
            "2026.2.01.1",
            "2026.02.29.1",
            "2026.10.29.0",
            "2026.10.29.01",
            "v2026.10.29.1",
            "0000.01.01.1",
            "2026.10.29.4294967296",
        ] {
            assert!(invalid.parse::<Version>().is_err(), "{invalid}");
        }
        let a: Version = "2026.10.29.9".parse().unwrap();
        let b = a
            .next(NaiveDate::from_ymd_opt(2026, 10, 29).unwrap())
            .unwrap();
        assert_eq!(b.to_string(), "2026.10.29.10");
        assert!(b > a);
        assert_eq!(
            b.next(NaiveDate::from_ymd_opt(2026, 10, 30).unwrap())
                .unwrap()
                .to_string(),
            "2026.10.30.1"
        );
        assert!(
            b.next(NaiveDate::from_ymd_opt(2026, 10, 28).unwrap())
                .is_err()
        );
        let maximum: Version = "2026.10.29.4294967295".parse().unwrap();
        assert!(
            maximum
                .next(NaiveDate::from_ymd_opt(2026, 10, 29).unwrap())
                .is_err()
        );
        assert!(serde_json::from_str::<Version>("1").is_err());
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"2026.10.29.9\"");
    }
}
