use chrono::{DateTime, Datelike, NaiveDate};
use std::{fs, path::Path, process::Command};

pub const SEED_PATH: &str = "crates/netcontrol-core/release-version";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub date: NaiveDate,
    pub iteration: u32,
}

impl Version {
    pub fn parse(value: &str) -> Result<Self, String> {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() != 4 {
            return Err("release seed must use yyyy.mm.dd.iteration".into());
        }
        let date = NaiveDate::parse_from_str(&parts[..3].join("."), "%Y.%m.%d")
            .map_err(|error| error.to_string())?;
        let iteration: u32 = parts[3].parse().map_err(|error| format!("{error}"))?;
        let version = Self { date, iteration };
        if !(1..=9999).contains(&date.year()) || iteration == 0 || version.text() != value {
            return Err("release seed is not a canonical calendar version".into());
        }
        Ok(version)
    }

    pub fn text(&self) -> String {
        format!(
            "{}.{iteration}",
            self.date.format("%Y.%m.%d"),
            iteration = self.iteration
        )
    }
}

pub fn derive(seed: &str, dates: &[NaiveDate]) -> Result<String, String> {
    let mut version = Version::parse(seed)?;
    if dates.is_empty() {
        return Err("release history must contain its seed commit".into());
    }
    for (index, date) in dates.iter().enumerate() {
        if !(1..=9999).contains(&date.year()) {
            return Err("release commit UTC year must be 0001..9999".into());
        }
        if *date < version.date {
            return Err("release commit UTC dates moved backward; correct the commit clock".into());
        }
        if *date > version.date {
            version = Version {
                date: *date,
                iteration: 1,
            };
        } else if index != 0 {
            version.iteration = version
                .iteration
                .checked_add(1)
                .ok_or("release iteration exhausted")?;
        }
    }
    Ok(version.text())
}

pub fn git(root: &Path, arguments: &[&str]) -> Result<String, String> {
    // Privileged native tests also build from the runner-owned checkout.
    let output = Command::new("git")
        .args(["-c", &format!("safe.directory={}", root.display())])
        .current_dir(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("git is required for commit-derived versions: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

pub fn resolve(root: &Path) -> Result<(String, Option<&'static str>), String> {
    let seed = fs::read_to_string(root.join(SEED_PATH)).map_err(|error| error.to_string())?;
    let seed = seed.trim();
    Version::parse(seed)?;
    if !root.join(".git").exists() {
        return Err("commit-derived builds require a full Git checkout; source archives cannot determine the commit version".into());
    }
    if git(root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false" {
        return Err("commit-derived versions require full Git history; fetch --unshallow".into());
    }
    let additions = git(
        root,
        &[
            "log",
            "--first-parent",
            "--reverse",
            "--diff-filter=A",
            "--format=%H",
            "HEAD",
            "--",
            SEED_PATH,
        ],
    )?;
    let Some(anchor) = additions.lines().next() else {
        return Ok((
            seed.into(),
            Some("release seed is not committed yet; using its development build label"),
        ));
    };
    let original = git(root, &["show", &format!("{anchor}:{SEED_PATH}")])?;
    if original.trim() != seed {
        return Err(
            "release-version is an immutable seed; do not edit it after its first commit".into(),
        );
    }
    let history = git(
        root,
        &[
            "log",
            "--first-parent",
            "--reverse",
            "--format=%H %ct",
            "HEAD",
        ],
    )?;
    let mut dates = Vec::new();
    let mut found = false;
    for line in history.lines() {
        let (commit, seconds) = line.split_once(' ').ok_or("invalid Git history record")?;
        found |= commit == anchor;
        if found {
            let seconds = seconds.parse().map_err(|error| format!("{error}"))?;
            let date = DateTime::from_timestamp(seconds, 0)
                .ok_or("invalid Git commit timestamp")?
                .date_naive();
            dates.push(date);
        }
    }
    Ok((derive(seed, &dates)?, None))
}
