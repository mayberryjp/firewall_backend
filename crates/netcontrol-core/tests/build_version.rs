#[path = "../build_version.rs"]
mod build_version;

use build_version::{SEED_PATH, Version, derive, git, resolve};
use chrono::NaiveDate;
use std::{fs, path::Path, process::Command};

fn date(value: &str) -> NaiveDate {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").unwrap()
}

#[test]
fn versions_advance_per_commit_reset_daily_and_reject_invalid_history() {
    assert_eq!(
        derive("2026.10.30.6", &[date("2026-10-30")]).unwrap(),
        "2026.10.30.6"
    );
    assert_eq!(
        derive("2026.10.30.6", &[date("2026-10-30"); 3]).unwrap(),
        "2026.10.30.8"
    );
    assert_eq!(
        derive(
            "2026.10.30.6",
            &[date("2026-10-30"), date("2026-10-31"), date("2026-10-31")]
        )
        .unwrap(),
        "2026.10.31.2"
    );
    assert!(derive("2026.10.30.6", &[]).is_err());
    assert!(derive("2026.10.30.6", &[date("2026-10-29")]).is_err());
    assert!(derive("2026.10.30.1", &[date("2026-10-31"), date("2026-10-30")]).is_err());
    assert!(derive("2026.10.30.4294967295", &[date("2026-10-30"); 2]).is_err());
    for invalid in [
        "2026.10.30.0",
        "2026.02.29.1",
        "2026.10.30.01",
        "v2026.10.30.1",
        "2026.10.30.4294967296",
        "0000.01.01.1",
    ] {
        assert!(Version::parse(invalid).is_err(), "{invalid}");
    }
}

fn commit(root: &Path, timestamp: &str) {
    git(root, &["add", "."]).unwrap();
    dated_git(
        root,
        &["commit", "--allow-empty", "-m", "fixture"],
        timestamp,
    );
}

fn dated_git(root: &Path, arguments: &[&str], timestamp: &str) {
    let status = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
        ])
        .args(arguments)
        .env("GIT_AUTHOR_DATE", timestamp)
        .env("GIT_COMMITTER_DATE", timestamp)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn merging_the_seed_starts_the_mainline_sequence_at_the_merge_commit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-b", "main"]).unwrap();
    commit(root, "2026-10-30T00:00:00Z");
    git(root, &["checkout", "-b", "introduce-seed"]).unwrap();
    fs::create_dir_all(root.join("crates/netcontrol-core")).unwrap();
    fs::write(root.join(SEED_PATH), "2026.10.30.6\n").unwrap();
    commit(root, "2026-10-30T01:00:00Z");
    commit(root, "2026-10-30T02:00:00Z");
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.7");
    git(root, &["checkout", "main"]).unwrap();
    dated_git(
        root,
        &["merge", "--no-ff", "introduce-seed", "-m", "merge fixture"],
        "2026-10-30T03:00:00Z",
    );
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.6");
    commit(root, "2026-10-30T04:00:00Z");
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.7");
}

#[test]
fn real_git_history_detached_builds_and_seed_immutability() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("crates/netcontrol-core")).unwrap();
    fs::write(root.join(SEED_PATH), "2026.10.30.6\n").unwrap();
    assert!(resolve(root).unwrap_err().contains("full Git checkout"));
    git(root, &["init"]).unwrap();
    commit(root, "2026-10-30T00:00:00Z");
    assert_eq!(resolve(root).unwrap(), ("2026.10.30.6".into(), None));
    commit(root, "2026-10-30T02:00:00Z");
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.7");
    let second = git(root, &["rev-parse", "HEAD"]).unwrap();
    commit(root, "2026-10-31T02:00:00+09:00");
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.8");
    commit(root, "2026-10-31T02:00:00Z");
    assert_eq!(resolve(root).unwrap().0, "2026.10.31.1");
    git(root, &["checkout", "--detach", second.trim()]).unwrap();
    assert_eq!(resolve(root).unwrap().0, "2026.10.30.7");
    fs::write(root.join(SEED_PATH), "2026.10.30.9\n").unwrap();
    assert!(resolve(root).unwrap_err().contains("immutable"));
    fs::write(root.join(SEED_PATH), "2026.10.30.6\n").unwrap();
    fs::write(root.join(".git/shallow"), second.trim()).unwrap();
    assert!(resolve(root).unwrap_err().contains("full Git history"));
}

#[test]
fn cargo_rebuilds_embedded_version_after_documentation_commits_and_detached_checkout() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let core = root.join("crates/netcontrol-core");
    fs::create_dir_all(core.join("src")).unwrap();
    fs::write(root.join(".gitignore"), "/target/\n/Cargo.lock\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/netcontrol-core\"]\nresolver = \"3\"\n",
    )
    .unwrap();
    fs::write(core.join("Cargo.toml"), "[package]\nname = \"netcontrol-version-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[build-dependencies]\nchrono = { version = \"0.4\", default-features = false, features = [\"std\"] }\n").unwrap();
    fs::write(
        core.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"NETCONTROL_RELEASE_VERSION\")); }\n",
    )
    .unwrap();
    fs::write(root.join(SEED_PATH), "2026.10.30.6\n").unwrap();
    for name in ["build.rs", "build_version.rs"] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(name),
            core.join(name),
        )
        .unwrap();
    }
    git(root, &["init"]).unwrap();
    commit(root, "2026-10-30T00:00:00Z");
    let first = git(root, &["rev-parse", "HEAD"]).unwrap();
    let run = || {
        let output = Command::new(env!("CARGO"))
            .current_dir(root)
            .args(["run", "--quiet", "--offline"])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    assert_eq!(run(), "2026.10.30.6");
    fs::write(root.join("notes.txt"), "documentation-only fixture\n").unwrap();
    commit(root, "2026-10-30T02:00:00Z");
    assert_eq!(run(), "2026.10.30.7");
    git(root, &["checkout", "--detach", first.trim()]).unwrap();
    assert_eq!(run(), "2026.10.30.6");
}
