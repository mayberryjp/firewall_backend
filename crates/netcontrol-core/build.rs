mod build_version;

use std::{env, path::Path};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let root = Path::new(&manifest)
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    println!("cargo:rerun-if-changed=build_version.rs");
    println!("cargo:rerun-if-changed=release-version");
    if root.join(".git").exists() {
        for name in ["HEAD", "packed-refs", "refs"] {
            let path = build_version::git(root, &["rev-parse", "--git-path", name])
                .unwrap_or_else(|error| panic!("{error}"));
            let path = root.join(path.trim());
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    let (version, warning) = build_version::resolve(root)
        .unwrap_or_else(|error| panic!("cannot determine release version: {error}"));
    if let Some(warning) = warning {
        println!("cargo:warning={warning}");
    }
    println!("cargo:rustc-env=NETCONTROL_RELEASE_VERSION={version}");
}
