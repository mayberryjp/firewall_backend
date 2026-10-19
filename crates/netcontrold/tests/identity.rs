use netcontrold::identity::{IdentityError, Store, secret};
use std::{fs, path::PathBuf};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".test-data")
            .join(secret("").unwrap());
        fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("identity.json")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn status(error: anyhow::Error) -> u16 {
    error.downcast::<IdentityError>().unwrap().status
}

#[test]
fn durable_identity_lock_reopen_and_hashes_only() {
    let dir = Directory::new();
    let mut store = Store::open(&dir.path()).unwrap();
    assert!(Store::open(&dir.path()).is_err());
    let session = store.setup("admin", "a unique test password").unwrap();
    let (key, token) = store.create_key(&session, "dashboard").unwrap();
    assert!(store.authenticate(&token).is_none());
    store.complete(&session).unwrap();
    assert!(store.authenticate(&token).is_some());
    let bytes = fs::read_to_string(dir.path()).unwrap();
    for secret in [&session, &token, "a unique test password"] {
        assert!(!bytes.contains(secret));
    }
    drop(store);
    let mut store = Store::open(&dir.path()).unwrap();
    assert_eq!(store.status(), (true, true, "admin"));
    store.session(&session).unwrap();
    assert_eq!(store.authenticate(&token).unwrap().id, key.id);
    assert_eq!(
        status(store.login("ADMIN", "a unique test password").unwrap_err()),
        401
    );
    assert!(store.login("admin", "a unique test password").is_ok());
    store.delete_key(&session, &key.id).unwrap();
    assert!(store.authenticate(&token).is_none());
    store.logout(&session).unwrap();
    assert_eq!(status(store.session(&session).unwrap_err()), 401);
}

#[test]
fn refuses_existing_invalid_empty_and_foreign_data_without_resetting() {
    for input in [
        b"".as_slice(),
        b"not json",
        b"{}",
        b"{\"schema\":2,\"account\":null,\"sessions\":{},\"keys\":{}}",
        b"{\"schema\":1,\"account\":null,\"sessions\":{},\"keys\":{},\"unknown\":true}",
    ] {
        let dir = Directory::new();
        fs::write(dir.path(), input).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(Store::open(&dir.path()).is_err());
        assert_eq!(fs::read(dir.path()).unwrap(), input);
    }
}

#[test]
fn names_passwords_key_cap_session_cap_and_expiry() {
    let dir = Directory::new();
    let mut store = Store::open(&dir.path()).unwrap();
    for (name, password) in [
        ("", "a long test password"),
        (" admin", "a long test password"),
        ("bad\nname", "a long test password"),
        ("admin", "short"),
        (
            "admin",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
    ] {
        assert_eq!(status(store.setup(name, password).unwrap_err()), 400);
    }
    let session = store.setup("admin", "a long test password").unwrap();
    for name in ["", " bad", "bad\nname"] {
        assert_eq!(status(store.create_key(&session, name).err().unwrap()), 400);
    }
    for i in 0..100 {
        store.create_key(&session, &format!("key-{i}")).unwrap();
    }
    assert_eq!(
        status(store.create_key(&session, "overflow").err().unwrap()),
        400
    );
    drop(store);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path()).unwrap()).unwrap();
    let sessions = value["sessions"].as_object_mut().unwrap();
    let hash = sessions.keys().next().unwrap().clone();
    sessions.insert(hash, serde_json::json!(1));
    fs::write(dir.path(), serde_json::to_vec(&value).unwrap()).unwrap();
    let store = Store::open(&dir.path()).unwrap();
    assert_eq!(status(store.session(&session).unwrap_err()), 401);
    drop(store);
    let sessions = value["sessions"].as_object_mut().unwrap();
    sessions.clear();
    for i in 0..32 {
        sessions.insert(
            format!("{i:064x}"),
            serde_json::json!(netcontrold::identity::now() + 1800),
        );
    }
    fs::write(dir.path(), serde_json::to_vec(&value).unwrap()).unwrap();
    let mut store = Store::open(&dir.path()).unwrap();
    assert_eq!(
        status(store.login("admin", "a long test password").unwrap_err()),
        409
    );
}

#[test]
fn failed_persistence_does_not_mutate_live_identity() {
    let dir = Directory::new();
    let mut store = Store::open(&dir.path()).unwrap();
    let session = store.setup("admin", "a unique test password").unwrap();
    let before = fs::read(dir.path()).unwrap();
    fs::remove_file(dir.path()).unwrap();
    fs::create_dir(dir.path()).unwrap();
    assert!(store.create_key(&session, "unpersisted").is_err());
    assert!(store.check_health().is_err());
    assert!(store.keys(&session).is_err());
    fs::remove_dir(dir.path()).unwrap();
    fs::write(dir.path(), before).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(store);
    let store = Store::open(&dir.path()).unwrap();
    assert!(store.keys(&session).unwrap().is_empty());
}

#[test]
fn failed_claim_is_not_visible_and_pending_setup_resumes_after_restart() {
    let dir = Directory::new();
    let mut store = Store::open(&dir.path()).unwrap();
    let empty = fs::read(dir.path()).unwrap();
    fs::remove_file(dir.path()).unwrap();
    fs::create_dir(dir.path()).unwrap();
    assert!(store.setup("admin", "a unique test password").is_err());
    assert!(!store.status().0);
    assert!(store.check_health().is_err());
    fs::remove_dir(dir.path()).unwrap();
    fs::write(dir.path(), empty).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(store);
    let mut store = Store::open(&dir.path()).unwrap();
    let session = store.setup("admin", "a unique test password").unwrap();
    drop(store);
    let mut store = Store::open(&dir.path()).unwrap();
    assert_eq!(store.status(), (true, false, "admin"));
    store.session(&session).unwrap();
    let (_, key) = store.create_key(&session, "resumed").unwrap();
    assert!(store.authenticate(&key).is_none());
    store.complete(&session).unwrap();
    assert!(store.authenticate(&key).is_some());
}

#[cfg(unix)]
#[test]
fn rejects_world_readable_symlink_and_hardlink_databases() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Directory::new();
    let store = Store::open(&dir.path()).unwrap();
    drop(store);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(&dir.path()).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let other = dir.0.join("other");
    fs::rename(dir.path(), &other).unwrap();
    symlink(&other, dir.path()).unwrap();
    assert!(Store::open(&dir.path()).is_err());
    fs::remove_file(dir.path()).unwrap();
    fs::hard_link(&other, dir.path()).unwrap();
    assert!(Store::open(&dir.path()).is_err());
}
