#![cfg(target_os = "linux")]

use netcontrol_core::{Engine, Simulator};
use netcontrold::{
    http::{App, Authentication},
    identity::Store,
    local_control::Listener,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::watch,
};
use zeroize::Zeroizing;

fn make_app(directory: &Path, scoped: bool) -> Arc<App> {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run ignored local-control tests as Linux root"
    );
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::open(&directory.join("state.json"), Box::new(Simulator::new())).unwrap();
    let auth = if scoped {
        Authentication::Scoped(vec![])
    } else {
        Authentication::Device(Mutex::new(
            Store::open(&directory.join("identity.json")).unwrap(),
        ))
    };
    App::new(Arc::new(Mutex::new(engine)), auth, false)
}

async fn exchange(path: &Path, request: Value) -> Value {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let bytes = Zeroizing::new(serde_json::to_vec(&request).unwrap());
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let length = stream.read_u32().await.unwrap();
    assert!(length <= 4096);
    let mut bytes = Zeroizing::new(vec![0; length as usize]);
    stream.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires Linux root"]
async fn live_key_is_immediately_authenticated_persisted_and_listener_restarts() {
    let directory = tempfile::tempdir_in("/run").unwrap();
    let app = make_app(directory.path(), false);
    let path = directory.path().join("control.sock");
    let listener = Listener::bind(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(Listener::bind(&path).is_err());
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(listener.serve(app.clone(), receiver));
    assert_eq!(
        exchange(&path, json!({"operation":"Status"})).await,
        json!({"result":"Status","account_exists":false})
    );
    let created = exchange(
        &path,
        json!({
            "operation":"CreateKey","name":"console",
            "account":{"username":"operator","password":"a unique test password"}
        }),
    )
    .await;
    assert_eq!(created["result"], "Created");
    let token = Zeroizing::new(created["api_key"].as_str().unwrap().to_owned());
    let credential = app.authenticate_api_key(&token).unwrap().unwrap();
    assert!(
        credential
            .permissions
            .iter()
            .any(|p| p == "interfaces.write")
    );
    assert!(
        credential
            .permissions
            .iter()
            .any(|p| p == "transactions.write")
    );
    let duplicate = exchange(
        &path,
        json!({"operation":"CreateKey","name":"console","account":null}),
    )
    .await;
    assert_eq!(duplicate["result"], "Error");
    let (first, second) = tokio::join!(
        exchange(
            &path,
            json!({"operation":"CreateKey","name":"parallel-one","account":null})
        ),
        exchange(
            &path,
            json!({"operation":"CreateKey","name":"parallel-two","account":null})
        )
    );
    for created in [first, second] {
        assert_eq!(created["result"], "Created");
        assert!(
            app.authenticate_api_key(created["api_key"].as_str().unwrap())
                .unwrap()
                .is_some()
        );
    }
    let stored = fs::read_to_string(directory.path().join("identity.json")).unwrap();
    assert!(!stored.contains(token.as_str()));
    assert!(!stored.contains("a unique test password"));
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(!path.exists());
    drop(app);
    let mut store = Store::open(&directory.path().join("identity.json")).unwrap();
    let key = store.authenticate(&token).unwrap();
    let session = store.login("operator", "a unique test password").unwrap();
    store.delete_key(&session, &key.id).unwrap();
    assert!(store.authenticate(&token).is_none());
    drop(store);
    let listener = Listener::bind(&path).unwrap();
    let (stop, receiver) = watch::channel(true);
    listener
        .serve(make_app(directory.path(), false), receiver)
        .await
        .unwrap();
    drop(stop);
    assert!(!path.exists());
}

#[tokio::test]
#[ignore = "requires Linux root"]
async fn refuses_foreign_paths_and_cleans_only_owned_socket() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir_in("/run").unwrap();
    let app = make_app(directory.path(), false);
    let path = directory.path().join("control.sock");
    fs::write(&path, b"not a socket").unwrap();
    assert!(Listener::bind(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"not a socket");
    fs::remove_file(&path).unwrap();
    let other = directory.path().join("other");
    fs::write(&other, b"foreign").unwrap();
    symlink(&other, &path).unwrap();
    assert!(Listener::bind(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Listener::bind(&path).is_err());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let listener = Listener::bind(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();
    let (_stop, receiver) = watch::channel(true);
    assert!(listener.serve(app, receiver).await.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
}

#[tokio::test]
#[ignore = "requires Linux root"]
async fn framing_scoped_auth_and_idle_shutdown_are_bounded() {
    let directory = tempfile::tempdir_in("/run").unwrap();
    let app = make_app(directory.path(), true);
    let path = directory.path().join("control.sock");
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(Listener::bind(&path).unwrap().serve(app, receiver));
    let denied = exchange(
        &path,
        json!({"operation":"CreateKey","name":"console","account":null}),
    )
    .await;
    assert_eq!(denied["result"], "Error");
    for length in [0, 4097, u32::MAX] {
        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_u32(length).await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }
    let mut malformed = UnixStream::connect(&path).await.unwrap();
    let bytes = br#"{"operation":"Status","extra":true}"#;
    malformed.write_u32(bytes.len() as u32).await.unwrap();
    malformed.write_all(bytes).await.unwrap();
    assert_eq!(malformed.read(&mut [0; 1]).await.unwrap(), 0);
    let _idle = UnixStream::connect(&path).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(12), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!path.exists());
}

fn interactive_key(path: &Path, setup: bool, mismatch: bool) -> String {
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    let mut command = Command::new(env!("CARGO_BIN_EXE_netcontrold"));
    command
        .args([
            "--create-api-key",
            if setup { "first" } else { "second" },
            "--control-socket",
        ])
        .arg(path)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        });
    }
    let mut child = ChildGuard(command.spawn().unwrap());
    drop(command);
    drop(slave);
    {
        let prompts: &[(&str, &[u8])] = if setup {
            &[
                ("Device username: ", b"operator\n"),
                (
                    "Device password (12..72 bytes): ",
                    b"a unique test password\n",
                ),
                (
                    "Confirm password: ",
                    if mismatch {
                        b"another test password\n"
                    } else {
                        b"a unique test password\n"
                    },
                ),
            ]
        } else {
            &[]
        };
        let mut output = Zeroizing::new(String::new());
        let mut next = 0;
        loop {
            let mut poll = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert!(
                unsafe { libc::poll(&mut poll, 1, 15000) } > 0,
                "interactive CLI timed out at prompt {next}; child status: {:?}",
                child.0.try_wait().unwrap()
            );
            let mut bytes = [0; 512];
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(length) => output.push_str(std::str::from_utf8(&bytes[..length]).unwrap()),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("PTY read failed: {error}"),
            }
            if next < prompts.len() && output.contains(prompts[next].0) {
                master.write_all(prompts[next].1).unwrap();
                next += 1;
            }
        }
        assert_eq!(
            child.0.wait().unwrap().success(),
            !mismatch,
            "unexpected interactive CLI result"
        );
        assert_eq!(next, prompts.len());
        assert!(
            !output.contains("a unique test password"),
            "password was echoed"
        );
        assert!(
            !output.contains("another test password"),
            "confirmation was echoed"
        );
        if mismatch {
            assert!(output.contains("passwords do not match"));
            assert!(!output.lines().any(|line| line.starts_with("nc_")));
            return String::new();
        }
        let token = output.lines().find(|line| line.starts_with("nc_")).unwrap();
        assert_eq!(token.len(), 67);
        token.to_owned()
    }
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires Linux root"]
async fn daemon_serves_live_control_and_removes_socket_on_sigterm() {
    let directory = tempfile::tempdir_in("/run").unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("control.sock");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_netcontrold"))
            .args([
                "--backend",
                "simulator",
                "--disable-release-checks",
                "--listen",
            ])
            .arg(format!("127.0.0.1:{port}"))
            .arg("--state")
            .arg(directory.path().join("state.json"))
            .arg("--credential-db")
            .arg(directory.path().join("identity.json"))
            .arg("--control-socket")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "daemon exited before local control readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        exchange(&path, json!({"operation":"Status"})).await["account_exists"],
        false
    );
    let created = exchange(
        &path,
        json!({
            "operation":"CreateKey","name":"process",
            "account":{"username":"operator","password":"a unique test password"}
        }),
    )
    .await;
    assert_eq!(created["result"], "Created");
    let token = Zeroizing::new(created["api_key"].as_str().unwrap().to_owned());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(response) = reqwest::Client::new()
                .get(format!("http://127.0.0.1:{port}/api/v1/state"))
                .bearer_auth(token.as_str())
                .send()
                .await
            {
                assert!(
                    response.status().is_success(),
                    "live local key was not accepted over HTTP"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let status: Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        status,
        json!({"stage":"login","authenticated":false,"configured":true,"username":""})
    );
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(status.success(), "daemon shutdown failed");
    assert!(!path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Linux root and a PTY"]
async fn exact_cli_prompts_once_then_adds_key_without_resetting_account() {
    let directory = tempfile::tempdir_in("/run").unwrap();
    let app = make_app(directory.path(), false);
    let path = directory.path().join("control.sock");
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(Listener::bind(&path).unwrap().serve(app.clone(), receiver));
    let mismatch_path = path.clone();
    tokio::task::spawn_blocking(move || interactive_key(&mismatch_path, true, true))
        .await
        .unwrap();
    assert_eq!(
        exchange(&path, json!({"operation":"Status"})).await["account_exists"],
        false
    );
    for setup in [true, false] {
        let path = path.clone();
        let token = Zeroizing::new(
            tokio::task::spawn_blocking(move || interactive_key(&path, setup, false))
                .await
                .unwrap(),
        );
        assert!(app.authenticate_api_key(&token).unwrap().is_some());
    }
    let denied = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
        .args(["--create-api-key", "nonroot", "--control-socket"])
        .arg(&path)
        .uid(65534)
        .gid(65534)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(
        String::from_utf8(denied.stderr)
            .unwrap()
            .contains("requires root")
    );
    let redirected = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
        .args(["--create-api-key", "redirected", "--control-socket"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!redirected.status.success());
    assert!(
        String::from_utf8(redirected.stderr)
            .unwrap()
            .contains("requires a terminal")
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Linux root"]
async fn root_peer_credentials_are_required_even_if_socket_permissions_are_relaxed() {
    if let Some(path) = std::env::var_os("NETCONTROL_TEST_PEER_SOCKET") {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let mut stream = UnixStream::connect(path).await.unwrap();
        let result = stream.read(&mut [0; 1]).await;
        assert!(matches!(result, Ok(0)) || result.is_err());
        return;
    }
    let directory = tempfile::tempdir_in("/run").unwrap();
    let app = make_app(directory.path(), false);
    let path = directory.path().join("control.sock");
    let (stop, receiver) = watch::channel(false);
    let listener = Listener::bind(&path).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o711)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let task = tokio::spawn(listener.serve(app, receiver));
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "root_peer_credentials_are_required_even_if_socket_permissions_are_relaxed",
            "--ignored",
        ])
        .env("NETCONTROL_TEST_PEER_SOCKET", &path)
        .uid(65534)
        .gid(65534)
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
