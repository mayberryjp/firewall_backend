use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

fn available() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn connect(child: &mut Daemon, address: SocketAddr) -> TcpStream {
    let start = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            child
                .0
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            panic!("daemon exited before readiness: {status}: {error}");
        }
        if let Ok(stream) = TcpStream::connect(address) {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            return stream;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "daemon never became ready"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn actual_daemon_exposes_http_and_custom_ssh_and_reuses_host_identity() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state.json");
    let identity = directory.path().join("identity.json");
    let key = directory.path().join("host.ssh-key");
    let mut public_identity = None;
    for explicit_listener in [false, true] {
        let http = available();
        let ssh = loop {
            let address = available();
            if address != http {
                break address;
            }
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_netcontrold"));
        command
            .env("NETCONTROL_ALLOW_HOST_SERVICES", "true")
            .env("NETCONTROL_GATEWAY_MONITORING", "true")
            .env(
                "NETCONTROL_SSH_LISTEN",
                if explicit_listener {
                    "invalid-listener".to_string()
                } else {
                    ssh.to_string()
                },
            )
            .args(["--listen", &http.to_string()]);
        if explicit_listener {
            command.args(["--ssh-listen", &ssh.to_string()]);
        }
        let mut child = Daemon(
            command
                .arg("--state")
                .arg(&state)
                .arg("--credential-db")
                .arg(&identity)
                .arg("--ssh-host-key")
                .arg(&key)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stream = connect(&mut child, http);
        stream
            .write_all(b"GET /auth/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"stage\":\"account\""), "{response}");
        let mut stream = connect(&mut child, ssh);
        let mut banner = [0; 256];
        let len = stream.read(&mut banner).unwrap();
        assert!(
            banner[..len].starts_with(b"SSH-2.0-"),
            "{:?}",
            &banner[..len]
        );
        let data = std::fs::read(&key).unwrap();
        if let Some(expected) = &public_identity {
            assert_eq!(&data, expected, "host key changed across restart");
        } else {
            public_identity = Some(data);
        }
    }
}

#[test]
fn invalid_service_opt_in_environment_fails_before_creating_state() {
    for variable in [
        "NETCONTROL_ALLOW_HOST_SERVICES",
        "NETCONTROL_GATEWAY_MONITORING",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.json");
        let output = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
            .env_remove("NETCONTROL_ALLOW_HOST_SERVICES")
            .env_remove("NETCONTROL_GATEWAY_MONITORING")
            .env(variable, "invalid")
            .arg("--state")
            .arg(&state)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("invalid value"), "{error}");
        assert!(!state.exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wireguard_key_flags_print_only_the_public_key_and_never_overwrite_or_start_the_daemon() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let keys = directory.path().join("keys");
    let run = |flag: &str, name: &str| {
        Command::new(env!("CARGO_BIN_EXE_netcontrold"))
            .current_dir(directory.path())
            .args([flag, name, "--keys"])
            .arg(&keys)
            .output()
            .unwrap()
    };
    let created = run("--create-wireguard-key", "wg-wan");
    assert!(created.status.success(), "{created:?}");
    assert!(created.stderr.is_empty());
    let public = String::from_utf8(created.stdout).unwrap();
    assert_eq!(public.trim_end().len(), 44);
    assert!(public.ends_with('\n') && public.matches('\n').count() == 1);
    let private = std::fs::read_to_string(keys.join("wg-wan")).unwrap();
    assert!(
        !public.contains(private.trim_end())
            && !String::from_utf8_lossy(&created.stderr).contains(private.trim_end())
    );
    assert_eq!(
        std::fs::metadata(keys.join("wg-wan"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let shown = run("--wireguard-public-key", "wg-wan");
    assert!(shown.status.success());
    assert_eq!(String::from_utf8(shown.stdout).unwrap(), public);
    let again = run("--create-wireguard-key", "wg-wan");
    assert!(!again.status.success() && again.stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(keys.join("wg-wan")).unwrap(),
        private
    );
    let invalid = run("--create-wireguard-key", "../escape");
    assert!(!invalid.status.success() && invalid.stdout.is_empty());
    assert!(!run("--wireguard-public-key", "missing").status.success());
    let both = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
        .args(["--create-wireguard-key", "a", "--wireguard-public-key", "a"])
        .output()
        .unwrap();
    assert!(!both.status.success());
    let mut names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["keys"]);
}

#[test]
fn invalid_existing_host_key_and_state_alias_fail_startup_without_reset() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state.json");
    let key = directory.path().join("host.ssh-key");
    std::fs::write(&key, b"not a host key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
        .args(["--listen", "127.0.0.1:0", "--ssh-listen", "127.0.0.1:0"])
        .arg("--state")
        .arg(&state)
        .arg("--ssh-host-key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&key).unwrap(), b"not a host key");
    assert!(!state.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_netcontrold"))
        .args(["--listen", "127.0.0.1:0", "--ssh-listen", "127.0.0.1:0"])
        .arg("--state")
        .arg(&state)
        .arg("--ssh-host-key")
        .arg(&state)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("SSH host key must use a different path")
    );
    assert!(!state.exists());
}

#[test]
fn http_bind_failure_stops_custom_ssh_and_exits_without_hanging() {
    let directory = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let http = occupied.local_addr().unwrap();
    let ssh = available();
    let mut child = Daemon(
        Command::new(env!("CARGO_BIN_EXE_netcontrold"))
            .args([
                "--listen",
                &http.to_string(),
                "--ssh-listen",
                &ssh.to_string(),
            ])
            .arg("--state")
            .arg(directory.path().join("state.json"))
            .arg("--credential-db")
            .arg(directory.path().join("identity.json"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            child
                .0
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            assert!(!status.success());
            assert!(error.contains("HTTP listener failed"), "{error}");
            assert!(
                TcpStream::connect(ssh).is_err(),
                "SSH listener outlived failed daemon"
            );
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "failed HTTP startup did not stop SSH"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
