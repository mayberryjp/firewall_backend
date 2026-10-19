use axum::{body::Body, http::Request};
use netcontrol_core::{Backend, Config, Engine, PERMISSIONS, Simulator};
use netcontrold::{
    http::{App, Authentication, Credential, router},
    identity::{Store, digest},
    ssh::{load_host_key, serve},
};
use russh::{Channel, ChannelMsg, Disconnect, client, keys::PublicKey};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};
use tower::ServiceExt;

const KEY: &str = "synthetic-scoped-test-api-key";
const WAIT: Duration = Duration::from_secs(10);

fn directory() -> TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-data");
    fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("ssh-")
        .tempdir_in(root)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

struct Client(PublicKey);
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.certificate().is_none() && key.public_key().key_data() == self.0.key_data())
    }
}

struct Fixture {
    directory: TempDir,
    app: Arc<App>,
    address: SocketAddr,
    key: PublicKey,
    stop: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}
impl Fixture {
    async fn scoped(permissions: &[&str]) -> Self {
        Self::scoped_backend(permissions, Box::new(Simulator::new())).await
    }
    async fn scoped_backend(permissions: &[&str], backend: Box<dyn Backend>) -> Self {
        let directory = directory();
        let engine = Engine::open(&directory.path().join("state.json"), backend).unwrap();
        let app = App::new(
            Arc::new(Mutex::new(engine)),
            Authentication::Scoped(vec![Credential {
                name: "ssh-test".into(),
                token_sha256: digest(KEY),
                permissions: permissions.iter().map(|p| p.to_string()).collect(),
            }]),
            false,
        );
        Self::start(directory, app).await
    }
    async fn start(directory: TempDir, app: Arc<App>) -> Self {
        let path = directory.path().join("ssh_host_ed25519_key");
        let key = load_host_key(&path).unwrap().public_key().clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, receiver) = watch::channel(false);
        let server_app = app.clone();
        let task = tokio::spawn(async move { serve(listener, &path, server_app, receiver).await });
        Self {
            directory,
            app,
            address,
            key,
            stop,
            task,
        }
    }
    async fn connect(&self) -> client::Handle<Client> {
        tokio::time::timeout(
            WAIT,
            client::connect(
                Arc::new(client::Config::default()),
                self.address,
                Client(self.key.clone()),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn login(&self, token: &str) -> client::Handle<Client> {
        let mut connection = self.connect().await;
        assert!(
            connection
                .authenticate_password("apikey", token)
                .await
                .unwrap()
                .success()
        );
        connection
    }
    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(self.address).await.is_err());
        // Keep identity locks and the state directory alive until the server has exited.
        let app = Arc::downgrade(&self.app);
        drop(self.app);
        assert!(
            app.upgrade().is_none(),
            "SSH session or worker leaked its App"
        );
        drop(self.directory);
    }
}

async fn exec(fixture: &Fixture, command: &[u8]) -> (String, Option<u32>, bool) {
    let connection = fixture.login(KEY).await;
    let mut channel = connection.channel_open_session().await.unwrap();
    channel.exec(true, command.to_vec()).await.unwrap();
    let result = tokio::time::timeout(WAIT, async {
        let mut output = Vec::new();
        let mut status = None;
        let mut rejected = false;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Failure => rejected = true,
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        (String::from_utf8(output).unwrap(), status, rejected)
    })
    .await
    .unwrap();
    let _ = connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await;
    result
}

async fn prompt(channel: &mut Channel<client::Msg>) -> String {
    tokio::time::timeout(WAIT, async {
        let mut output = String::new();
        loop {
            match channel.wait().await.expect("channel closed before prompt") {
                ChannelMsg::Data { data } => {
                    output.push_str(std::str::from_utf8(&data).unwrap());
                    if [
                        "netcontrol> ",
                        "netcontrol# ",
                        "netcontrol(config)# ",
                        "netcontrol(config-if)# ",
                    ]
                    .iter()
                    .any(|prompt| output.ends_with(prompt))
                    {
                        return output;
                    }
                }
                ChannelMsg::Failure => panic!("shell request unexpectedly rejected"),
                _ => {}
            }
        }
    })
    .await
    .unwrap()
}

async fn shell(connection: &client::Handle<Client>) -> Channel<client::Msg> {
    let mut channel = connection.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    assert!(
        prompt(&mut channel)
            .await
            .contains("Netcontrol configuration CLI")
    );
    channel
}

async fn command(channel: &mut Channel<client::Msg>, command: &str) -> String {
    channel
        .data(format!("{command}\r\n").as_bytes())
        .await
        .unwrap();
    prompt(channel).await
}

async fn next(channel: &mut Channel<client::Msg>) -> Option<ChannelMsg> {
    tokio::time::timeout(WAIT, channel.wait()).await.unwrap()
}

#[tokio::test]
async fn authentication_is_fixed_username_and_api_key_only() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    for (user, password) in [("admin", KEY), ("apikey", "incorrect-key"), ("apikey", "")] {
        let mut connection = fixture.connect().await;
        assert!(
            !connection
                .authenticate_password(user, password)
                .await
                .unwrap()
                .success()
        );
        let _ = connection
            .disconnect(Disconnect::ByApplication, "test completed", "")
            .await;
    }
    let connection = fixture.login(KEY).await;
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn exec_has_truthful_status_and_rejects_multiline_controls_and_invalid_utf8() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let (output, status, rejected) = exec(&fixture, b"show running-config").await;
    assert!(output.contains("Committed running configuration"));
    assert_eq!(status, Some(0));
    assert!(!rejected);
    let (output, status, _) = exec(&fixture, b"not-an-os-shell").await;
    assert!(output.contains('%'));
    assert_eq!(status, Some(1));
    for input in [
        &b"show runtime\nshow running-config"[..],
        &b"show runtime\rshow running-config"[..],
        &b"show \x1bruntime"[..],
        &b"show \xff"[..],
        &b""[..],
    ] {
        let (_, status, rejected) = exec(&fixture, input).await;
        assert!(rejected);
        assert_eq!(status, Some(1));
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn oversized_json_output_is_an_explicit_exec_failure_and_shell_recovers() {
    struct LargeRuntime(Simulator);
    impl Backend for LargeRuntime {
        fn scope(&self) -> anyhow::Result<String> {
            self.0.scope()
        }
        fn observe(&mut self, expected: &Config) -> anyhow::Result<Config> {
            self.0.observe(expected)
        }
        fn apply(&mut self, before: &Config, after: &Config) -> anyhow::Result<()> {
            self.0.apply(before, after)
        }
        fn runtime(&mut self, _: &Config) -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::json!({"oversized_payload_marker": "x".repeat(4 * 1024 * 1024)}))
        }
        fn statistics(
            &mut self,
            config: &Config,
            path: &str,
            query: &str,
        ) -> anyhow::Result<serde_json::Value> {
            self.0.statistics(config, path, query)
        }
        fn repair(&mut self, config: &Config) -> anyhow::Result<serde_json::Value> {
            self.0.repair(config)
        }
    }
    let fixture =
        Fixture::scoped_backend(&["state.read"], Box::new(LargeRuntime(Simulator::new()))).await;
    let (output, status, rejected) = exec(&fixture, b"show runtime").await;
    assert_eq!(status, Some(1));
    assert!(!rejected);
    assert!(output.contains("Output exceeds the 4 MiB SSH limit"));
    assert!(output.contains("no command output was sent"));
    assert!(output.contains("may already have completed or applied changes"));
    assert!(output.contains("inspect state and transactions before retrying"));
    assert!(!output.contains("oversized_payload_marker"));
    assert!(output.len() < 512);
    let connection = fixture.login(KEY).await;
    let mut channel = shell(&connection).await;
    let output = command(&mut channel, "show runtime").await;
    assert!(output.contains("Output exceeds the 4 MiB SSH limit"));
    assert!(!output.contains("oversized_payload_marker"));
    assert!(output.len() < 512);
    assert!(
        command(&mut channel, "show running-config")
            .await
            .contains("Committed running configuration")
    );
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn forwarding_subsystems_environment_and_second_channels_are_rejected() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let connection = fixture.login(KEY).await;
    assert!(
        connection
            .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 1)
            .await
            .is_err()
    );
    assert!(connection.tcpip_forward("127.0.0.1", 0).await.is_err());
    let mut channel = connection.channel_open_session().await.unwrap();
    assert!(connection.channel_open_session().await.is_err());
    channel.set_env(true, "PATH", "/not-used").await.unwrap();
    assert!(matches!(
        next(&mut channel).await,
        Some(ChannelMsg::Failure)
    ));
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(matches!(
        next(&mut channel).await,
        Some(ChannelMsg::Failure)
    ));
    channel.agent_forward(true).await.unwrap();
    assert!(matches!(
        next(&mut channel).await,
        Some(ChannelMsg::Failure)
    ));
    channel
        .request_x11(true, true, "MIT-MAGIC-COOKIE-1", "synthetic-cookie", 0)
        .await
        .unwrap();
    assert!(matches!(
        next(&mut channel).await,
        Some(ChannelMsg::Failure)
    ));
    channel.request_shell(true).await.unwrap();
    assert!(matches!(
        next(&mut channel).await,
        Some(ChannelMsg::Failure)
    ));
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    assert!(
        prompt(&mut channel)
            .await
            .contains("Netcontrol configuration CLI")
    );
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn shell_line_editing_input_rejection_and_scopes() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let connection = fixture.login(KEY).await;
    let mut channel = shell(&connection).await;
    let output = command(&mut channel, "show runtimx\u{7f}e").await;
    assert!(!output.contains("% "));
    channel.data(&b"show runtime\r"[..]).await.unwrap();
    let output = prompt(&mut channel).await;
    assert!(!output.contains("% "));
    channel
        .data(&b"\nshow running-config\r\n"[..])
        .await
        .unwrap();
    assert!(
        prompt(&mut channel)
            .await
            .contains("Committed running configuration")
    );
    assert!(
        command(&mut channel, "show \u{1b}[31mruntime")
            .await
            .contains("Invalid input")
    );
    channel.data(&b"show \xff\r\n"[..]).await.unwrap();
    assert!(prompt(&mut channel).await.contains("Invalid input"));
    assert!(command(&mut channel, "?").await.contains("Cisco-inspired"));
    command(&mut channel, "enable").await;
    let denied = command(&mut channel, "configure terminal").await;
    assert!(
        denied.contains("permission") || denied.contains("403"),
        "{denied}"
    );
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn oversized_shell_line_is_discarded_and_next_command_is_valid() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let connection = fixture.login(KEY).await;
    let mut channel = shell(&connection).await;
    let oversized = format!("{}\r\n", "x".repeat(65_537));
    channel.data(oversized.as_bytes()).await.unwrap();
    assert!(prompt(&mut channel).await.contains("Invalid input"));
    assert!(
        command(&mut channel, "show running-config")
            .await
            .contains("Committed running configuration")
    );
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

async fn orderly_close(channel: &mut Channel<client::Msg>) -> u32 {
    tokio::time::timeout(WAIT, async {
        let mut status = None;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::ExitStatus { exit_status }) => status = Some(exit_status),
                Some(ChannelMsg::Close) | None => return status.expect("exit status missing"),
                _ => {}
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn ctrl_c_cancels_without_newline_and_ctrl_d_discards_candidate_and_partial_input() {
    let fixture = Fixture::scoped(PERMISSIONS).await;
    let connection = fixture.login(KEY).await;
    let mut channel = shell(&connection).await;
    edit_candidate(&mut channel).await;
    channel
        .data(&b"commit confirmed 30 must-not-run\x03"[..])
        .await
        .unwrap();
    let output = prompt(&mut channel).await;
    assert!(output.contains("^C\r\n"));
    assert!(!output.contains("Provisional apply"));
    assert!(output.ends_with("netcontrol(config)# "));
    assert!(
        command(&mut channel, "show candidate-config")
            .await
            .contains("lan0")
    );
    assert!(
        !command(&mut channel, "show transactions")
            .await
            .contains("pending_confirmation")
    );
    // Ctrl-C also recovers a poisoned line immediately.
    channel.data(&b"\x1b[31m\x03"[..]).await.unwrap();
    assert!(prompt(&mut channel).await.contains("^C\r\n"));
    channel
        .data(&b"commit confirmed 30 must-not-run\x04show runtime\r\n"[..])
        .await
        .unwrap();
    assert_eq!(orderly_close(&mut channel).await, 0);
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    let (running, status, _) = exec(&fixture, b"show running-config").await;
    assert_eq!(status, Some(0));
    assert!(!running.contains("lan0"));
    let (transactions, status, _) = exec(&fixture, b"show transactions").await;
    assert_eq!(status, Some(0));
    assert!(!transactions.contains("must-not-run"));
    let next_connection = fixture.login(KEY).await;
    let mut next_channel = shell(&next_connection).await;
    assert!(
        command(&mut next_channel, "show candidate-config")
            .await
            .contains("no candidate")
    );
    next_connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn ctrl_d_leaves_pending_transaction_engine_owned_and_discards_new_candidate() {
    let fixture = Fixture::scoped(PERMISSIONS).await;
    let connection = fixture.login(KEY).await;
    let mut channel = shell(&connection).await;
    edit_candidate(&mut channel).await;
    assert!(
        command(&mut channel, "commit confirmed 30 ctrl-d-pending")
            .await
            .contains("Provisional apply only")
    );
    command(&mut channel, "configure terminal").await;
    command(&mut channel, "set /firewall/policy \"drop\"").await;
    channel.data(&b"rollback\x04"[..]).await.unwrap();
    assert_eq!(orderly_close(&mut channel).await, 0);
    connection
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    let (transactions, status, _) = exec(&fixture, b"show transactions").await;
    assert_eq!(status, Some(0));
    assert!(transactions.contains("pending_confirmation"));
    assert!(transactions.contains("ctrl-d-pending"));
    assert!(!transactions.contains("rolled_back"));
    assert!(!transactions.contains("\"status\": \"committed\""));
    fixture.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_sessions_have_a_deadline() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let connection = fixture.connect().await;
    let closed = tokio::time::timeout(Duration::from_secs(20), connection).await;
    assert!(
        closed.is_ok(),
        "unauthenticated connection outlived its deadline"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn connection_capacity_is_bounded_and_shutdown_drains_stalled_clients() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let mut stalled = Vec::new();
    for _ in 0..32 {
        stalled.push(
            tokio::net::TcpStream::connect(fixture.address)
                .await
                .unwrap(),
        );
    }
    let mut excess = tokio::net::TcpStream::connect(fixture.address)
        .await
        .unwrap();
    use tokio::io::AsyncReadExt;
    let mut output = Vec::new();
    let closed = tokio::time::timeout(WAIT, excess.read_to_end(&mut output))
        .await
        .unwrap();
    assert!(
        closed.is_ok()
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    fixture.shutdown().await;
    drop(stalled);
}

#[tokio::test]
async fn repeated_authentication_failures_cannot_be_followed_by_valid_authentication() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let mut connection = fixture.connect().await;
    for _ in 0..3 {
        if connection
            .authenticate_password("apikey", "incorrect-key")
            .await
            .is_err()
        {
            break;
        }
    }
    let result = tokio::time::timeout(WAIT, connection.authenticate_password("apikey", KEY))
        .await
        .unwrap();
    assert!(result.is_err() || !result.unwrap().success());
    fixture.shutdown().await;
}

async fn edit_candidate(channel: &mut Channel<client::Msg>) {
    assert!(command(channel, "enable").await.ends_with("netcontrol# "));
    assert!(
        command(channel, "configure terminal")
            .await
            .contains("Private candidate")
    );
    for line in [
        "interface lan0 dummy",
        "role lan",
        "no shutdown",
        "ip address 192.0.2.1/24",
        "exit",
    ] {
        let output = command(channel, line).await;
        assert!(!output.contains("% "), "{line}: {output}");
    }
}

#[tokio::test]
async fn candidates_are_private_and_commit_confirm_and_rollback_are_real() {
    let fixture = Fixture::scoped(PERMISSIONS).await;
    let first = fixture.login(KEY).await;
    let second = fixture.login(KEY).await;
    let mut a = shell(&first).await;
    let mut b = shell(&second).await;
    edit_candidate(&mut a).await;
    assert!(
        command(&mut a, "show candidate-config")
            .await
            .contains("192.0.2.1/24")
    );
    assert!(
        !command(&mut b, "show running-config")
            .await
            .contains("lan0")
    );
    command(&mut b, "enable").await;
    command(&mut b, "configure terminal").await;
    assert!(
        !command(&mut b, "show candidate-config")
            .await
            .contains("lan0")
    );
    assert!(
        command(&mut a, "commit check")
            .await
            .contains("Candidate is valid")
    );
    let provisional = command(&mut a, "commit confirmed 30 integration-check").await;
    assert!(
        provisional.contains("Provisional apply only"),
        "{provisional}"
    );
    assert!(
        command(&mut a, "show transactions")
            .await
            .contains("pending")
    );
    // An unrelated session retains its own candidate even while the engine has a pending apply.
    assert!(
        !command(&mut b, "show candidate-config")
            .await
            .contains("lan0")
    );
    let confirmed = command(&mut a, "confirm").await;
    assert!(
        confirmed.contains("confirmed") || confirmed.contains("committed"),
        "{confirmed}"
    );
    assert!(
        command(&mut a, "show running-config")
            .await
            .contains("lan0")
    );
    command(&mut a, "configure terminal").await;
    command(&mut a, "set /firewall/policy \"drop\"").await;
    let provisional = command(&mut a, "commit confirmed 30 rollback-check").await;
    assert!(
        provisional.contains("Provisional apply only"),
        "{provisional}"
    );
    assert!(command(&mut a, "rollback").await.contains("rolled_back"));
    let running = command(&mut a, "show running-config").await;
    assert!(running.contains("lan0"));
    first
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    second
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn disconnect_discards_candidate_but_not_engine_owned_pending_transaction() {
    let fixture = Fixture::scoped(PERMISSIONS).await;
    let first = fixture.login(KEY).await;
    let mut channel = shell(&first).await;
    edit_candidate(&mut channel).await;
    first
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    let second = fixture.login(KEY).await;
    let mut channel = shell(&second).await;
    assert!(
        command(&mut channel, "show candidate-config")
            .await
            .contains("no candidate")
    );
    assert!(
        !command(&mut channel, "show running-config")
            .await
            .contains("lan0")
    );
    edit_candidate(&mut channel).await;
    assert!(
        command(&mut channel, "commit confirmed 30 disconnect-check")
            .await
            .contains("Provisional apply only")
    );
    second
        .disconnect(Disconnect::ByApplication, "test completed", "")
        .await
        .unwrap();
    let (transactions, status, _) = exec(&fixture, b"show transactions").await;
    assert_eq!(status, Some(0));
    assert!(transactions.contains("pending"));
    assert!(!transactions.contains("confirmed"));
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoking_a_managed_key_denies_the_next_command_and_disconnects() {
    let directory = directory();
    let mut store = Store::open(&directory.path().join("identity.json")).unwrap();
    let session = store.setup("admin", "synthetic setup password").unwrap();
    let (key, token) = store.create_key(&session, "ssh-test").unwrap();
    store.complete(&session).unwrap();
    let engine = Engine::open(
        &directory.path().join("state.json"),
        Box::new(Simulator::new()),
    )
    .unwrap();
    let app = App::new(
        Arc::new(Mutex::new(engine)),
        Authentication::Device(Mutex::new(store)),
        false,
    );
    let fixture = Fixture::start(directory, app.clone()).await;
    let connection = fixture.login(&token).await;
    let mut channel = shell(&connection).await;
    assert!(
        command(&mut channel, "show running-config")
            .await
            .contains("Committed running configuration")
    );
    let response = router(app)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/keys/{}", key.id))
                .header("host", "device.test")
                .header("origin", "http://device.test")
                .header("content-type", "application/json")
                .header("cookie", format!("netcontrol_session={session}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    channel.data(&b"show running-config\r\n"[..]).await.unwrap();
    let (output, status) = tokio::time::timeout(WAIT, async {
        let mut output = String::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.push_str(std::str::from_utf8(&data).unwrap()),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        (output, status)
    })
    .await
    .unwrap();
    assert!(output.contains("API key revoked or unavailable"));
    assert!(!output.contains("Committed running configuration"));
    assert_eq!(status, Some(1));
    assert!(
        tokio::time::timeout(WAIT, connection)
            .await
            .unwrap()
            .is_ok()
    );
    fixture.shutdown().await;
}

#[test]
fn host_key_is_persistent_and_invalid_existing_files_are_not_replaced() {
    let directory = directory();
    let path = directory.path().join("host-key");
    let first = load_host_key(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let second = load_host_key(&path).unwrap();
    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(original, fs::read(&path).unwrap());
    fs::write(&path, b"invalid").unwrap();
    assert!(load_host_key(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"invalid");
    fs::write(&path, vec![b'x'; 16385]).unwrap();
    assert!(load_host_key(&path).is_err());
    assert!(load_host_key(directory.path()).is_err());
    let hardlink = directory.path().join("hardlink");
    fs::remove_file(&path).unwrap();
    load_host_key(&path).unwrap();
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(load_host_key(&path).is_err());
    assert!(load_host_key(&hardlink).is_err());
    fs::remove_file(hardlink).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_host_key(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("symlink");
        symlink(&path, &link).unwrap();
        assert!(load_host_key(&link).is_err());
    }
}

#[tokio::test]
async fn shutdown_closes_active_shell_and_stalled_handshake() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let connection = fixture.login(KEY).await;
    let _channel = shell(&connection).await;
    let mut stalled = tokio::net::TcpStream::connect(fixture.address)
        .await
        .unwrap();
    fixture.stop.send(true).unwrap();
    tokio::time::timeout(WAIT, fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(WAIT, connection)
        .await
        .unwrap()
        .unwrap();
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let closed = tokio::time::timeout(WAIT, stalled.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        closed.is_ok()
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    assert!(
        tokio::net::TcpStream::connect(fixture.address)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invalid_host_key_fails_before_accepting() {
    let fixture = Fixture::scoped(&["state.read"]).await;
    let path = fixture.directory.path().join("invalid-key");
    fs::write(&path, b"invalid").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_, stop) = watch::channel(false);
    assert!(
        serve(listener, Path::new(&path), fixture.app.clone(), stop)
            .await
            .is_err()
    );
    fixture.shutdown().await;
}
