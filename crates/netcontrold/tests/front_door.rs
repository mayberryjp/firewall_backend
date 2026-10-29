#[cfg(test)]
fn test_revision(index: u32) -> netcontrol_core::Version {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}.{:02}.{:02}.{}",
        now.year(),
        now.month() as u8,
        now.day(),
        index + 1
    )
    .parse()
    .unwrap()
}

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use netcontrol_core::{Engine, Simulator};
use netcontrold::{
    http::{App, Authentication, router},
    identity::{Store, secret},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

struct Fixture {
    path: PathBuf,
    router: axum::Router,
}
impl Fixture {
    fn new(tls: bool) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".test-data")
            .join(secret("").unwrap());
        fs::create_dir_all(&path).unwrap();
        let store = Store::open(&path.join("identity.json")).unwrap();
        let engine = Engine::open(&path.join("state.json"), Box::new(Simulator::new())).unwrap();
        let router = router(App::new(
            Arc::new(Mutex::new(engine)),
            Authentication::Device(Mutex::new(store)),
            tls,
        ));
        Self { path, router }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &str,
        cookie: &str,
        bearer: &str,
        origin: &str,
    ) -> (u16, axum::http::HeaderMap, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "device.test")
            .header("origin", origin)
            .header("content-type", "application/json");
        if !cookie.is_empty() {
            builder = builder.header("cookie", cookie);
        }
        if !bearer.is_empty() {
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let response = self
            .router
            .clone()
            .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, json)
    }
    async fn setup(&self, origin: &str) -> String {
        let (status, headers, _) = self
            .request(
                "POST",
                "/auth/setup",
                r#"{"username":"admin","password":"a unique test password"}"#,
                "",
                "",
                origin,
            )
            .await;
        assert_eq!(status, 200);
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.router = axum::Router::new();
        fs::remove_dir_all(&self.path).unwrap();
    }
}

#[tokio::test]
async fn platform_status_is_authenticated_nonblocking_and_included_with_configuration() {
    use netcontrold::http::Credential;
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(Mutex::new(
        Engine::open(
            &directory.path().join("state.json"),
            Box::new(Simulator::new()),
        )
        .unwrap(),
    ));
    let app = App::new(
        engine.clone(),
        Authentication::Scoped(vec![
            Credential {
                name: "reader".into(),
                token_sha256: netcontrold::identity::digest("reader"),
                permissions: vec!["state.read".into()],
            },
            Credential {
                name: "writer".into(),
                token_sha256: netcontrold::identity::digest("writer"),
                permissions: vec!["transactions.write".into()],
            },
        ]),
        false,
    );
    app.health.observe(
        Some(&json!({"appliance_services":[{"name":"ntp","state":"error","retrying":true}]})),
        &[],
        false,
    );
    let snapshot = app.health.snapshot();
    let service = router(app);
    for (method, path, body, token, expected) in [
        ("GET", "/api/v1/platform/status", "", "bad", 401),
        ("GET", "/api/v1/platform/status", "", "writer", 403),
        ("POST", "/api/v1/platform/status", "", "reader", 405),
        ("GET", "/api/v1/platform/status?extra=1", "", "reader", 400),
        ("GET", "/api/v1/platform/status", "{}", "reader", 400),
        ("GET", "/api/v1/platform/status", "", "reader", 200),
        ("GET", "/api/v1/state", "", "reader", 200),
        ("GET", "/api/v1/runtime", "", "reader", 200),
    ] {
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{method} {path}");
        if expected == 200 {
            assert_eq!(response.headers()["cache-control"], "no-store");
            let value: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(value["process_health"], snapshot["process_health"]);
            assert_eq!(value["active_alerts"], snapshot["active_alerts"]);
            if path == "/api/v1/state" {
                assert!(value["desired"].get("active_alerts").is_none());
                assert_eq!(value["revision"], serde_json::json!(test_revision(0)));
            }
        }
    }
    let (held_sender, held_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _guard = engine.lock().unwrap();
        held_sender.send(()).unwrap();
        release_receiver.recv().unwrap();
    });
    held_receiver.recv().unwrap();
    let request = service.oneshot(
        Request::builder()
            .uri("/api/v1/platform/status")
            .header("authorization", "Bearer reader")
            .body(Body::empty())
            .unwrap(),
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), request).await;
    release_sender.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(response.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn mdns_http_contract_authentication_permissions_queries_and_repair() {
    use netcontrold::http::Credential;
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.json"),
        Box::new(Simulator::new()),
    )
    .unwrap();
    let app = router(App::new(
        Arc::new(Mutex::new(engine)),
        Authentication::Scoped(vec![
            Credential {
                name: "reader".into(),
                token_sha256: netcontrold::identity::digest("reader"),
                permissions: vec!["state.read".into()],
            },
            Credential {
                name: "operator".into(),
                token_sha256: netcontrold::identity::digest("operator"),
                permissions: netcontrol_core::PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).into())
                    .collect(),
            },
            Credential {
                name: "writer".into(),
                token_sha256: netcontrold::identity::digest("writer"),
                permissions: vec!["mdns.write".into()],
            },
        ]),
        false,
    ));
    for (method, path, token, body, expected) in [
        ("GET", "/api/v1/services/mdns", "", "", 401),
        ("GET", "/api/v1/services/mdns/status", "writer", "", 403),
        ("GET", "/api/v1/services/mdns?unused=1", "reader", "", 400),
        (
            "GET",
            "/api/v1/services/mdns/status?unused=1",
            "reader",
            "",
            400,
        ),
        ("POST", "/api/v1/services/mdns/reconcile", "reader", "", 403),
        (
            "POST",
            "/api/v1/services/mdns/reconcile?unused=1",
            "operator",
            "",
            400,
        ),
        (
            "POST",
            "/api/v1/services/mdns/reconcile",
            "operator",
            "{}",
            400,
        ),
        ("GET", "/api/v1/services/mdns", "reader", "", 200),
        ("GET", "/api/v1/services/mdns/status", "reader", "", 200),
        (
            "POST",
            "/api/v1/services/mdns/reconcile",
            "operator",
            "",
            200,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("origin", "http://dashboard.test")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{method} {path}");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        if expected != 200 {
            assert!(value["error"].is_string(), "{value}");
        } else if method == "GET" && path.ends_with("/status") {
            let rows = value["instances"].as_array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["name"], "mdns");
            assert_eq!(rows[0]["state"], "disabled");
            assert_eq!(rows[0]["received_packets"], "0");
            assert!(rows[0]["receive_drops"].is_null());
            assert_eq!(rows[0]["statistics_complete"], false);
            assert_eq!(value["error"], "");
        } else if method == "GET" {
            let config: netcontrol_core::MDNSConfig = serde_json::from_value(value).unwrap();
            assert_eq!(config, netcontrol_core::MDNSConfig::default());
        } else {
            assert!(
                value["appliance_services"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["name"] == "mdns")
            );
        }
    }
}

#[tokio::test]
async fn host_health_http_authentication_permissions_and_cors() {
    use netcontrold::http::Credential;
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.json"),
        Box::new(Simulator::new()),
    )
    .unwrap();
    let app = router(App::new(
        Arc::new(Mutex::new(engine)),
        Authentication::Scoped(vec![
            Credential {
                name: "reader".into(),
                token_sha256: netcontrold::identity::digest("reader"),
                permissions: vec!["state.read".into()],
            },
            Credential {
                name: "writer".into(),
                token_sha256: netcontrold::identity::digest("writer"),
                permissions: vec!["interfaces.write".into()],
            },
        ]),
        false,
    ));
    for (method, path, token, expected) in [
        ("GET", "/api/v1/statistics/host", "", 401),
        ("GET", "/api/v1/statistics/host", "writer", 403),
        ("GET", "/api/v1/statistics/host?unused=1", "reader", 400),
        ("POST", "/api/v1/statistics/host", "reader", 405),
        ("GET", "/api/v1/statistics/host", "reader", 200),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("origin", "http://dashboard.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        if expected == 200 {
            assert_eq!(body["schema"], "netcontrol-host-health/v1");
            assert_eq!(body["sample"]["status"], "simulated");
        } else {
            assert!(body["error"].is_string());
        }
    }
}

#[tokio::test]
async fn host_system_endpoints_authentication_permissions_and_simulated_catalog() {
    use netcontrold::{
        host_system::{Manager, Mode},
        http::Credential,
    };
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(Mutex::new(
        Engine::open(
            &directory.path().join("state.json"),
            Box::new(Simulator::new()),
        )
        .unwrap(),
    ));
    let credentials = || {
        Authentication::Scoped(vec![
            Credential {
                name: "reader".into(),
                token_sha256: netcontrold::identity::digest("reader"),
                permissions: vec!["state.read".into()],
            },
            Credential {
                name: "writer".into(),
                token_sha256: netcontrold::identity::digest("writer"),
                permissions: vec!["system.write".into()],
            },
        ])
    };
    let detached = router(App::new(engine.clone(), credentials(), false));
    let mut app = App::new(engine.clone(), credentials(), false);
    App::attach_system(&mut app, Manager::open(engine, Mode::Simulated).unwrap()).unwrap();
    let attached = router(app);
    let call = |router: axum::Router,
                method: &'static str,
                path: &'static str,
                token: &'static str| async move {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    for path in ["/api/v1/system/status", "/api/v1/system/timezones"] {
        assert_eq!(call(attached.clone(), "GET", path, "").await.0, 401);
        assert_eq!(call(attached.clone(), "GET", path, "writer").await.0, 403);
        assert_eq!(call(attached.clone(), "POST", path, "reader").await.0, 405);
        assert_eq!(call(detached.clone(), "GET", path, "reader").await.0, 503);
    }
    assert_eq!(
        call(
            attached.clone(),
            "GET",
            "/api/v1/system/status?unused=1",
            "reader"
        )
        .await
        .0,
        400
    );
    let (status, body) = call(attached.clone(), "GET", "/api/v1/system/status", "reader").await;
    assert_eq!(status, 200);
    assert_eq!(body["hostname"]["state"], "unmanaged");
    assert_eq!(body["timezone"]["configured"], "");
    assert!(body["last_applied_at_unix"].is_null());
    let (status, body) = call(attached, "GET", "/api/v1/system/timezones", "reader").await;
    assert_eq!(status, 200);
    assert!(
        body["timezones"]
            .as_array()
            .unwrap()
            .contains(&json!("UTC"))
    );
}

#[tokio::test]
async fn software_upgrade_requires_permission_and_validates_versions_when_disabled() {
    use netcontrold::http::Credential;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".test-data")
        .join(secret("").unwrap());
    fs::create_dir_all(&path).unwrap();
    let engine = Engine::open(&path.join("state.json"), Box::new(Simulator::new())).unwrap();
    let fixture = Fixture {
        path,
        router: router(App::new(
            Arc::new(Mutex::new(engine)),
            Authentication::Scoped(vec![
                Credential {
                    name: "reader".into(),
                    token_sha256: netcontrold::identity::digest("reader"),
                    permissions: vec!["state.read".into()],
                },
                Credential {
                    name: "upgrader".into(),
                    token_sha256: netcontrold::identity::digest("upgrader"),
                    permissions: vec!["system.upgrade".into()],
                },
            ]),
            false,
        )),
    };
    let endpoint = "/api/v1/system/upgrade";
    assert_eq!(
        fixture
            .request("GET", endpoint, "", "", "", "allowed")
            .await
            .0,
        401
    );
    let response = fixture.request("GET", endpoint, "", "", "reader", "").await;
    assert_eq!(response.0, 200);
    assert_eq!(response.2["enabled"], false);
    assert!(response.2["last_successful_version"].is_null());
    let latest = fixture
        .request("GET", "/api/v1/revisions/latest", "", "", "reader", "")
        .await;
    assert_eq!(latest.0, 200);
    assert_eq!(latest.2["revision"], serde_json::json!(test_revision(0)));
    assert_eq!(
        latest.2["config"]["software"],
        serde_json::json!(netcontrol_core::SoftwareMetadata::default())
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                endpoint,
                r#"{"version":"2026.10.29.2"}"#,
                "",
                "reader",
                ""
            )
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request("GET", endpoint, "", "", "upgrader", "")
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request("PUT", endpoint, "", "", "reader", "")
            .await
            .0,
        405
    );
    for body in [
        "",
        "{}",
        r#"{"version":"latest"}"#,
        r#"{"version":"1.2.3"}"#,
        r#"{"version":"2026.02.29.1"}"#,
        r#"{"version":"2026.10.29.0"}"#,
        r#"{"version":"../1.2.3"}"#,
        r#"{"version":"v1.2.3"}"#,
        r#"{"version":"1.2.3","url":"https://example.invalid"}"#,
        r#"{"version":"1.2.3","version":"1.2.4"}"#,
    ] {
        assert_eq!(
            fixture
                .request("POST", endpoint, body, "", "upgrader", "")
                .await
                .0,
            400
        );
    }
    assert_eq!(
        fixture
            .request(
                "POST",
                endpoint,
                r#"{"version":"2026.10.29.2"}"#,
                "",
                "upgrader",
                ""
            )
            .await
            .0,
        503
    );
    assert_eq!(
        fixture
            .request(
                "GET",
                "/api/v1/system/upgrade?limit=1",
                "",
                "",
                "reader",
                ""
            )
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn complete_onboarding_revocation_logout_and_login() {
    let f = Fixture::new(false);
    let origin = "http://device.test";
    let (_, _, status) = f.request("GET", "/auth/status", "", "", "", origin).await;
    assert_eq!(
        status,
        json!({"stage":"account","authenticated":false,"configured":false,"username":""})
    );
    let cookie = f.setup(origin).await;
    assert_eq!(
        f.request(
            "POST",
            "/auth/setup",
            r#"{"username":"other","password":"another long password"}"#,
            "",
            "",
            origin
        )
        .await
        .0,
        409
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/complete",
            r#"{"saved":true}"#,
            &cookie,
            "",
            origin
        )
        .await
        .0,
        409
    );
    let (status, _, key) = f
        .request(
            "POST",
            "/auth/keys",
            r#"{"name":"dashboard"}"#,
            &cookie,
            "",
            origin,
        )
        .await;
    assert_eq!(status, 201);
    let token = key["token"].as_str().unwrap();
    assert_eq!(token.len(), 67);
    assert_eq!(
        f.request("GET", "/api/v1/state", "", "", token, origin)
            .await
            .0,
        401
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/complete",
            r#"{"saved":false}"#,
            &cookie,
            "",
            origin
        )
        .await
        .0,
        400
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/complete",
            r#"{"saved":true}"#,
            &cookie,
            "",
            origin
        )
        .await
        .0,
        200
    );
    let (status, headers, _) = f
        .request("GET", "/api/v1/state", "", "", token, origin)
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(
        f.request("GET", "/api/v1/state", "", &cookie, "", origin)
            .await
            .0,
        401
    );
    assert_eq!(
        f.request("GET", "/auth/keys", "", "", token, origin)
            .await
            .0,
        401
    );
    let (_, headers, list) = f
        .request("GET", "/auth/keys", "", &cookie, "", origin)
        .await;
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert!(!list.to_string().contains(token));
    assert!(!list.to_string().contains("hash"));
    assert_eq!(list["keys"][0]["masked"].as_str().unwrap().len(), 10);
    assert_eq!(
        f.request(
            "POST",
            "/auth/keys",
            r#"{"name":"dashboard"}"#,
            &cookie,
            "",
            origin
        )
        .await
        .0,
        400
    );
    let path = format!("/auth/keys/{}", key["key"]["id"].as_str().unwrap());
    assert_eq!(
        f.request("DELETE", &path, "", &cookie, "", origin).await.0,
        200
    );
    assert_eq!(
        f.request("GET", "/api/v1/state", "", "", token, origin)
            .await
            .0,
        401
    );
    assert_eq!(
        f.request("DELETE", &path, "", &cookie, "", origin).await.0,
        404
    );
    assert_eq!(
        f.request("POST", "/auth/logout", "{}", &cookie, "", origin)
            .await
            .0,
        200
    );
    assert_eq!(
        f.request("GET", "/auth/keys", "", &cookie, "", origin)
            .await
            .0,
        401
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"wrong"}"#,
            "",
            "",
            origin
        )
        .await
        .0,
        401
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"a unique test password"}"#,
            "",
            "",
            origin
        )
        .await
        .0,
        200
    );
    let disk = fs::read_to_string(f.path.join("identity.json")).unwrap();
    assert!(!disk.contains(token));
    assert!(!disk.contains("a unique test password"));
    assert!(!disk.contains(cookie.split('=').nth(1).unwrap()));
    assert!(disk.contains("$argon2id$"));
}

#[tokio::test]
async fn same_origin_json_cookies_limits_and_security_headers() {
    for tls in [false, true] {
        let f = Fixture::new(tls);
        let origin = if tls {
            "https://device.test"
        } else {
            "http://device.test"
        };
        for bad in [
            "",
            "https://evil.test",
            "http://device.test.evil.test",
            if tls {
                "http://device.test"
            } else {
                "https://device.test"
            },
        ] {
            assert_eq!(
                f.request("POST", "/auth/setup", "{}", "", "", bad).await.0,
                403
            );
        }
        for body in [
            r#"{"unexpected":true}"#.to_owned(),
            "{} {}".to_owned(),
            "x".repeat(4097),
        ] {
            let (status, _, error) = f
                .request("POST", "/auth/setup", &body, "", "", origin)
                .await;
            assert_eq!(status, 400);
            assert!(error.get("error").unwrap().is_string());
            assert!(error.get("transaction").is_none());
        }
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/setup")
                    .header("host", "device.test")
                    .header("origin", origin)
                    .header("content-type", "text/plain")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let payload = r#"{"username":"admin","password":"a unique test password"}"#;
        let boundary_body = format!("{payload}{}", " ".repeat(4096 - payload.len()));
        let (status, headers, _) = f
            .request("POST", "/auth/setup", &boundary_body, "", "", origin)
            .await;
        assert_eq!(status, 200);
        let cookie = headers["set-cookie"].to_str().unwrap();
        for expected in ["HttpOnly", "SameSite=Strict", "Path=/auth/", "Max-Age=1800"] {
            assert!(cookie.contains(expected));
        }
        assert_eq!(cookie.contains("; Secure"), tls);
        assert_eq!(headers.contains_key("strict-transport-security"), tls);
        for asset in ["/", "/app.js", "/style.css"] {
            let (status, headers, _) = f.request("GET", asset, "", "", "", origin).await;
            assert_eq!(status, 200);
            assert!(headers.contains_key("content-security-policy"));
            assert_eq!(headers["cache-control"], "no-store");
        }
        assert_eq!(f.request("POST", "/", "", "", "", origin).await.0, 405);
    }
}

#[tokio::test]
async fn login_rate_limit_and_api_error_shape() {
    let f = Fixture::new(false);
    for _ in 0..10 {
        assert_eq!(
            f.request(
                "POST",
                "/auth/login",
                r#"{"username":"unknown","password":"incorrect"}"#,
                "",
                "",
                "http://device.test"
            )
            .await
            .0,
            401
        );
    }
    let (status, headers, _) = f
        .request("POST", "/auth/login", "{}", "", "", "http://device.test")
        .await;
    assert_eq!(status, 429);
    assert_eq!(headers["retry-after"], "60");
    let (status, headers, body) = f
        .request("GET", "/api/v1/state", "", "", "", "https://foreign.test")
        .await;
    assert_eq!(status, 401);
    assert_eq!(headers["www-authenticate"], "Bearer");
    assert_eq!(
        headers["access-control-expose-headers"],
        "Location, WWW-Authenticate, Retry-After"
    );
    assert_eq!(
        body,
        json!({"error":"valid API key required","transaction":null})
    );
}

#[tokio::test]
async fn cors_preflight_is_unauthenticated_and_strictly_scoped() {
    let f = Fixture::new(false);
    for (method, requested_headers, status) in [
        ("GET", "Authorization, Content-Type", 204),
        ("POST", "authorization,content-type", 204),
        ("DELETE", "Authorization", 204),
        ("PUT", "Authorization", 405),
        ("POST", "X-Other", 400),
    ] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/state")
                    .header("origin", "https://other.test")
                    .header("access-control-request-method", method)
                    .header("access-control-request-headers", requested_headers)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(
            response.headers()["access-control-allow-methods"],
            "GET, POST, DELETE"
        );
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
    }

    for path in ["/auth/status", "/", "/api/other"] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(path)
                    .header("origin", "https://other.test")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
}

#[tokio::test]
async fn scoped_credentials_permissions_and_api_body_limit() {
    use netcontrold::{http::load_credentials, identity::digest};
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".test-data")
        .join(secret("").unwrap());
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth.json");
    let token = secret("nc_").unwrap();
    let input = json!({"schema":1,"credentials":[{"name":"read-only","token_sha256":digest(&token),"permissions":["state.read"]}]});
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let credentials = load_credentials(&path).unwrap();
    let engine = Engine::open(&dir.join("state.json"), Box::new(Simulator::new())).unwrap();
    let app = router(App::new(
        Arc::new(Mutex::new(engine)),
        Authentication::Scoped(credentials),
        false,
    ));
    for (method, path, body, status) in [
        ("GET", "/api/v1/state", String::new(), 200),
        ("GET", "/api/v1/interfaces/discovered", String::new(), 200),
        (
            "GET",
            "/api/v1/interfaces/discovered?unexpected=1",
            String::new(),
            400,
        ),
        (
            "POST",
            "/api/v1/interfaces/discovered",
            "{}".to_owned(),
            405,
        ),
        ("GET", "/api/v1/state", "x".repeat(1 << 20), 200),
        ("GET", "/api/v1/state", "x".repeat((1 << 20) + 1), 400),
        ("POST", "/api/v1/transactions", "{}".to_owned(), 403),
        (
            "POST",
            "/api/v1/transactions",
            "x".repeat((1 << 20) + 1),
            400,
        ),
        ("GET", "/auth/status", String::new(), 404),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/v1/state")
                .header("origin", "https://other.test")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    drop(app);
    let invalid: Vec<Value> = vec![
        json!([]),
        json!({"schema":2,"credentials":input["credentials"]}),
        json!({"schema":1,"credentials":[]}),
        json!({"schema":1,"credentials":[input["credentials"][0],input["credentials"][0]]}),
        json!({"schema":1,"credentials":[{"name":"invalid","token_sha256":digest(&token),"permissions":["unknown"]}]}),
        json!({"schema":1,"credentials":[{"name":"invalid","token_sha256":digest(&token),"permissions":["state.read","state.read"]}]}),
    ];
    for value in invalid {
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_credentials(&path).is_err());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn native_tls_listener_handshake_and_secure_cookie() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let certificate = rcgen::generate_simple_self_signed(vec!["device.test".to_owned()]).unwrap();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.cert.pem().into_bytes(),
        certificate.key_pair.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let f = Fixture::new(true);
    let service = f.router.clone().into_make_service();
    let handle = axum_server::Handle::<std::net::SocketAddr>::new();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), config)
            .handle(server_handle)
            .serve(service)
            .await
            .unwrap();
    });
    let address = tokio::time::timeout(std::time::Duration::from_secs(5), handle.listening())
        .await
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("device.test").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let body = r#"{"username":"admin","password":"a unique test password"}"#;
    stream.write_all(format!("POST /auth/setup HTTP/1.1\r\nHost: device.test\r\nOrigin: https://device.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    handle.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
    server.await.unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("HttpOnly; SameSite=Strict; Secure"));
}

#[tokio::test]
async fn concurrent_account_claims_have_one_winner() {
    let f = Fixture::new(false);
    let body = r#"{"username":"admin","password":"a unique test password"}"#;
    let (first, second) = tokio::join!(
        f.request("POST", "/auth/setup", body, "", "", "http://device.test"),
        f.request("POST", "/auth/setup", body, "", "", "http://device.test"),
    );
    let mut codes = [first.0, second.0];
    codes.sort();
    assert_eq!(codes, [200, 409]);
}

#[tokio::test]
async fn persistence_failures_are_sanitized_and_fail_closed() {
    let f = Fixture::new(false);
    let origin = "http://device.test";
    let cookie = f.setup(origin).await;
    let (_, _, created) = f
        .request(
            "POST",
            "/auth/keys",
            r#"{"name":"saved"}"#,
            &cookie,
            "",
            origin,
        )
        .await;
    let key = created["token"].as_str().unwrap();
    assert_eq!(
        f.request(
            "POST",
            "/auth/complete",
            r#"{"saved":true}"#,
            &cookie,
            "",
            origin
        )
        .await
        .0,
        200
    );
    let path = f.path.join("identity.json");
    let saved = f.path.join("saved-identity.json");
    fs::rename(&path, &saved).unwrap();
    fs::create_dir(&path).unwrap();
    let (status, _, error) = f
        .request(
            "POST",
            "/auth/keys",
            r#"{"name":"unsaved"}"#,
            &cookie,
            "",
            origin,
        )
        .await;
    assert_eq!(status, 500);
    assert_eq!(error, json!({"error":"credential service unavailable"}));
    assert_eq!(
        f.request("GET", "/auth/status", "", &cookie, "", origin)
            .await
            .0,
        500
    );
    let (status, headers, error) = f.request("GET", "/api/v1/state", "", "", key, origin).await;
    assert_eq!(status, 503);
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(
        error,
        json!({"error":"credential store unavailable","transaction":null})
    );
    fs::remove_dir(&path).unwrap();
    fs::rename(saved, path).unwrap();
}
