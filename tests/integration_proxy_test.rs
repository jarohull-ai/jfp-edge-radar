use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jfp_edge_radar::{RadarConfig, RadarServer};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_radar_reverse_proxy_and_attack_interception() {
    // 1. Launch a mock upstream backend server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr: SocketAddr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = upstream_listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(|_req: Request<hyper::body::Incoming>| async {
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("x-backend-id", "real-upstream-backend")
                                        .body(Full::new(Bytes::from(r#"{"data":"upstream_ok"}"#)))
                                        .unwrap(),
                                )
                            }),
                        )
                        .await;
                });
            }
        }
    });

    // 2. Launch JFP Edge Radar in front of the upstream
    let radar_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let radar_addr = radar_listener.local_addr().unwrap();

    let tmp_proof = tempfile::NamedTempFile::new().unwrap();
    let config = RadarConfig {
        bind_addr: radar_addr,
        upstream_addr: Some(upstream_addr),
        proof_log_path: tmp_proof.path().to_path_buf(),
        max_session_idle_secs: 60,
        enable_honey_tokens: true,
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        if let Err(e) = server.run_with_listener(radar_listener).await {
            eprintln!("RadarServer error: {:?}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Helper client function with connection retry
    let client_send = |path: &str, headers: &[(&str, &str)]| {
        let addr = radar_addr;
        let p = path.to_string();
        let h: Vec<(String, String)> = headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        async move {
            let mut stream = None;
            for _ in 0..20 {
                if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
                    stream = Some(s);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let s = stream.expect("Failed to connect to radar gateway");
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s)).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut req = Request::builder().uri(p);
            for (k, v) in h {
                req = req.header(k, v);
            }
            let req = req.body(Full::new(Bytes::new())).unwrap();
            sender.send_request(req).await.unwrap()
        }
    };

    // 3. Test clean request -> should be forwarded to upstream
    let clean_resp = client_send("/api/products", &[]).await;
    assert_eq!(clean_resp.status(), StatusCode::OK);
    assert_eq!(
        clean_resp.headers().get("x-backend-id").unwrap(),
        "real-upstream-backend"
    );

    // 4. Test malicious PHP-2-Shell / PHP-CGI injection request -> MUST be intercepted by Radar with 403
    let attack_resp = client_send("/index.php?-d+allow_url_include=on", &[("PHP_VALUE", "auto_prepend_file=php://input")]).await;
    assert_eq!(attack_resp.status(), StatusCode::FORBIDDEN);
    assert!(attack_resp.headers().contains_key("x-jfp-proof-hash"));

    // 5. Verify proof log written to disk
    let log_content = std::fs::read_to_string(tmp_proof.path()).unwrap();
    assert!(log_content.contains("ASA_ATTACK_BLOCKED"));
    assert!(log_content.contains("PHP_CGI_ARG_INJECTION"));
}


#[tokio::test]
async fn test_radar_dry_run_audit_mode() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr: SocketAddr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = upstream_listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(|_req: Request<hyper::body::Incoming>| async {
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from(r#"{"status":"backend_allowed"}"#)))
                                        .unwrap(),
                                )
                            }),
                        )
                        .await;
                });
            }
        }
    });

    let radar_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let radar_addr = radar_listener.local_addr().unwrap();

    let tmp_proof = tempfile::NamedTempFile::new().unwrap();
    let config = RadarConfig {
        bind_addr: radar_addr,
        upstream_addr: Some(upstream_addr),
        proof_log_path: tmp_proof.path().to_path_buf(),
        dry_run: true, // Audit only
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        let _ = server.run_with_listener(radar_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send attack payload - in dry-run mode, it should NOT return 403, but forward to backend and log audit
    let stream = tokio::net::TcpStream::connect(radar_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("/index.php?-d+allow_url_include=on")
        .header("PHP_VALUE", "auto_prepend_file=php://input")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-jfp-dry-run-hash"));

    let log_content = std::fs::read_to_string(tmp_proof.path()).unwrap();
    assert!(log_content.contains("ASA_ATTACK_SIMULATED_DRY_RUN"));
}


#[tokio::test]
async fn test_radar_slow_drip_tarpit() {
    let radar_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let radar_addr = radar_listener.local_addr().unwrap();

    let tmp_proof = tempfile::NamedTempFile::new().unwrap();
    let config = RadarConfig {
        bind_addr: radar_addr,
        proof_log_path: tmp_proof.path().to_path_buf(),
        tarpit_drip_interval_ms: 50, // 50ms for rapid test execution
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        let _ = server.run_with_listener(radar_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and send a request that triggers Tarpit (e.g. PHP probe scoring ~0.35)
    let stream = tokio::net::TcpStream::connect(radar_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("/test.php")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-jfp-defense").unwrap(),
        "slow-drip-tarpit"
    );

    // Read a few bytes from the stream to verify chunked slow drip
    let mut body = resp.into_body();
    let frame = body.frame().await.unwrap().unwrap();
    assert!(frame.is_data());
}


#[tokio::test]
async fn test_radar_tarpit_concurrency_cap_fallback() {
    let radar_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let radar_addr = radar_listener.local_addr().unwrap();

    let tmp_proof = tempfile::NamedTempFile::new().unwrap();
    let config = RadarConfig {
        bind_addr: radar_addr,
        proof_log_path: tmp_proof.path().to_path_buf(),
        tarpit_drip_interval_ms: 1000,
        max_tarpit_concurrency: 1, // Max 1 active tarpit!
        trusted_proxies: vec!["127.0.0.1/32".to_string()],
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        let _ = server.run_with_listener(radar_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1st request from IP A -> acquires the 1 available Tarpit slot
    let stream1 = tokio::net::TcpStream::connect(radar_addr).await.unwrap();
    let (mut sender1, conn1) = hyper::client::conn::http1::handshake(TokioIo::new(stream1)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn1.await;
    });

    let req1 = Request::builder()
        .uri("/test.php")
        .header("x-forwarded-for", "198.51.100.1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp1 = sender1.send_request(req1).await.unwrap();
    assert_eq!(resp1.headers().get("x-jfp-defense").unwrap(), "slow-drip-tarpit");

    // 2nd request from IP B while 1st is still active -> must hit concurrency cap and fallback immediately to 403 Forbidden!
    let stream2 = tokio::net::TcpStream::connect(radar_addr).await.unwrap();
    let (mut sender2, conn2) = hyper::client::conn::http1::handshake(TokioIo::new(stream2)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });

    let req2 = Request::builder()
        .uri("/test.php")
        .header("x-forwarded-for", "198.51.100.2")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp2 = sender2.send_request(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
}
