use bytes::Bytes;
use http_body_util::Full;
use hyper::header::HeaderMap;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jfp_edge_radar::{
    AmbiguityViolation, CanonicalShield, ForensicReporter, RadarConfig, RadarServer,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_scenario_1_php2shell_cve_2026_exploitation() {
    println!("\n=== [SCENARIO 1: PHP-2-SHELL CVE-2026-109618 EXPLOIT INTERCEPTION] ===");

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr: SocketAddr = upstream_listener.local_addr().unwrap();

    // Mock Upstream PHP-FPM / Web server
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
                                        .header("x-backend", "vulnerable-php-fpm")
                                        .body(Full::new(Bytes::from("PHP execution output")))
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
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        let _ = server.run_with_listener(radar_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Attacker sends PHP-2-Shell exploit payload
    let stream = tokio::net::TcpStream::connect(radar_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let attack_req = Request::builder()
        .uri("/index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input")
        .header("PHP_VALUE", "auto_prepend_file=php://input")
        .body(Full::new(Bytes::from("<?php system('id'); ?>")))
        .unwrap();

    let resp = sender.send_request(attack_req).await.unwrap();

    println!("-> Attack Request: GET /index.php?-d+allow_url_include=on... with PHP_VALUE header");
    println!("<- Response Status: {}", resp.status());
    println!(
        "<- Proof Hash Header: {:?}",
        resp.headers().get("x-jfp-proof-hash")
    );

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp.headers().contains_key("x-jfp-proof-hash"));

    let log_data = std::fs::read_to_string(tmp_proof.path()).unwrap();
    assert!(log_data.contains("PHP_CGI_ARG_INJECTION"));
    assert!(log_data.contains("PHP_ENV_POLLUTION"));
    println!("✅ Verified: Threat was intercepted before upstream. Backend was 100% isolated.");
}

#[tokio::test]
async fn test_scenario_2_multipass_url_encoding_obfuscation() {
    println!("\n=== [SCENARIO 2: MULTI-PASS URL ENCODING EVASION (CANONICAL SHIELD)] ===");

    // Attacker crafts double-encoded `%252d` which decodes to `%2d` then `-`
    // CanonicalShield detects this double URL encoding and disqualifies it immediately
    let path = "/index.php";
    let double_encoded_query = "%252d+allow_url_include=on";
    let result = CanonicalShield::canonicalize_uri(path, Some(double_encoded_query));

    println!("-> Raw obfuscated query: {}", double_encoded_query);
    println!("<- Canonical check result: {:?}", result);

    assert!(matches!(
        result,
        Err(AmbiguityViolation::DoubleUrlEncodingDetected(_))
    ));
    println!("✅ Verified: Fixed-point URL decoding caught nested %252d evasion and blocked it.");
}

#[tokio::test]
async fn test_scenario_3_autonomous_ai_agent_timing_loop_and_recon() {
    println!("\n=== [SCENARIO 3: AUTONOMOUS AI AGENT RECONNAISSANCE & TIMING WINDOW] ===");

    let radar_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let radar_addr = radar_listener.local_addr().unwrap();
    let tmp_proof = tempfile::NamedTempFile::new().unwrap();

    let config = RadarConfig {
        bind_addr: radar_addr,
        proof_log_path: tmp_proof.path().to_path_buf(),
        ..RadarConfig::default()
    };

    let server = RadarServer::new(config);
    tokio::spawn(async move {
        let _ = server.run_with_listener(radar_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_send = |uri: &'static str| {
        let addr = radar_addr;
        async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .uri(uri)
                .body(Full::new(Bytes::new()))
                .unwrap();
            sender.send_request(req).await.unwrap()
        }
    };

    // Step 1: Agent inspects robots.txt
    let _ = client_send("/robots.txt").await;

    // Simulate Agent LLM thinking reflection loop (2.0 seconds delta)
    println!("-> AI Agent thinking / inferencing next prompt step (2.0s pause)...");
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Step 2: Agent attempts structural reconnaissance probing AGENTS.md
    let resp = client_send("/AGENTS.md").await;

    println!("<- Response Status: {}", resp.status());
    println!(
        "<- Defense Header: {:?}",
        resp.headers().get("x-jfp-proof-hash")
    );

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp.headers().contains_key("x-jfp-proof-hash"));

    let log_data = std::fs::read_to_string(tmp_proof.path()).unwrap();
    assert!(log_data.contains("STRUCTURAL_RECON"));
    assert!(log_data.contains("TIMING_WINDOW"));
    println!("✅ Verified: Agent was caught on structural recon + LLM timing window correlation.");
}

#[tokio::test]
async fn test_scenario_4_http_request_smuggling_disqualification() {
    println!("\n=== [SCENARIO 4: HTTP PROTOCOL SMUGGLING RFC 7230 §3.3.3 DISQUALIFICATION] ===");

    // Construct HeaderMap with conflicting Content-Length and Transfer-Encoding headers
    let mut headers = HeaderMap::new();
    headers.insert("content-length", "42".parse().unwrap());
    headers.insert("transfer-encoding", "chunked".parse().unwrap());

    let check_result = CanonicalShield::inspect_headers(&headers);
    println!("-> Headers contain both Content-Length: 42 and Transfer-Encoding: chunked");
    println!("<- Smuggling shield check result: {:?}", check_result);

    assert_eq!(
        check_result,
        Err(AmbiguityViolation::RequestSmugglingBothLengthAndEncoding)
    );
    println!("✅ Verified: Protocol smuggling attack immediately disqualified with zero downstream ambiguity.");
}

#[tokio::test]
async fn test_scenario_5_tamper_evident_proof_chain_integrity() {
    println!("\n=== [SCENARIO 5: CRYPTOGRAPHIC PROOF CHAIN TAMPER-EVIDENCE AUDIT] ===");

    let tmp_proof = tempfile::NamedTempFile::new().unwrap();
    let logger = jfp_edge_radar::ProofLogger::new(
        PathBuf::from(tmp_proof.path()),
        None,
        Some(10 * 1024 * 1024),
    );

    let details1 = serde_json::json!({
        "method": "POST",
        "path": "/upload.php",
        "delta_ms": 2500,
        "indicators": ["PHP_CGI_ARG_INJECTION: detected '-d'"]
    });
    let details2 = serde_json::json!({
        "method": "GET",
        "path": "/admin.php",
        "delta_ms": 3100,
        "indicators": ["PHP_CGI_ARG_INJECTION: detected '-d'"]
    });
    let details3 = serde_json::json!({
        "method": "GET",
        "path": "/shell.php",
        "delta_ms": 4200,
        "indicators": ["PHP_CGI_ARG_INJECTION: detected '-d'"]
    });

    let rec1 = logger
        .log_event("ASA_ATTACK_BLOCKED", "203.0.113.42", details1)
        .unwrap();
    let rec2 = logger
        .log_event("ASA_ATTACK_BLOCKED", "203.0.113.42", details2)
        .unwrap();
    let rec3 = logger
        .log_event("ASA_ATTACK_BLOCKED", "203.0.113.42", details3)
        .unwrap();

    println!("-> Chained block 0 hash: {}", rec1.entry_hash);
    println!("-> Chained block 1 hash: {}", rec2.entry_hash);
    println!("-> Chained block 2 hash: {}", rec3.entry_hash);

    // Verify legitimate chain with ForensicReporter
    let stats = ForensicReporter::analyze_log(tmp_proof.path()).unwrap();
    assert_eq!(stats.total_records, 3);
    assert_eq!(stats.blocked_attacks, 3);
    assert!(stats.chain_verified);
    println!("✅ Verified: Complete 3-block cryptographic chain is 100% valid.");

    // Now TAMPER with entry 1 in the file
    let content = std::fs::read_to_string(tmp_proof.path()).unwrap();
    let tampered_content = content.replace("/admin.php", "/legit.php");
    std::fs::write(tmp_proof.path(), tampered_content).unwrap();

    // Re-audit the tampered log
    let tampered_stats = ForensicReporter::analyze_log(tmp_proof.path()).unwrap();
    println!(
        "<- Tampered chain verification status: chain_verified = {}, broken_at = {:?}",
        tampered_stats.chain_verified, tampered_stats.broken_chain_at
    );
    assert!(!tampered_stats.chain_verified);
    assert_eq!(tampered_stats.broken_chain_at, Some(2));
    println!("✅ Verified: Tampering of a single byte breaks downstream SHA-256 links and pinpointed record #2.");
}
