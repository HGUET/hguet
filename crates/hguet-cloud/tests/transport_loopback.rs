//! The strict transport against real `openssl s_server` peers on loopback (OpenSSL >= 3.5, ML-DSA-87 certificate).
//! Explicitly ignored in default runs; mandatory with --ignored in PQ CI. No external host is contacted.

use hguet_cloud::transport::{exchange, TlsProfile};
use hguet_cloud::wire::{encode_frame, envelope_with, v1};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn make_identity(dir: &Path, name: &str) -> Option<(PathBuf, PathBuf)> {
    let key = dir.join(format!("{name}-key.pem"));
    let cert = dir.join(format!("{name}-cert.pem"));
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ML-DSA-87", "-out"])
        .arg(&key)
        .output();
    match generated {
        Ok(output) if output.status.success() => {}
        _ => panic!("ML-DSA-87 is required but unavailable"),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let status = Command::new("openssl")
        .args(["req", "-new", "-x509", "-key"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-days",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    Some((key, cert))
}

/// One-shot TLS peer that, once connected, sends `response` and then exits.
fn serve(port: u16, key: &Path, cert: &Path, groups: &str, response: &[u8]) -> Child {
    let mut child = Command::new("openssl")
        .args(["s_server", "-accept"])
        .arg(format!("127.0.0.1:{port}"))
        .arg("-cert")
        .arg(cert)
        .arg("-key")
        .arg(key)
        .args([
            "-tls1_3",
            "-groups",
            groups,
            "-ciphersuites",
            "TLS_AES_256_GCM_SHA384",
            "-naccept",
            "1",
            "-quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(response).unwrap();
    std::thread::sleep(Duration::from_millis(400)); // let the listener come up
    child
}

fn profile(host: &str, port: u16, ca: &Path) -> TlsProfile {
    TlsProfile {
        host: host.into(),
        port,
        ca_file: ca.to_path_buf(),
        openssl: "openssl".into(),
        timeout: Duration::from_secs(8),
    }
}

fn hello() -> v1::Envelope {
    envelope_with(
        [3; 16],
        v1::envelope::Payload::ClientHello(v1::ClientHello {
            supported_majors: vec![1],
            max_minor: 0,
            requested_capabilities: vec![],
            cli_release: "test".into(),
        }),
    )
}

fn server_hello_frame() -> Vec<u8> {
    encode_frame(&envelope_with(
        [3; 16],
        v1::envelope::Payload::ServerHello(v1::ServerHello {
            selected_major: 1,
            selected_minor: 0,
            available_capabilities: vec!["network_health".into()],
            server_release: "loopback".into(),
        }),
    ))
    .unwrap()
}

fn finish(mut peer: Child) {
    let _ = peer.kill();
    let _ = peer.wait();
}

#[test]
#[ignore = "requires OpenSSL ML-DSA-87; mandatory in the PQ interoperability job"]
fn the_profile_is_met_and_every_deviation_is_refused() {
    let dir = Dir(std::env::temp_dir().join(format!("hguet-transport-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let Some((key, cert)) = make_identity(&dir.0, "server") else {
        return;
    };
    let (_, other_cert) = make_identity(&dir.0, "other").unwrap();

    // 1. A conforming server: the response is returned.
    let port = free_port();
    let peer = serve(
        port,
        &key,
        &cert,
        "SecP384r1MLKEM1024",
        &server_hello_frame(),
    );
    let response = exchange(&profile("localhost", port, &cert), &hello()).unwrap();
    assert!(matches!(
        response.payload,
        Some(v1::envelope::Payload::ServerHello(_))
    ));
    assert_eq!(response.request_id, vec![3; 16]);
    finish(peer);

    // 2. A CA that did not issue the server certificate: refused (no TOFU, no system store fallback).
    let port = free_port();
    let peer = serve(
        port,
        &key,
        &cert,
        "SecP384r1MLKEM1024",
        &server_hello_frame(),
    );
    assert_eq!(
        exchange(&profile("localhost", port, &other_cert), &hello())
            .unwrap_err()
            .code(),
        "TRANSPORT_HANDSHAKE_FAILED"
    );
    finish(peer);

    // 3. Right CA, wrong identity: the certificate names localhost, not this address.
    let port = free_port();
    let peer = serve(
        port,
        &key,
        &cert,
        "SecP384r1MLKEM1024",
        &server_hello_frame(),
    );
    assert_eq!(
        exchange(&profile("127.0.0.1", port, &cert), &hello())
            .unwrap_err()
            .code(),
        "TRANSPORT_HANDSHAKE_FAILED"
    );
    finish(peer);

    // 4. A classical-only key exchange is a downgrade: refused.
    let port = free_port();
    let peer = serve(port, &key, &cert, "X25519", &server_hello_frame());
    assert!(exchange(&profile("localhost", port, &cert), &hello()).is_err());
    finish(peer);

    // 5. A conforming connection that returns a malformed frame yields an error, never a message.
    let port = free_port();
    let peer = serve(port, &key, &cert, "SecP384r1MLKEM1024", &[0, 0, 0, 5, 1, 2]);
    let mut short = profile("localhost", port, &cert);
    short.timeout = Duration::from_secs(2); // the peer never completes the frame, so the wait is bounded by the timeout
    let code = exchange(&short, &hello()).unwrap_err().code();
    assert!(
        ["TRANSPORT_TIMEOUT", "FRAME_TRUNCATED"].contains(&code),
        "{code}"
    );
    finish(peer);

    // 6. Nothing listening: refused quickly, not hung.
    let closed = free_port();
    assert!(exchange(&profile("localhost", closed, &cert), &hello()).is_err());
}
