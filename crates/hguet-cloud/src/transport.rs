//! Strict Cloud transport through the OpenSSL command line (>= 3.5): one TLS 1.3 connection, one request frame, one
//! response frame. The CLI hand-rolls no TLS or cryptography and sends no wallet or key material.
//!
//! Policy, all of it mandatory and fail-closed (no classical fallback, no downgrade, no TOFU, no client certificate):
//! * TLS 1.3 only, key exchange group `SecP384r1MLKEM1024`, cipher suite `TLS_AES_256_GCM_SHA384`, server certificate
//!   signature `mldsa87`;
//! * the server must chain to the CONFIGURED CA file only (system trust stores are disabled) and present the expected
//!   host name (or IP address);
//! * the negotiated parameters printed by OpenSSL are parsed and every one must match, otherwise the response is discarded
//!   even if the connection worked - a client that cannot prove the profile was met has not met it.
//!
//! The Cloud endpoint is not enabled in the CLI yet; this module is not called by any command.

use crate::wire::{decode_frame, encode_frame, v1, MAX_FRAME_BYTES};
use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const REQUIRED_GROUP: &str = "SecP384r1MLKEM1024";
pub const REQUIRED_CIPHERSUITE: &str = "TLS_AES_256_GCM_SHA384";
pub const REQUIRED_SIGNATURE: &str = "mldsa87";
const MAX_DIAGNOSTIC_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub host: String,
    pub port: u16,
    /// The only trust anchor: a CA (or the pinned server certificate) supplied by configuration, never by the server.
    pub ca_file: PathBuf,
    pub openssl: String,
    pub timeout: Duration,
}

fn host_is_valid(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl TlsProfile {
    /// The exact `openssl s_client` argument vector. Pure, so the policy is testable without a network.
    pub fn s_client_args(&self) -> Result<Vec<String>> {
        if !host_is_valid(&self.host) || self.port == 0 {
            return Err(Error("TRANSPORT_ENDPOINT_INVALID"));
        }
        let verify = if self.host.parse::<IpAddr>().is_ok() {
            "-verify_ip"
        } else {
            "-verify_hostname"
        };
        let mut args: Vec<String> = ["s_client", "-connect"].map(String::from).to_vec();
        args.push(if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        });
        args.extend([verify.to_owned(), self.host.clone()]);
        if verify == "-verify_hostname" {
            args.extend(["-servername".to_owned(), self.host.clone()]);
        }
        args.extend(["-verify_return_error", "-CAfile"].map(String::from));
        args.push(self.ca_file.to_string_lossy().into_owned());
        args.extend(
            [
                "-no-CApath",
                "-no-CAstore",
                "-tls1_3",
                "-groups",
                REQUIRED_GROUP,
                "-ciphersuites",
                REQUIRED_CIPHERSUITE,
                "-sigalgs",
                REQUIRED_SIGNATURE,
            ]
            .map(String::from),
        );
        // -brief prints the negotiated parameters on stderr; -nocommands stops binary frames that happen to start with
        // 'Q' or 'R' from being read as s_client commands.
        args.extend(["-brief", "-nocommands"].map(String::from));
        Ok(args)
    }
}

/// Checks the parameter summary OpenSSL printed. Every line below must be present and exactly right.
pub fn check_session_summary(summary: &str, host: &str) -> Result<()> {
    let value = |key: &str| {
        summary
            .lines()
            .find_map(|l| l.strip_prefix(key).map(str::trim))
    };
    let ok = value("Protocol version:") == Some("TLSv1.3")
        && value("Ciphersuite:") == Some(REQUIRED_CIPHERSUITE)
        && value("Signature type:") == Some(REQUIRED_SIGNATURE)
        && value("Verification:") == Some("OK")
        && value("Negotiated TLS1.3 group:") == Some(REQUIRED_GROUP)
        && (value("Verified peername:") == Some(host)
            || (host.parse::<IpAddr>().is_ok() && value("Verified peername:").is_none()));
    if ok {
        Ok(())
    } else {
        Err(Error("TRANSPORT_PROFILE_NOT_MET"))
    }
}

/// Sends one encoded frame and returns the one response frame's decoded Envelope.
pub fn exchange(profile: &TlsProfile, request: &v1::Envelope) -> Result<v1::Envelope> {
    let frame = encode_frame(request)?;
    let args = profile.s_client_args()?;
    let mut child = Command::new(&profile.openssl)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error("TRANSPORT_OPENSSL_UNAVAILABLE"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(Error("TRANSPORT_OPENSSL_UNAVAILABLE"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or(Error("TRANSPORT_OPENSSL_UNAVAILABLE"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or(Error("TRANSPORT_OPENSSL_UNAVAILABLE"))?;
    // Writer and readers run on their own threads so a full pipe can never deadlock the exchange.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&frame); // dropping stdin signals the end of the request
    });
    let out_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = (&mut stdout)
            .take(MAX_FRAME_BYTES as u64 + 5)
            .read_to_end(&mut buffer);
        buffer
    });
    let err_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = (&mut stderr)
            .take(MAX_DIAGNOSTIC_BYTES)
            .read_to_end(&mut buffer);
        buffer
    });
    let deadline = Instant::now() + profile.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let _ = writer.join();
    let body = out_reader.join().unwrap_or_default();
    let diagnostics = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned();
    let Some(status) = status else {
        return Err(Error("TRANSPORT_TIMEOUT"));
    };
    if !status.success() {
        return Err(Error("TRANSPORT_HANDSHAKE_FAILED"));
    }
    check_session_summary(&diagnostics, &profile.host)?;
    decode_frame(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(host: &str) -> TlsProfile {
        TlsProfile {
            host: host.into(),
            port: 443,
            ca_file: PathBuf::from("/etc/hguet/ca.pem"),
            openssl: "openssl".into(),
            timeout: Duration::from_secs(5),
        }
    }

    const GOOD: &str = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nPeer certificate: CN=localhost\nHash used: UNDEF\nSignature type: mldsa87\nVerification: OK\nVerified peername: localhost\nNegotiated TLS1.3 group: SecP384r1MLKEM1024\n";

    #[test]
    fn the_command_line_pins_the_whole_profile_and_disables_every_fallback() {
        let args = profile("cloud.example").s_client_args().unwrap().join(" ");
        for must in [
            "-tls1_3",
            "-groups SecP384r1MLKEM1024",
            "-ciphersuites TLS_AES_256_GCM_SHA384",
            "-sigalgs mldsa87",
            "-verify_return_error",
            "-CAfile /etc/hguet/ca.pem",
            "-no-CApath",
            "-no-CAstore",
            "-verify_hostname cloud.example",
            "-servername cloud.example",
            "-nocommands",
            "-connect cloud.example:443",
        ] {
            assert!(args.contains(must), "missing {must}: {args}");
        }
        for forbidden in [
            "-cert",
            "-key",
            "-no_tls1_3",
            "-tls1_2",
            "-insecure",
            "-noverify",
            "-psk",
        ] {
            assert!(!args.split(' ').any(|a| a == forbidden), "{forbidden}");
        }
        let ip = profile("127.0.0.1").s_client_args().unwrap().join(" ");
        assert!(ip.contains("-verify_ip 127.0.0.1") && !ip.contains("-servername"));
    }

    #[test]
    fn invalid_endpoints_are_refused_before_anything_runs() {
        for bad in [
            "",
            "-oops",
            "a b",
            "host;rm",
            "host/../x",
            "ssh://host",
            "user@host",
            "host:443",
            "-",
            "a..b",
        ] {
            assert_eq!(
                profile(bad).s_client_args().unwrap_err().code(),
                "TRANSPORT_ENDPOINT_INVALID",
                "{bad}"
            );
        }
        let mut zero = profile("cloud.example");
        zero.port = 0;
        assert!(zero.s_client_args().is_err());
    }

    #[test]
    fn only_a_summary_that_proves_every_parameter_is_accepted() {
        assert!(check_session_summary(GOOD, "localhost").is_ok());
        for (needle, replacement) in [
            ("TLSv1.3", "TLSv1.2"),
            ("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"),
            ("mldsa87", "ed25519"),
            ("Verification: OK", "Verification: FAILED"),
            ("SecP384r1MLKEM1024", "X25519"),
            (
                "Verified peername: localhost",
                "Verified peername: evil.example",
            ),
        ] {
            assert_eq!(
                check_session_summary(&GOOD.replace(needle, replacement), "localhost")
                    .unwrap_err()
                    .code(),
                "TRANSPORT_PROFILE_NOT_MET",
                "{needle}"
            );
        }
        // A missing line is as bad as a wrong one: an unproven parameter is an unmet parameter.
        for line in [
            "Protocol version",
            "Ciphersuite",
            "Signature type",
            "Verification",
            "Negotiated TLS1.3 group",
            "Verified peername",
        ] {
            let without: String = GOOD
                .lines()
                .filter(|l| !l.starts_with(line))
                .map(|l| format!("{l}\n"))
                .collect();
            assert!(
                check_session_summary(&without, "localhost").is_err(),
                "{line}"
            );
        }
        assert!(check_session_summary("", "localhost").is_err());
    }
}
