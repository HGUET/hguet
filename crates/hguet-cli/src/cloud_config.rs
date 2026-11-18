//! Public endpoint metadata and the explicit local Devnet handshake.
//! Hostname is public routing metadata, NEVER an SSH username or a TLS trust anchor.
pub const DEFAULT_CLOUD_HOST: &str = "vps-d0669a91.vps.ovh.net";
pub const DEFAULT_CLOUD_PORT: u16 = 443;
pub const DEFAULT_CLOUD_ENDPOINT: &str = "vps-d0669a91.vps.ovh.net:443";

pub fn loopback_hello(ca_file: std::path::PathBuf) -> Result<serde_json::Value, &'static str> {
    use hguet_cloud::transport::{exchange, TlsProfile};
    use hguet_cloud::wire::{
        envelope_with,
        v1::{envelope::Payload, ClientHello},
    };
    let profile = TlsProfile {
        host: "127.0.0.1".into(),
        port: 8443,
        openssl: "openssl".into(),
        timeout: std::time::Duration::from_secs(10),
        ca_file,
    };
    let request = envelope_with(
        [1; 16],
        Payload::ClientHello(ClientHello {
            supported_majors: vec![1],
            max_minor: 0,
            requested_capabilities: vec![],
            cli_release: env!("CARGO_PKG_VERSION").into(),
        }),
    );
    let reply = exchange(&profile, &request).map_err(|err| err.code())?;
    let Some(Payload::ServerHello(hello)) = reply.payload else {
        return Err("EXPECTED_SERVER_HELLO");
    };
    if reply.request_id != request.request_id
        || (reply.protocol_major, reply.protocol_minor) != (1, 0)
        || (hello.selected_major, hello.selected_minor) != (1, 0)
    {
        return Err("INVALID_SERVER_HELLO");
    }
    Ok(
        serde_json::json!({"endpoint":"127.0.0.1:8443","protocol":"1.0",
        "server_release":hello.server_release,"available_capabilities":hello.available_capabilities}),
    )
}

pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "cloud": {
            "default_endpoint": DEFAULT_CLOUD_ENDPOINT,
            "host": DEFAULT_CLOUD_HOST,
            "port": DEFAULT_CLOUD_PORT,
            "transport": "tls1.3-protobuf-tcp",
            "available": false,
            "status": "NOT_IMPLEMENTED",
            "authentication": "future server-authenticated certificate and pinned trust; not implemented"
        },
        "local_mode": {
            "cloud_network_access": false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correct_vps_default_is_not_an_ssh_url_or_port() {
        assert_eq!(
            DEFAULT_CLOUD_ENDPOINT,
            format!("{DEFAULT_CLOUD_HOST}:{DEFAULT_CLOUD_PORT}")
        );
        assert!(!DEFAULT_CLOUD_ENDPOINT.contains('@'));
        assert!(!DEFAULT_CLOUD_ENDPOINT.starts_with("ssh://"));
        assert_eq!(DEFAULT_CLOUD_PORT, 443);
        assert!(!describe()["cloud"]["available"].as_bool().unwrap());
    }
}
