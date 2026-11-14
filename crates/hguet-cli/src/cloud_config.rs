//! Cloud endpoint configuration. The network transport is NOT implemented yet.
//! Hostname is public routing metadata, NEVER an SSH username or a TLS trust anchor.
pub const DEFAULT_CLOUD_HOST: &str = "vps-d0669a91.vps.ovh.net";
pub const DEFAULT_CLOUD_PORT: u16 = 443;
pub const DEFAULT_CLOUD_ENDPOINT: &str = "vps-d0669a91.vps.ovh.net:443";

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
