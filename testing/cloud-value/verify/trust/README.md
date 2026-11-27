# Trust stores

> **Community Edition direction (2026-11-27):** Cloud verification test trust material is not a Community Edition release trust anchor. See the [release roadmap](../../../../docs/release/community-0.1.0/ROADMAP.md).

`test_issuers.json` holds TEST-ONLY public keys. There is deliberately **no** `real_issuers.json`: until HGUET provisions an authenticated issuer key (signed release / pin rotation), the real server cannot be verified and stays `unavailable`.
