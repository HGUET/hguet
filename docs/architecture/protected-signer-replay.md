# Protected signer launch and one-use intent journal

**Status: implemented BLOCK-only prototype; no private keys, device signing, transfer approval or Solana broadcast.** This path adds operator-controlled launch data and a durable one-use intent-ID journal before invoking the existing Linux Bubblewrap sandbox. It is not a production signer.

## Operator policy

The stricter launcher at scripts/run_signer_protected.py accepts *only* an absolute --policy path. Its JSON includes schema_version=1, kind=hguet_protected_signer_policy, binary, binary_sha256, network, trusted_key, and replay_directory. No agent-controlled CLI option can override those values.

Example *illustrative* operator policy (replace the SHA-256 with the **independently verified** digest, never a hash obtained from an untrusted agent):

~~~json
{
  "schema_version": 1,
  "kind": "hguet_protected_signer_policy",
  "binary": "/opt/hguet/bin/hguet-signer-isolate",
  "binary_sha256": "REPLACE_WITH_SEPARATELY_VERIFIED_64_LOWERCASE_HEX_SHA256",
  "network": "devnet",
  "trusted_key": "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ",
  "replay_directory": "/var/lib/hguet-signer/replay"
}
~~~

The policy file, protected launcher, sandbox launcher Python source files **and signer ELF binary** must be **root-owned** regular files without group/world write permission, under root-owned protected ancestor directories. The executable must not be writable by the unprivileged signer service user, even after it is opened and SHA-256 checked, because inode-pinning alone cannot stop in-place mutation. No symlinks are accepted. The launcher explicitly **refuses execution with UID 0**. The replay directory must already exist, be owned by the *separate dedicated **non-root** signer service UID*, and have restrictive permissions (0700). The untrusted agent must have a different OS identity without filesystem write/delete rights to the policy or journal. The prototype checks ownership and permissions, but **does not install or provision** the service account, secure launcher, or OS access control.

Example invocation from an independently configured trusted service:

~~~sh
/usr/bin/python3 -E -s /usr/local/libexec/hguet/run_signer_protected.py \
  --policy /etc/hguet/signer-policy.json < agent-request.json
~~~

This is a documentation example, not an endorsement for real funds.

## Durable one-use intent journal

The protected launcher accepts at most 64 KiB of agent JSON. Before spawning the sandbox, it checks the request shape, canonical Base64 transaction and intent payload, valid signed intent-ID structure, and consistency with the separately pinned operator network and public key.

**This preliminary parsing is not a cryptographic signature verification.** The independently signed Ed25519 intent is still verified by the isolated Rust program.

The reservation key is SHA-256 of a domain-separated tuple containing: constant hguet-protected-intent-id-v1, pinned network, pinned signer public key, and the *signed payload's intent_id*. Whitespace changes, changed transaction bytes, or changed signatures do not create a new reservation for the same intent ID.

Before any sandbox is spawned, the launcher atomically creates a marker named <digest>.used with O_CREAT | O_EXCL | O_NOFOLLOW and mode 0600. It writes the identifier and fsyncs both the marker and the containing directory. A second reservation for the same intent ID is refused even when concurrent; no marker is deleted or reused after invalid signature, timeout, process crash or sandbox failure. If journal creation, write or fsync fails, HGUET blocks without launching the signer.

### Important limitations

- **Early-consumption denial of service:** because the marker is reserved *before* the isolated Rust signature check, a malicious submitter knowing an intent ID may burn it before legitimate use. A production service must authenticate and authorize callers independently before allowing journal reservation.
- **No rollback resistance:** an administrator or compromised service account can delete markers or restore older filesystem snapshots. No monotonic secure hardware counter or externally anchored audit log exists.
- **No total spending enforcement:** one-use IDs do not guarantee CPI, fees, Token-2022 hooks, delegate limits or gross token/SOL debits.
- **No OS deployment attestation:** an operator-protected Python installation, service process identity, kernel and local POSIX filesystem remain security assumptions. The repository does not create a production systemd unit or harden the actual host.
- **No guaranteed live Bubblewrap:** CI may prohibit unprivileged user namespaces. In that case tests verify fail-closed exit 40, while live sandbox execution remains unverified.
- **No ALLOW:** the program remains BLOCK-only with no key, wallet or transaction broadcaster. No intent or replay marker constitutes a payment authorization.

## Tests

scripts/check_protected_signer.py uses a real on-disk atomic replay journal, eight concurrent attempts, altered requests, malformed signed payloads, forged operator overrides and sandbox-launch failures. Its temporary CI directory cannot represent administrator provisioning: ownership/ancestor checks are mocked only for the unit environment. A passing test is **not proof of an installed protected production service**.

Linux sandbox tests remain in scripts/check_signer_sandbox.py and scripts/check_signer_sandbox_runtime.py. See also trusted-signer-isolation.md and linux-signer-sandbox.md.
