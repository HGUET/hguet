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

## Deployment acceptance checklist (unreleased prototype)

For an operator-controlled Linux test deployment, do **not** use a writable
source checkout as the protected entrypoint. Install the two Python launchers,
pinned signer ELF and policy in root-owned, non-group/world-writable paths.
Run the launcher as a **dedicated non-root service identity**, separate from
the untrusted agent. The service must own only its private mode-0700 replay
directory; the agent must not be able to edit or reset it.

A deployment is **not accepted** solely because a CI test passes. Before
considering any installed prototype ready for further evaluation:

1. Verify the ELF digest and operator public key out of band, with no agent
   influence over either value or the policy file.
2. Verify all protected file ancestors and the installed scripts/ELF are
   root-owned and cannot be modified by the service or agent.
3. Verify the journal resides on a durable **local filesystem** with reliable
   file and directory fsync and exclusive-create semantics; do not use an
   unverified network share or ephemeral container layer.
4. Run the installed-path test under separate identities. A successful
   sandboxed BLOCK refusal is exit 20; exit 40 is a safe failure, **not**
   proof that a real sandbox ran.
5. On a representative Linux host with user namespaces permitted, confirm
   Bubblewrap and seccomp run live. Capture the actual host/kernel policy
   and test outcome. A skipped CI sandbox run does not satisfy this gate.
6. Prove that an already consumed intent ID stays blocked across process
   restarts. Test storage-full, permission-denied and fsync-failure handling
   without permitting any signer launch.
7. Ensure the untrusted agent cannot invoke a hypothetical future key/device
   signer directly. This no-key prototype alone cannot establish that boundary.

### Storage fault-injection contract

The offline regression test `scripts/check_protected_signer.py` injects
both marker-file and parent-directory `fsync` errors. It requires exit-denial
semantics with **no sandbox child spawn**, retention of any created marker and
subsequent `REPLAY_BLOCKED` for that identifier. Tests do not establish that
a particular storage device honors flushes across power loss. If journal
durability cannot be established operationally, deny use; never silently
switch to a memory-only replay cache.

**Outstanding production blockers:** authenticated and authorized client
admission *before* reservation, tamper/rollback-resistant journal anchoring,
signed artifact provenance, controlled service provisioning and isolation,
tested host resource limits, complete execution-time spending enforcement,
and independent security review. Until all relevant controls are implemented
and verified, no funds or keys should be entrusted to this component.

## Local client admission gate (Linux prototype)

`scripts/run_signer_admission.py` is an **additional one-request Unix
domain socket entrypoint** for a dedicated non-root signer service. Its
administrator-owned JSON policy has exactly these fields:

~~~json
{
  "schema_version": 1,
  "kind": "hguet_signer_admission",
  "socket_path": "/run/hguet-signer/admission.sock",
  "allowed_client_uid": 12345,
  "protected_policy": "/etc/hguet/signer-policy.json"
}
~~~

The numeric UID is illustrative, **not** a safe universal value. Provision
the intended client and signer service as **different Unix users**. The
admission JSON, both existing protected launcher scripts, the admission
script and signer ELF must be installed under root-owned, non-writable
ancestor directories. Provision the Unix socket directory separately as
owned by the signer service, non-group-writable and not accessible to
world users; group access to the socket must be limited administratively.
The gate creates a mode-0660 socket, handles one connection, and exits.
The connecting client must send at most 64 KiB then shut down its
write-half, allowing the gate to detect the end of the request.

**Order of checks:** strict root-owned admission policy → protected
signer policy verification → kernel `SO_PEERCRED` on the accepted socket →
compare peer UID against the administrator-pinned allowed UID → bounded
request read → protected child invocation → one-use journal reservation →
Bubblewrap sandbox → unconditional BLOCK refusal. An unauthorized UID
cannot cause the gate to launch the journal-reserving child.

This is an **experimental OS identity boundary**, not an authenticated
PaymentIntent issuer or end-user identity. It prevents a *different UID*
from consuming identifiers via this gate but cannot stop a compromised
allowed client, root/host compromise or a service-user compromise. It
does not prevent availability denial by connections or requests from
permitted peers, and it does not enforce a long-lived daemon lifecycle.
Agent and signer service accounts must never be the same; OS permissions
must prevent agents from writing to the replay directory or directly
running the protected launcher **as the signer service account**.
The underlying protected launcher remains available to an already
compromised service UID; this gate alone does not remove that risk.

**Socket group and timeouts.** The socket inherits the group of its
directory only if that directory is setgid (for example mode `2750`,
service-owned, group = the clients group); otherwise it takes the service
user's primary group and group members cannot connect. The directory must stay
non-group-writable so no other UID can unlink, rename or replace the socket.
Group membership is a coarse first filter; the pinned UID in `SO_PEERCRED` is
the actual admission decision, so a group member with another UID is refused
before any payload is read. The request must arrive within a **total** 5 s
budget (not per `recv`), so a slow-drip peer cannot stall the one-shot gate;
replies use a 5 s send timeout. The gate unlinks only the exact socket inode it
bound itself, never a pre-existing or substituted path.

**Known limitation (asserted by the live test):** any process already running
as the signer-service UID can invoke the protected launcher directly and skip
the gateway allow-list. It still only receives a BLOCK refusal and can burn
intent identifiers. UID separation is therefore **not user authentication**.

**Tests:** `scripts/check_signer_admission.py` is the offline unit test (real
peer credentials on a socketpair, unauthorized UID rejection before payload
read, strict admission policy, input bounds, total read deadline, forged
child responses). `scripts/check_signer_admission_users.py` is a **live test
that must run as root on Linux**: it creates a service, an allowed and an
unauthorized (same socket group) user plus an outsider, and exercises
`Unix socket -> SO_PEERCRED -> protected signer -> replay journal ->
Bubblewrap -> BLOCK`, replay refusal, socket tamper attempts and direct
launcher calls. It prints `SKIP` (not PASS) when root, the user tools or
Bubblewrap namespaces are unavailable. Live validation on a production host
and an independent security review are still outstanding. No signing, wallet,
key custody, spending authorization or broadcast is enabled.
