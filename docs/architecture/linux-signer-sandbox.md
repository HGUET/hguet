# Linux signer sandbox — mandatory Bubblewrap launcher

**Status: optional operator-controlled Linux launcher implemented; all signing remains BLOCK.** This is not a wallet, hardware signer, secure enclave, signed release or complete OS security proof. The standalone Rust refusal binary still exists and can be run directly without a sandbox; that path likewise cannot sign.

## How to run

On Linux x86_64 or AArch64, install the operating system's trusted Bubblewrap package at /usr/bin/bwrap. Build the Rust HGUET no-key signer, verify its exact expected SHA-256 **from an independently trusted source**, and provide a strictly shaped agent JSON file on stdin:

~~~sh
cargo build -p hguet-signer --bin hguet-signer-isolate
SIGNER_BIN="$(realpath target/debug/hguet-signer-isolate)"
# A local build hash is suitable only for demos; pin a separately verified digest for real use.
EXPECTED_SHA256="$(sha256sum "$SIGNER_BIN" | cut -d' ' -f1)"
python3 scripts/run_signer_sandbox.py \
  --binary "$SIGNER_BIN" \
  --binary-sha256 "$EXPECTED_SHA256" \
  --network devnet \
  --trusted-key 2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ \
  < agent-request.json
~~~

The public key above is a **synthetic, non-secret, test-only identity**. The operator must own the real trust configuration and verify the signer binary outside any agent request. The launcher takes no RPC URL, wallet key, approval flag or arbitrary command.

Exit **20** requires a valid block-only signer-refusal result *from inside a successful sandbox*. Exit **40**, with no signer report, is mandatory when Bubblewrap is missing, the hash differs, process creation or namespaces or seccomp fail, an unknown Linux architecture is used, or the sandboxed process claims an ALLOW/signature/broadcast. No ordinary unsandboxed fallback exists.

## Runtime restrictions when a sandbox actually launches

- Bubblewrap requires a new network, PID, IPC, mount and user namespace, no shared host network, restricted further user namespaces, a new session, child death on parent exit, and all capabilities dropped.
- The subprocess starts with a cleared environment. Only read-only host runtime libraries under /usr and available library directories are shared. Host home, /etc, working directory, wallet paths, IPC sockets, and host device nodes are **not** mounted. Private /tmp, empty /dev and namespace-scoped /proc are used.
- A regular, executable, non-group/world-writable hguet-signer-isolate file is opened with O_NOFOLLOW, hashed and pinned to an operator-supplied SHA-256. Bubblewrap mounts the **same open file descriptor** read-only. Replacing its pathname after verification cannot swap the executable inode.
- The mandatory, architecture-checked classic-BPF seccomp filter denies direct socket/network calls, fork/clone, mount and namespace manipulation, ptrace/process memory, kernel module and keyring operations, BPF, perf and io_uring. It kills mismatched audit architectures and x86_64 x32 syscalls. This is **a denylist defense in depth**, not a comprehensive syscall allowlist or formal proof.
- The untrusted agent supplies a bounded JSON message (64 KiB) and a transaction no larger than 16 KiB, which the already implemented Rust isolation module strictly parses and checks against an independently pinned Ed25519 PaymentIntent signer. The signer has no private keys, signing backend or broadcast action.

## Security limitations and release blockers

1. **Not an enforced universal entrypoint.** The bare Rust refusal binary can still run without the launcher; while BLOCK-only that is harmless, but a production device signer must ensure untrusted code cannot reach its device except through the enforced, attested OS isolation service.
2. **Host parent and supply chain are trusted assumptions.** An attacker controlling the launcher, trusted digest, executable, Bubblewrap installation, OS kernel, process startup or operator key can undermine isolation. A hash computed from the same untrusted build is not an authenticity proof.
3. **Broad library tree.** A read-only /usr is mounted to support dynamically linked Rust. A more minimal verified runtime bundle, protected provisioning, hardened OS service identity, MAC policy and signed binaries are needed.
4. **No resource governance.** A 12-second launcher timeout and bounded input exist, but cgroup CPU/memory/pid quotas and integrity-protected launch configuration do not.
5. **Kernel dependence.** Some Linux hosts and CI runners disallow unprivileged user namespaces. That is a genuine **sandbox unavailable** state: refusal exit 40, no signer report. No equivalent isolation is claimed for Windows, macOS or unsupported Linux ABIs.
6. **Signing is still prohibited.** No wallet device or secret exists; the execution-time bound for SOL, fees, CPI, hooks, ALT, delegates, and gross token spending remains incomplete. Replay prevention, trusted clock, hardware custody and secure user confirmation are still future work.

## Tests

- scripts/check_signer_sandbox.py verifies architecture-specific seccomp instructions, mandatory namespace options, rejection of forged ALLOW, missing-Bubblewrap failure and file-inode pinning against pathname replacement.
- scripts/check_signer_sandbox_runtime.py attempts the real Bubblewrap launch when the runner permits it. It checks valid and invalid synthetic pinned keys and the executable digest. If required kernel namespaces are unavailable, it explicitly reports a **skipped runtime sandbox test** and verifies no unsandboxed fallback (exit 40 and empty stdout). Do not call that a successful live sandbox test.
- The existing Rust and CLI tests validate signature and message checks, strictly allowed agent input and unconditional block-only outcomes.

See [Trusted Signer Isolation threat model](trusted-signer-isolation.md).
