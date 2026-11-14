# Release readiness: independent-environment verification and reproducible builds

BLOCK-only. These artifacts hold no key, cannot sign, and cannot broadcast.
They are **unsigned test builds**: `SHA256SUMS` lets anyone compare their own
build with CI's; it is not a publisher signature.

## Independent-environment evidence

A WSL2 kernel is shared by all WSL distributions, so another WSL distribution
is a different *userland*, not a different kernel. Evidence is therefore
recorded per environment and must be read as such:

| Environment | Kernel / policy | What ran |
|-------------|-----------------|----------|
| WSL2 Ubuntu 26.04 (Python 3.14) | WSL2 kernel 6.18, no AppArmor | full CI suite, live multi-UID, REQUIRE_LIVE |
| WSL2 Debian 13 (Python 3.13, glibc 2.41) | same WSL2 kernel | offline tests, live sandbox, live multi-UID (single, split, resilience) |
| GitHub-hosted `ubuntu-22.04` VM | Azure VM kernel, no userns restriction | full CI suite, `HGUET_REQUIRE_LIVE=1` |
| GitHub-hosted `ubuntu-24.04` VM | Azure VM kernel, AppArmor userns restriction | full CI suite, `HGUET_REQUIRE_LIVE=1` |

The CI job prints kernel, bubblewrap version and the AppArmor userns sysctl as
check-run annotations. **No locally managed VM (Hyper-V/QEMU) was created:**
that needs elevation and a multi-hundred-MB OS image download, which was not
authorised. The remaining gap is a self-managed VM with a distinct kernel
build; run the same commands there:

~~~bash
cargo build --workspace --locked && cargo build -p hguet-signer --bin hguet-signer-isolate
HGUET_REQUIRE_LIVE=1 python3 scripts/check_signer_sandbox_runtime.py
sudo env HGUET_REQUIRE_LIVE=1 python3 scripts/check_signer_admission_users.py target/debug/hguet-signer-isolate
python3 scripts/check_require_live.py
~~~

## Gateway/backend resilience and concurrency assessment

Measured (WSL2): 20 consecutive refused/hostile requests leave gateway and
backend running; backend stop/restart is survived and the journal persists; a
legitimate client queued behind a slow-drip peer waits about **4.8 s** (the 5 s
read deadline) and is then served; 8 concurrent clients sending one `intent_id`
produce exactly **one** sandboxed BLOCK and one journal marker.

The gateway and backend handle connections **serially**. That is deliberate:

* Journal atomicity does not depend on the serial server — `O_EXCL` create plus
  `fsync`, covered by the existing 8-writer launcher test and the 8-client live
  test above.
* Serial handling bounds worst-case head-of-line blocking to the read deadline
  (5 s) plus the sandbox timeout (18 s for an admitted caller), which is
  acceptable for a prototype and is the documented availability limit.

Bounded concurrency (for example a worker pool of 2–4 processes, each doing
authenticate → read with deadline → reserve → sandbox) would be safe for the
journal, but it is **not implemented**: it multiplies sandbox launches, needs
per-peer connection limits, and the rollback anchor (see
`journal-rollback-protection.md`) must be designed first because it adds a
serialisation point. Do not add threads in the gateway process: the current
code uses process-wide state (`os.umask`, signal handlers).

## Reproducible builds

~~~bash
python scripts/build_release.py                       # artifacts + SHA256SUMS in dist/dist
python scripts/build_release.py --verify-reproducible  # HEAD built twice, different dirs
~~~

Inputs that are pinned: `rust-toolchain.toml` (1.100.0), committed `Cargo.lock`
(**it was previously git-ignored, so dependency versions were not fixed**),
`--locked`, `CARGO_INCREMENTAL=0`, `SOURCE_DATE_EPOCH` = commit time, and
`--remap-path-prefix` for the source tree, `CARGO_HOME` and `RUSTUP_HOME`.
`--verify-reproducible` builds in two different directories and fails on any
byte difference; identical bytes are claimed only per target, toolchain and OS
image, and are proven on every run rather than assumed.

The `Reproducible CLI build` workflow runs it on `ubuntu-24.04` and
`windows-latest` and uploads `hguet` (Linux also `hguet-signer-isolate`) with
`SHA256SUMS` and `BUILD-INFO.json`. Building the Windows binary locally needs
the MSVC toolchain, which is not installed on the development machine; use the
workflow.

Not provided: publisher signatures, SBOM, provenance attestation, notarisation.

## Observed GitHub CI results and what was done about them

Real results read from the check-run annotations (not assumed):

| Run | Job | Result | Cause |
|-----|-----|--------|-------|
| `95aac83` / `42e631b` | rust (ubuntu-22.04) | FAIL at live sandbox | bubblewrap **0.6.1**: `Unknown option --disable-userns` (option exists from 0.8.0) |
| `95aac83` / `42e631b` | rust (ubuntu-24.04) | FAIL at live sandbox | kernel 7.0.0-1017-azure, `apparmor_restrict_unprivileged_userns=1`, bubblewrap 0.9.0: `loopback: Failed RTM_NEWADDR: Operation not permitted` |
| `930d39d` | Reproducible build (windows-latest) | FAIL | `hguet.exe` differs between two build directories (`ef59db42...` vs `724f2534...`); the Linux build is identical |
| `42e631b` | Security benchmark (full) | PASS | - |

Responses (none weakens the sandbox):

* **Ubuntu 22.04**: unsupported for live isolation. The launcher now checks `bwrap --version` and refuses below
  **0.8.0** (exit 40, "no weaker sandbox is used"). CI marks 22.04 `live_sandbox: false` and runs
  `check_signer_sandbox_unsupported.py`, which **asserts the refusal** instead of silently skipping.
* **Ubuntu 24.04**: the runner step sets `kernel.apparmor_restrict_unprivileged_userns=0` (platform
  prerequisite on the ephemeral VM) and `HGUET_REQUIRE_LIVE=1` stays on, so a skip still fails.
* **Windows reproducibility**: MSVC `link.exe` embeds a build-time timestamp unless `/Brepro` is passed; the
  build now adds `-Clink-arg=/Brepro` on Windows. This is a hypothesis taken from the differing hashes and
  the known linker behaviour, **not yet confirmed**; the next Windows CI run is the evidence. If the hashes
  still differ, the remaining candidates are embedded PDB paths and resource data.
