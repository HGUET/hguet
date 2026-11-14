# Replay-journal rollback protection — design proposal (not implemented)

Status: **proposal for review**. Nothing here is implemented and no new
cryptographic protocol is introduced. HGUET stays BLOCK-only: no keys, no
signing, no broadcast.

## Why this matters, honestly

The replay journal (`<replay_dir>/<sha256>.used`, `O_EXCL` + `fsync`) stops an
`intent_id` from being processed twice. If an attacker can **roll the journal
back**, a used identifier becomes usable again. Today every path ends in an
unconditional BLOCK, so a rolled-back journal gains nothing. The protection is
therefore a **hard prerequisite for any future mode more permissive than
BLOCK**, and is useful earlier only as tamper/corruption detection.

## Threat model

| ID | Adversary / event | Capability | In scope |
|----|-------------------|------------|----------|
| R1 | Operator mistake | restores an old backup, reverts a VM snapshot, loses the volume | yes |
| R2 | Storage / hypervisor / cloud-admin rollback | rewrites the disk or snapshot underneath a healthy host | yes (detect, fail closed) |
| R3 | Local non-root attacker | cannot write the 0700 journal (UID separation) | already mitigated by OS permissions |
| R4 | Compromised backend UID | can forge any local state, including a local counter | **out of scope** for local state; only an independent anchor that the backend cannot rewrite limits it |
| R5 | Root / kernel compromise | everything | out of scope |
| R6 | Anchor outage or partition | anchor unreachable | yes (defined behaviour below) |

Goal: a journal state **older than the last acknowledged state** is detected
at startup and on every reservation; the service then refuses (fails closed)
until an operator recovers it explicitly.

## What the trusted external anchor must provide

1. **Monotonicity** — a value that can only increase, in a failure domain
   different from the journal disk and from the VM snapshot.
2. **Atomic compare-and-swap** — advance only if the previous value is the one
   the writer last saw (prevents two writers diverging).
3. **Durability before use** — acknowledged only after it is persistent.
4. **Independent authority** — the backend UID must not be able to rewind it.

Candidate anchors (to be chosen by the operator, none implemented):

| Anchor | Pros | Cons |
|--------|------|------|
| TPM 2.0 NV counter (physical host) | local, cheap, survives disk rollback | a *virtual* TPM is usually stored with the VM and is rolled back by a snapshot revert; limited NV write endurance |
| Cloud object/KV store with generation preconditions (conditional write) | strong consistency, separate failure domain, audit logs | cloud trust and availability; credentials must not be reachable by the backend UID beyond "advance" |
| Independent append-only witness / transparency log run by HGUET or the customer | strongest rollback evidence, third-party verifiable | operational cost; needs its own review |
| HSM monotonic counter | hardware assurance | availability and cost |

A pure local file or a same-volume counter is **not** an anchor.

## Proposed state and ordering (existing primitives only)

Local checkpoint `epoch`, `count`, `head` where `head = SHA-256(head_prev ||
marker_name)` — a plain hash chain, no new primitive. The anchor stores
`(epoch, count, head)`.

Reservation order, fail-closed at every step:

1. Read anchor `(e, n, h)`; verify the local chain reproduces `h` at `n`.
   Mismatch → `ROLLBACK_DETECTED`, refuse everything.
2. Compute `h' = H(h || new_marker)`; **advance the anchor** to `(e, n+1, h')`
   with compare-and-swap. Failure → refuse (nothing reserved).
3. Create the local `O_EXCL` marker, `fsync` file and directory, update the
   local checkpoint.
4. Only now run the sandbox.

Crash recovery: anchor ahead of local by exactly one entry whose marker is
missing → the interrupted reservation is **completed conservatively** (marker
created, identifier consumed). Ahead by more than one, or local ahead of
anchor → anomaly, refuse and require the operator.

## Behaviour when the anchor is unavailable

* Current BLOCK-only mode: the answer is always BLOCK, so unavailability must
  not become an approval path. Default is **refuse all requests** (fail closed)
  with a distinct reason code so operators can alert.
* Any future permissive mode: **no grace period**. A cache of "last known good"
  would reintroduce rollback.
* Reads of status (health) stay available; reservations never do.

## Recovery strategy

1. Preferred: restore the journal backup whose chain head equals the anchor.
2. Otherwise the operator performs an explicit, audited **re-baseline**
   recorded in the anchor as a new epoch. A re-baseline is only safe once every
   previously issued intent has **expired**, because replay of an expired
   intent is already rejected by its `expires_at_unix`. The procedure must
   therefore enforce a wait of the maximum intent lifetime before accepting
   requests in the new epoch.
3. Every recovery action is logged outside the host.

## Test plan (before any implementation ships)

* Restore an older journal snapshot → refuse with `ROLLBACK_DETECTED`.
* Anchor down / timeout / partial write → refuse, no marker created.
* Crash injection between steps 2 and 3, and between 3 and 4 → deterministic
  recovery, identifier consumed exactly once.
* Concurrent reservations (existing 8-writer test) with the anchor in the loop.
* Anchor value rewound by the backend UID → must be impossible by credential
  design, verified, not assumed.
* Chaos: clock skew, duplicate anchor writes, truncated checkpoint.

## Explicitly not decided

Which anchor to use; whether HGUET operates a witness; retention of the
transparency record; independent cryptographic and protocol review. Those need
an owner and a review **before** implementation. No custom signature or
commitment scheme should be written without that review.
