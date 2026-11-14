"""Independent, dependency-free Solana transaction and intent builders.

Everything here is written from the public Solana wire format and RFC 8032, NOT
from HGUET's Rust code, so scenario inputs and ground truth do not depend on the
component under test. All keys are deterministic, synthetic, TEST-ONLY seeds
derived from a label; they never hold funds.
"""
from __future__ import annotations

import base64
import hashlib
import json

# ---------------------------------------------------------------- Base58
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _ALPHABET[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + _ALPHABET.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


# ------------------------------------------------- Ed25519 (RFC 8032, 5.1)
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    return _P - x if x % 2 else x


_BY = 4 * _inv(5) % _P
_B = (_xrecover(_BY) % _P, _BY % _P, 1, _xrecover(_BY) * _BY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _compress(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _hash(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, _B))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    public = _compress(_mul(a, _B))
    r = _hash(prefix + message) % _L
    big_r = _compress(_mul(r, _B))
    s = (r + _hash(big_r + public + message) * a) % _L
    return big_r + s.to_bytes(32, "little")


# ----------------------------------------------------------- Identities
def seed_for(label: str) -> bytes:
    return hashlib.sha256(("hguet-bench-test-only-seed:" + label).encode()).digest()


def signer_pubkey(label: str) -> str:
    return b58encode(ed25519_public(seed_for(label)))


def plain_pubkey(label: str) -> str:
    """Deterministic 32-byte non-signer account address (need not be on-curve)."""
    return b58encode(hashlib.sha256(("hguet-bench-account:" + label).encode()).digest())


SYSTEM = "11111111111111111111111111111111"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
CUSTOM_PROGRAM = plain_pubkey("program:custom-unreviewed")
DRAINER_PROGRAM = plain_pubkey("program:known-drainer")


def account(label: str) -> str:
    """`signer:x` labels yield real Ed25519 pubkeys; everything else is plain."""
    if label.startswith("signer:"):
        return signer_pubkey(label)
    if label.startswith("program-id:"):
        return label[len("program-id:"):]
    return plain_pubkey(label)


# ------------------------------------------------------------ Wire format
def _shortvec(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


class Instruction:
    def __init__(self, program: str, accounts: list, data: bytes):
        self.program, self.accounts, self.data = program, list(accounts), bytes(data)


def ix_system_transfer(src: str, dst: str, lamports: int) -> Instruction:
    return Instruction(SYSTEM, [(src, True, True), (dst, False, True)],
                       (2).to_bytes(4, "little") + lamports.to_bytes(8, "little"))


def ix_token_transfer_checked(program, src, mint, dst, authority, amount, decimals=6):
    return Instruction(program, [(src, False, True), (mint, False, False), (dst, False, True),
                                 (authority, True, False)],
                       bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals]))


def ix_token_transfer_unchecked(program, src, dst, authority, amount):
    return Instruction(program, [(src, False, True), (dst, False, True), (authority, True, False)],
                       bytes([3]) + amount.to_bytes(8, "little"))


def ix_token_burn_checked(program, src, mint, authority, amount, decimals=6):
    return Instruction(program, [(src, False, True), (mint, False, True), (authority, True, False)],
                       bytes([15]) + amount.to_bytes(8, "little") + bytes([decimals]))


def ix_token_approve(program, src, delegate, owner, amount):
    return Instruction(program, [(src, False, True), (delegate, False, False), (owner, True, False)],
                       bytes([4]) + amount.to_bytes(8, "little"))


def ix_token_set_authority(program, account_, current, new_authority):
    # AuthorityType::AccountOwner = 2, COption::Some(new) -> 1 + pubkey
    return Instruction(program, [(account_, False, True), (current, True, False)],
                       bytes([6, 2, 1]) + b58decode(new_authority))


def ix_token_close_account(program, account_, destination, owner):
    return Instruction(program, [(account_, False, True), (destination, False, True), (owner, True, False)],
                       bytes([9]))


def ix_compute_budget_limit(units: int) -> Instruction:
    return Instruction(COMPUTE_BUDGET, [], bytes([2]) + units.to_bytes(4, "little"))


def ix_memo(text: str, signer_label: str) -> Instruction:
    return Instruction(MEMO, [(signer_label, True, False)], text.encode())


def ix_custom(program: str, accounts: list, data: bytes = b"\x01") -> Instruction:
    return Instruction(program, accounts, data)


def _classify(instructions, fee_payer):
    """Account ordering per the Solana message spec."""
    meta = {fee_payer: [True, True]}
    order = [fee_payer]
    for ins in instructions:
        for key, signer, writable in ins.accounts + [(ins.program, False, False)]:
            if key.startswith("alt:"):
                continue
            if key not in meta:
                meta[key] = [False, False]
                order.append(key)
            meta[key][0] |= signer
            meta[key][1] |= writable
    groups = {(True, True): [], (True, False): [], (False, True): [], (False, False): []}
    for key in order:
        groups[(meta[key][0], meta[key][1])].append(key)
    keys = (groups[(True, True)] + groups[(True, False)]
            + groups[(False, True)] + groups[(False, False)])
    header = (len(groups[(True, True)]) + len(groups[(True, False)]),
              len(groups[(True, False)]), len(groups[(False, False)]))
    return keys, header


def build_message(instructions, fee_payer, blockhash_label="blockhash", v0_lookups=None):
    """Return (message_bytes, ordered_static_keys, num_required_signatures).

    `v0_lookups` = [(table_label, [writable_indexes], [readonly_indexes])] produces a v0
    message. Instruction accounts that name "alt:<n>" refer to the n-th looked-up address
    (writable lookups first, then readonly), appended after the static keys.
    """
    static_ix = []
    alt_ix = []
    for ins in instructions:
        if any(isinstance(k, str) and k.startswith("alt:") for k, _, _ in ins.accounts):
            alt_ix.append(ins)
        static_ix.append(ins)
    keys, (n_sig, n_ro_signed, n_ro_unsigned) = _classify(
        [Instruction(i.program, [a for a in i.accounts if not a[0].startswith("alt:")], i.data)
         for i in instructions], fee_payer)
    index = {k: n for n, k in enumerate(keys)}
    total_lookup = 0
    if v0_lookups:
        total_lookup = sum(len(w) + len(r) for _, w, r in v0_lookups)
    body = bytes([n_sig, n_ro_signed, n_ro_unsigned]) + _shortvec(len(keys))
    body += b"".join(b58decode(k) for k in keys)
    body += hashlib.sha256(("hguet-bench-blockhash:" + blockhash_label).encode()).digest()
    body += _shortvec(len(instructions))
    for ins in instructions:
        ids = []
        for key, _, _ in ins.accounts:
            if key.startswith("alt:"):
                ids.append(len(keys) + int(key[4:]))
            else:
                ids.append(index[key])
        program_index = len(keys) + int(ins.program[4:]) if ins.program.startswith("alt:") else index[ins.program]
        body += bytes([program_index]) + _shortvec(len(ids)) + bytes(ids)
        body += _shortvec(len(ins.data)) + ins.data
    if v0_lookups is None:
        return body, keys, n_sig
    lookups = _shortvec(len(v0_lookups))
    for table, writable, readonly in v0_lookups:
        lookups += (b58decode(plain_pubkey("alt-table:" + table)) + _shortvec(len(writable))
                    + bytes(writable) + _shortvec(len(readonly)) + bytes(readonly))
    return b"\x80" + body + lookups, keys, n_sig


def build_transaction(instructions, fee_payer, signers=(), v0_lookups=None, blockhash_label="blockhash",
                      signature_mode="unsigned"):
    """signature_mode: unsigned | valid | invalid (non-zero garbage) | partial."""
    message, keys, n_sig = build_message(instructions, fee_payer, blockhash_label, v0_lookups)
    sigs = []
    for position in range(n_sig):
        key = keys[position]
        label = next((s for s in signers if signer_pubkey(s) == key), None)
        if signature_mode == "valid" and label:
            sigs.append(ed25519_sign(seed_for(label), message))
        elif signature_mode == "partial" and label and position == 0:
            sigs.append(ed25519_sign(seed_for(label), message))
        elif signature_mode == "invalid" and position == 0:
            sigs.append(bytes([7]) * 64)
        else:
            sigs.append(bytes(64))
    return _shortvec(n_sig) + b"".join(sigs) + message, message


# ----------------------------------------------------------- Intents
INTENT_DOMAIN = b"HGUET-PAYMENT-INTENT\0"


def intent_payload(message: bytes, *, network="devnet", intent_id="bench-intent", not_before=1,
                   expires=4102444800, allowed_programs=(SYSTEM,), max_spend="1000",
                   token_caps=None, source_caps=None, override_message_sha=None):
    body = {
        "schema_version": 1, "kind": "hguet_payment_intent", "intent_id": intent_id,
        "network": network,
        "message_sha256": override_message_sha or hashlib.sha256(message).hexdigest(),
        "not_before_unix": not_before, "expires_at_unix": expires,
        "allowed_program_ids": list(allowed_programs), "max_spend_lamports": max_spend,
    }
    if token_caps is not None:
        body["token_spend_limits"] = [{"mint": m, "max_debit_raw": r} for m, r in token_caps]
    if source_caps is not None:
        body["token_source_limits"] = [
            {"mint": m, "source_token_account": s, "authority": a, "max_debit_raw": r}
            for m, s, a, r in source_caps]
    return body


def sign_intent(payload: dict, issuer_label="issuer:trusted", *, tamper=False):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    signature = ed25519_sign(seed_for(issuer_label), INTENT_DOMAIN + raw)
    envelope_payload = raw
    if tamper:  # change a byte AFTER signing: cryptographic verification must fail
        envelope_payload = raw.replace(b'"max_spend_lamports":"', b'"max_spend_lamports":"9', 1)
    return {"payload_b64": base64.b64encode(envelope_payload).decode(),
            "signer_pubkey_b58": signer_pubkey(issuer_label),
            "signature_b58": b58encode(signature)}
