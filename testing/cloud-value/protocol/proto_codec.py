"""Protobuf wire codec DERIVED FROM protocol/v1/hguet.proto (no second protocol, no schema fork).

The public .proto is parsed at import time; messages, enums, field numbers and `oneof` groups come
from that file only. If the file changes, this codec changes with it. Scope: exactly what the proto
uses (proto3; string, bytes, bool, uint32, enums, nested messages, repeated, oneof). Decoding is
strict: unknown fields, wrong wire types, truncation and oversize frames are errors (the protocol
defines ERROR_UNKNOWN_CRITICAL_FIELD; silently skipping fields is not acceptable for a verifier).

Framing (proto comment and cloud-protocol.md): 4-byte unsigned big-endian length + exactly one
`Envelope`, maximum 1 MiB.
"""
import re
import struct
from pathlib import Path

PROTO_PATH = Path(__file__).resolve().parents[3] / "protocol/v1/hguet.proto"
MAX_FRAME = 1 << 20
SCALARS = {"string", "bytes", "bool", "uint32", "uint64"}
VARINT, LEN = 0, 2


class ProtoError(ValueError):
    pass


def _strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def parse_proto(text):
    text = _strip_comments(text)
    enums, messages = {}, {}
    for match in re.finditer(r"enum\s+(\w+)\s*\{(.*?)\}", text, re.S):
        enums[match.group(1)] = {name: int(num) for name, num in re.findall(r"(\w+)\s*=\s*(\d+)\s*;", match.group(2))}
    for match in re.finditer(r"message\s+(\w+)\s*\{", text):
        start, depth, i = match.end(), 1, match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        body = text[start:i - 1]
        fields, oneofs = {}, {}
        for one in re.finditer(r"oneof\s+(\w+)\s*\{(.*?)\}", body, re.S):
            members = []
            for typ, name, num in re.findall(r"(\w+)\s+(\w+)\s*=\s*(\d+)\s*;", one.group(2)):
                fields[int(num)] = {"name": name, "type": typ, "repeated": False, "oneof": one.group(1)}
                members.append(name)
            oneofs[one.group(1)] = members
        body_no_oneof = re.sub(r"oneof\s+\w+\s*\{.*?\}", "", body, flags=re.S)
        for rep, typ, name, num in re.findall(r"(repeated\s+)?(\w+)\s+(\w+)\s*=\s*(\d+)\s*;", body_no_oneof):
            fields[int(num)] = {"name": name, "type": typ, "repeated": bool(rep), "oneof": None}
        messages[match.group(1)] = {"fields": fields, "oneofs": oneofs}
    if not messages:
        raise ProtoError("no messages parsed from the public proto")
    return {"enums": enums, "messages": messages}


SCHEMA = parse_proto(PROTO_PATH.read_text(encoding="utf-8"))


def _varint(value):
    if value < 0:
        raise ProtoError("negative varint")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _read_varint(data, pos):
    shift = result = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ProtoError("truncated or oversized varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _is_numeric(typ):
    return typ in ("uint32", "uint64", "bool") or typ in SCHEMA["enums"]


def _encode_scalar(typ, value):
    if typ == "string":
        return LEN, _varint(len(value.encode())) + value.encode()
    if typ == "bytes":
        if not isinstance(value, (bytes, bytearray)):
            raise ProtoError("bytes field needs bytes")
        return LEN, _varint(len(value)) + bytes(value)
    if typ == "bool":
        return VARINT, _varint(1 if value else 0)
    if typ in SCHEMA["enums"]:
        if isinstance(value, str):
            value = SCHEMA["enums"][typ][value]
        return VARINT, _varint(int(value))
    if typ == "uint32":
        if not 0 <= int(value) < 1 << 32:
            raise ProtoError("uint32 out of range")
    return VARINT, _varint(int(value))


def encode(message, value):
    spec = SCHEMA["messages"][message]
    out = bytearray()
    chosen = {}
    for number in sorted(spec["fields"]):
        field = spec["fields"][number]
        name, typ = field["name"], field["type"]
        if name not in value or value[name] is None:
            continue
        if field["oneof"]:
            if chosen.get(field["oneof"]):
                raise ProtoError("two members of oneof %s set" % field["oneof"])
            chosen[field["oneof"]] = name
        items = value[name] if field["repeated"] else [value[name]]
        if field["repeated"] and _is_numeric(typ) and items:
            payload = b"".join(_encode_scalar(typ, v)[1] for v in items)
            out += _varint(number << 3 | LEN) + _varint(len(payload)) + payload  # proto3 packs numerics
            continue
        for item in items:
            if typ in SCHEMA["messages"]:
                payload = encode(typ, item)
                out += _varint(number << 3 | LEN) + _varint(len(payload)) + payload
                continue
            wire, body = _encode_scalar(typ, item)
            if not field["repeated"] and not field["oneof"] and _is_default(typ, item):
                continue  # proto3 omits scalar defaults
            out += _varint(number << 3 | wire) + body
    return bytes(out)


def _is_default(typ, value):
    if typ in ("string",):
        return value == ""
    if typ == "bytes":
        return len(value) == 0
    if typ == "bool":
        return not value
    if typ in SCHEMA["enums"]:
        return (SCHEMA["enums"][typ][value] if isinstance(value, str) else int(value)) == 0
    return int(value) == 0


def decode(message, data, *, _depth=0):
    if _depth > 8:
        raise ProtoError("nesting too deep")
    spec, pos, out = SCHEMA["messages"][message], 0, {}
    oneof_seen = {}
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        field = spec["fields"].get(number)
        if field is None:
            raise ProtoError("unknown field %d in %s (critical: refusing to skip)" % (number, message))
        typ, name = field["type"], field["name"]
        values = []
        if wire == VARINT:
            if not _is_numeric(typ):
                raise ProtoError("wire type mismatch for %s.%s" % (message, name))
            raw, pos = _read_varint(data, pos)
            values.append(raw)
        elif wire == LEN:
            length, pos = _read_varint(data, pos)
            chunk = data[pos:pos + length]
            if len(chunk) != length:
                raise ProtoError("truncated length-delimited field")
            pos += length
            if typ == "string":
                values.append(chunk.decode("utf-8"))
            elif typ == "bytes":
                values.append(bytes(chunk))
            elif typ in SCHEMA["messages"]:
                values.append(decode(typ, chunk, _depth=_depth + 1))
            elif _is_numeric(typ) and field["repeated"]:
                inner = 0
                while inner < len(chunk):
                    raw, inner = _read_varint(chunk, inner)
                    values.append(raw)
            else:
                raise ProtoError("wire type mismatch for %s.%s" % (message, name))
        else:
            raise ProtoError("unsupported wire type %d" % wire)
        converted = []
        for raw in values:
            if typ == "bool":
                converted.append(bool(raw))
            elif typ in SCHEMA["enums"]:
                names = {v: k for k, v in SCHEMA["enums"][typ].items()}
                if raw not in names:
                    raise ProtoError("unknown enum value %d for %s" % (raw, typ))
                converted.append(names[raw])
            elif typ == "uint32" and isinstance(raw, int) and raw >= 1 << 32:
                raise ProtoError("uint32 overflow")
            else:
                converted.append(raw)
        if field["oneof"]:
            if oneof_seen.get(field["oneof"]) not in (None, name):
                raise ProtoError("two members of oneof %s present" % field["oneof"])
            oneof_seen[field["oneof"]] = name
        if field["repeated"]:
            out.setdefault(name, []).extend(converted)
        else:
            out[name] = converted[-1]
    return out


def frame(envelope_bytes):
    if len(envelope_bytes) > MAX_FRAME:
        raise ProtoError("frame exceeds 1 MiB")
    return struct.pack(">I", len(envelope_bytes)) + envelope_bytes


def read_frame(read_exact):
    """`read_exact(n)` must return exactly n bytes or raise. Rejects oversize before reading the body."""
    (length,) = struct.unpack(">I", read_exact(4))
    if length == 0 or length > MAX_FRAME:
        raise ProtoError("invalid frame length %d" % length)
    return read_exact(length)


def new_envelope(payload_name, payload, request_id, major=1, minor=0):
    if len(request_id) != 16:
        raise ProtoError("request_id must be exactly 16 bytes")
    return {"protocol_major": major, "protocol_minor": minor, "request_id": request_id, payload_name: payload}


def envelope_payload(envelope):
    names = [n for n in SCHEMA["messages"]["Envelope"]["oneofs"]["payload"] if n in envelope]
    if len(names) != 1:
        raise ProtoError("Envelope must carry exactly one payload")
    return names[0], envelope[names[0]]
