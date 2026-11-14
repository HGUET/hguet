"""Protobuf wire codec DERIVED FROM protocol/v1/hguet.proto (no second protocol, no schema fork).

The public .proto is parsed at import time; messages, enums, field numbers and `oneof` groups come
from that file only. If the file changes, this codec changes with it. Scope: exactly what the proto
uses (proto3; string, bytes, bool, uint32, enums, nested messages, repeated, oneof). Decoding is
strict, following the S7.1 critical/unknown-field policy (HGUET/server docs/architecture/canonical-contract-s7.md):
an unknown field number >= 1000 is a non-critical extension and is skipped; any other unknown field is critical;
field number 0, group wire types, truncation, overlong varints, duplicate singular fields, `oneof` conflicts, wire
type mismatches, invalid UTF-8, bool not in {0,1}, uint32 overflow and undefined enum values are errors. Every error
carries a stable `code` shared with the server's golden vectors.

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


EXTENSION_FLOOR = 1000
MAX_DEPTH = 6


class ProtoError(ValueError):
    def __init__(self, message, code="PROTO_ERROR"):
        super().__init__(message)
        self.code = code


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
    start = pos
    shift = result = 0
    while True:
        if pos >= len(data):
            raise ProtoError("truncated varint", "PROTO_TRUNCATED")
        if shift > 63:
            raise ProtoError("oversized varint", "PROTO_OVERLONG_VARINT")
        byte = data[pos]
        pos += 1
        result = (result | ((byte & 0x7F) << shift)) & 0xFFFFFFFFFFFFFFFF
        if not byte & 0x80:
            if pos - start > 1 and byte == 0:
                raise ProtoError("non-minimal varint", "PROTO_OVERLONG_VARINT")
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


def _check_scalar(typ, raw):
    if typ == "bool" and raw > 1:
        raise ProtoError("bool is not 0 or 1", "PROTO_INVALID_BOOL")
    if typ == "uint32" and raw >= 1 << 32:
        raise ProtoError("uint32 overflow", "PROTO_INTEGER_OVERFLOW")
    if typ in SCHEMA["enums"] and raw not in SCHEMA["enums"][typ].values():
        raise ProtoError("unknown enum value %d for %s" % (raw, typ), "PROTO_UNKNOWN_ENUM_VALUE")


def decode(message, data, *, _depth=0):
    if _depth == 0 and len(data) > MAX_FRAME:
        raise ProtoError("envelope exceeds 1 MiB", "PROTO_FRAME_TOO_LARGE")
    if _depth > MAX_DEPTH:
        raise ProtoError("nesting too deep", "PROTO_DEPTH")
    spec, pos, out = SCHEMA["messages"][message], 0, {}
    oneof_seen, singular_seen = {}, set()
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ProtoError("field number 0", "PROTO_FIELD_NUMBER_ZERO")
        if wire in (3, 4):
            raise ProtoError("group wire type", "PROTO_GROUP_WIRE_TYPE")
        if wire not in (0, 1, 2, 5):
            raise ProtoError("unsupported wire type %d" % wire, "PROTO_WIRE_TYPE_MISMATCH")
        field = spec["fields"].get(number)
        raw, chunk = 0, b""
        if wire == VARINT:
            raw, pos = _read_varint(data, pos)
        elif wire in (1, 5):
            width = 8 if wire == 1 else 4
            if pos + width > len(data):
                raise ProtoError("truncated fixed-width field", "PROTO_TRUNCATED")
            pos += width
        else:
            length, pos = _read_varint(data, pos)
            if length > len(data) - pos:
                raise ProtoError("truncated length-delimited field", "PROTO_TRUNCATED")
            chunk = data[pos:pos + length]
            pos += length
        if field is None:
            if number >= EXTENSION_FLOOR:
                continue  # non-critical extension: skipped, never interpreted
            raise ProtoError("unknown critical field %d in %s" % (number, message), "PROTO_UNKNOWN_CRITICAL_FIELD")
        typ, name = field["type"], field["name"]
        if not field["repeated"]:
            if number in singular_seen:
                raise ProtoError("duplicate singular field %s.%s" % (message, name), "PROTO_DUPLICATE_FIELD")
            singular_seen.add(number)
        if field["oneof"]:
            if oneof_seen.get(field["oneof"]) not in (None, number):
                raise ProtoError("two members of oneof %s present" % field["oneof"], "PROTO_ONEOF_CONFLICT")
            oneof_seen[field["oneof"]] = number
        values = []
        if wire == VARINT:
            if not _is_numeric(typ):
                raise ProtoError("wire type mismatch for %s.%s" % (message, name), "PROTO_WIRE_TYPE_MISMATCH")
            _check_scalar(typ, raw)
            values.append(raw)
        elif wire == LEN:
            if typ == "string":
                try:
                    values.append(chunk.decode("utf-8"))
                except UnicodeDecodeError:
                    raise ProtoError("invalid UTF-8 in %s.%s" % (message, name), "PROTO_INVALID_UTF8") from None
            elif typ == "bytes":
                values.append(bytes(chunk))
            elif typ in SCHEMA["messages"]:
                values.append(decode(typ, chunk, _depth=_depth + 1))
            elif _is_numeric(typ) and field["repeated"]:
                inner = 0
                while inner < len(chunk):
                    item, inner = _read_varint(chunk, inner)
                    _check_scalar(typ, item)
                    values.append(item)
            else:
                raise ProtoError("wire type mismatch for %s.%s" % (message, name), "PROTO_WIRE_TYPE_MISMATCH")
        else:
            raise ProtoError("wire type mismatch for %s.%s" % (message, name), "PROTO_WIRE_TYPE_MISMATCH")
        converted = []
        for item in values:
            if typ == "bool":
                converted.append(bool(item))
            elif typ in SCHEMA["enums"]:
                converted.append({v: k for k, v in SCHEMA["enums"][typ].items()}[item])
            else:
                converted.append(item)
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
