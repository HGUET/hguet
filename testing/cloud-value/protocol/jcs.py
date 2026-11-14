"""RFC 8785 (JCS) canonical JSON for the value types HGUET payloads use.

Supported: objects, arrays, strings, integers within +-(2^53-1), booleans, null, and plain decimal
floats (no exponent form; evidence fixtures carry confidences such as 0.95). Signed payloads
themselves use integers only. Anything whose ES6 serialisation could differ is REFUSED, so a payload
can never silently canonicalise differently across implementations. Keys sort by UTF-16
code units per the RFC; strings use the minimal JSON escaping the RFC requires.
"""
import json

MAX_SAFE_INT = (1 << 53) - 1


class JcsError(ValueError):
    pass


def _string(value):
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _refuse_float():
    raise JcsError("float needs exponent notation: outside the supported canonical range")


def _emit(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise JcsError("integer outside the IEEE-754 safe range")
        return str(value)
    if isinstance(value, float):
        # ES6 Number::toString agrees with Python's shortest repr for finite values in [1e-6, 1e21)
        # that do not need an exponent. Anything else is refused rather than risk a divergent encoding.
        if value != value or value in (float("inf"), float("-inf")):
            raise JcsError("non-finite number")
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value)) if abs(value) <= MAX_SAFE_INT else _refuse_float()
        text = repr(value)
        if "e" in text or "E" in text or not (1e-6 <= abs(value) < 1e21):
            return _refuse_float()
        return text
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_emit(v) for v in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JcsError("object keys must be strings")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _emit(v) for k, v in items) + "}"
    raise JcsError("unsupported type %s" % type(value).__name__)


def canonicalize(value) -> bytes:
    return _emit(value).encode("utf-8")


def _reject_duplicates(pairs):
    seen = {}
    for key, val in pairs:
        if key in seen:
            raise JcsError("duplicate object key %r" % key)
        seen[key] = val
    return seen


def parse_strict(data: bytes):
    """Parse JSON rejecting duplicate keys, NaN/Infinity and floats."""
    def no_float(text):
        raise JcsError("floats are not accepted in signed payloads")

    def no_const(text):
        raise JcsError("non-finite number")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates, parse_float=no_float,
                      parse_constant=no_const)


def is_canonical(data: bytes) -> bool:
    """True iff `data` is byte-for-byte the JCS form of what it parses to."""
    try:
        return canonicalize(parse_strict(data)) == data
    except (JcsError, ValueError, UnicodeDecodeError):
        return False
