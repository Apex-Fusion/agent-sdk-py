"""Plutus Data and its CBOR form.

The encoder writes the same bytes as Aiken ``cbor.serialise`` and the Haskell
``encodeData`` of plutus-core (``PlutusCore.Data``):

- integers in [-2^64, 2^64 - 1] use CBOR major type 0 or 1 in the shortest
  form; other integers use the bignum tags 2 and 3 (RFC 8949 §3.4.3);
- byte strings of at most 64 bytes are definite; longer byte strings are
  indefinite, in chunks of 64 bytes;
- a non-empty list (and the fields of a constructor) is an indefinite array;
  an empty list is ``80``;
- a map is a definite map;
- constructor ``i`` uses tag ``121 + i`` for 0..6, tag ``1280 + (i - 7)`` for
  7..127, and else tag 102 with ``[i, fields]`` (CIP-0005 / plutus-core).

The decoder accepts every form that the ledger accepts for Plutus Data
(definite or indefinite arrays, maps and byte strings, any integer width). It
rejects other CBOR items, byte-string chunks over 64 bytes and trailing bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "Constr",
    "PlutusData",
    "PlutusDataError",
    "PlutusMap",
    "decode_data",
    "decode_data_hex",
    "encode_data",
    "encode_data_hex",
]

_MAX_DEPTH = 256
_CHUNK = 64


class PlutusDataError(ValueError):
    """CBOR that is not Plutus Data, or a value that cannot be Plutus Data."""


@dataclass(frozen=True)
class Constr:
    """A constructor application: ``Constr index fields``."""

    index: int
    fields: tuple[PlutusData, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.fields, tuple):
            object.__setattr__(self, "fields", tuple(self.fields))


@dataclass(frozen=True)
class PlutusMap:
    """A Plutus map: ordered key-value pairs (the ledger allows repeated keys)."""

    entries: tuple[tuple[PlutusData, PlutusData], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple):
            object.__setattr__(self, "entries", tuple(tuple(e) for e in self.entries))


PlutusData = int | bytes | list | PlutusMap | Constr


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def _encode_bytes(value: bytes, out: bytearray) -> None:
    if len(value) <= _CHUNK:
        out += _head(2, len(value))
        out += value
        return
    out.append(0x5F)
    for start in range(0, len(value), _CHUNK):
        chunk = value[start : start + _CHUNK]
        out += _head(2, len(chunk))
        out += chunk
    out.append(0xFF)


def _encode_int(value: int, out: bytearray) -> None:
    if 0 <= value < 1 << 64:
        out += _head(0, value)
    elif -(1 << 64) <= value < 0:
        out += _head(1, -1 - value)
    else:
        magnitude = value if value >= 0 else -1 - value
        out += _head(6, 2 if value >= 0 else 3)
        _encode_bytes(magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big"), out)


def _encode_list(items, out: bytearray, depth: int) -> None:
    if not items:
        out.append(0x80)
        return
    out.append(0x9F)
    for item in items:
        _encode(item, out, depth + 1)
    out.append(0xFF)


def _encode(value: PlutusData, out: bytearray, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise PlutusDataError("Plutus Data nested too deeply")
    if isinstance(value, bool):
        raise PlutusDataError("bool is not Plutus Data; use Constr(0) or Constr(1)")
    if isinstance(value, int):
        _encode_int(value, out)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        _encode_bytes(bytes(value), out)
    elif isinstance(value, Constr):
        index = value.index
        if index < 0:
            raise PlutusDataError(f"constructor index {index} is negative")
        if index <= 6:
            out += _head(6, 121 + index)
        elif index <= 127:
            out += _head(6, 1280 + index - 7)
        else:
            out += _head(6, 102)
            out.append(0x82)
            _encode_int(index, out)
        _encode_list(value.fields, out, depth)
    elif isinstance(value, (list, tuple)):
        _encode_list(value, out, depth)
    elif isinstance(value, PlutusMap):
        out += _head(5, len(value.entries))
        for key, item in value.entries:
            _encode(key, out, depth + 1)
            _encode(item, out, depth + 1)
    else:
        raise PlutusDataError(f"{type(value).__name__} is not Plutus Data")


def encode_data(value: PlutusData) -> bytes:
    """The CBOR bytes of ``value``, as Aiken ``cbor.serialise`` writes them."""
    out = bytearray()
    _encode(value, out, 0)
    return bytes(out)


def encode_data_hex(value: PlutusData) -> str:
    """Lowercase hex of :func:`encode_data`."""
    return encode_data(value).hex()


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise PlutusDataError("unexpected end of CBOR")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise PlutusDataError("unexpected end of CBOR")
        value = self.data[self.pos : self.pos + n]
        self.pos += n
        return value

    def peek_break(self) -> bool:
        if self.pos >= len(self.data):
            raise PlutusDataError("unexpected end of CBOR")
        if self.data[self.pos] == 0xFF:
            self.pos += 1
            return True
        return False

    def head(self) -> tuple[int, int | None]:
        """Major type and argument; the argument is None for indefinite length."""
        initial = self.byte()
        major, info = initial >> 5, initial & 0x1F
        if info < 24:
            return major, info
        if info in (24, 25, 26, 27):
            return major, int.from_bytes(self.take(1 << (info - 24)), "big")
        if info == 31 and major in (2, 3, 4, 5):
            return major, None
        raise PlutusDataError(f"unsupported CBOR initial byte 0x{initial:02x}")


def _decode_bytes(reader: _Reader, length: int | None) -> bytes:
    if length is not None:
        if length > _CHUNK:
            raise PlutusDataError(f"byte string of {length} bytes is not chunked")
        return reader.take(length)
    out = bytearray()
    while not reader.peek_break():
        major, chunk = reader.head()
        if major != 2 or chunk is None:
            raise PlutusDataError("indefinite byte string holds a non-byte-string chunk")
        if chunk > _CHUNK:
            raise PlutusDataError(f"byte-string chunk of {chunk} bytes (at most {_CHUNK})")
        out += reader.take(chunk)
    return bytes(out)


def _decode_items(reader: _Reader, length: int | None, depth: int) -> list:
    items = []
    if length is None:
        while not reader.peek_break():
            items.append(_decode(reader, depth + 1))
    else:
        for _ in range(length):
            items.append(_decode(reader, depth + 1))
    return items


def _decode_array(reader: _Reader, depth: int) -> list:
    major, length = reader.head()
    if major != 4:
        raise PlutusDataError("constructor fields must be an array")
    return _decode_items(reader, length, depth)


def _decode(reader: _Reader, depth: int) -> PlutusData:
    if depth > _MAX_DEPTH:
        raise PlutusDataError("Plutus Data nested too deeply")
    major, arg = reader.head()
    if major == 0:
        return arg
    if major == 1:
        return -1 - arg
    if major == 2:
        return _decode_bytes(reader, arg)
    if major == 4:
        return _decode_items(reader, arg, depth)
    if major == 5:
        entries = []
        if arg is None:
            while not reader.peek_break():
                entries.append((_decode(reader, depth + 1), _decode(reader, depth + 1)))
        else:
            for _ in range(arg):
                entries.append((_decode(reader, depth + 1), _decode(reader, depth + 1)))
        return PlutusMap(tuple(entries))
    if major == 6:
        tag = arg
        if 121 <= tag <= 127:
            return Constr(tag - 121, tuple(_decode_array(reader, depth)))
        if 1280 <= tag <= 1400:
            return Constr(tag - 1280 + 7, tuple(_decode_array(reader, depth)))
        if tag == 102:
            inner_major, inner_length = reader.head()
            if inner_major != 4 or inner_length != 2:
                raise PlutusDataError("tag 102 must hold a two-element array")
            index = _decode(reader, depth + 1)
            if not isinstance(index, int) or index < 0:
                raise PlutusDataError("tag 102 constructor index must be a non-negative integer")
            return Constr(index, tuple(_decode_array(reader, depth)))
        if tag in (2, 3):
            bmajor, blength = reader.head()
            if bmajor != 2:
                raise PlutusDataError("bignum tag must hold a byte string")
            magnitude = int.from_bytes(_decode_bytes(reader, blength), "big")
            return magnitude if tag == 2 else -1 - magnitude
        raise PlutusDataError(f"CBOR tag {tag} is not Plutus Data")
    raise PlutusDataError(f"CBOR major type {major} is not Plutus Data")


def decode_data(data: bytes) -> PlutusData:
    """Decode the CBOR of one Plutus Data value. Fails on trailing bytes."""
    reader = _Reader(bytes(data))
    value = _decode(reader, 0)
    if reader.pos != len(reader.data):
        raise PlutusDataError(f"{len(reader.data) - reader.pos} trailing bytes after Plutus Data")
    return value


def decode_data_hex(value: str) -> PlutusData:
    """Decode hex CBOR of one Plutus Data value."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise PlutusDataError(f"not hex: {exc}") from exc
    return decode_data(raw)
