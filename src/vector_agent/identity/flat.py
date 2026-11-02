"""Parameter application for Plutus V3 scripts, without a UPLC toolchain.

A blueprint ``compiledCode`` (CIP-57) is one CBOR byte string around a
flat-encoded UPLC program. ``aiken blueprint apply`` turns the program
``(program v term)`` into ``(program v [term (con data parameter)])``.
:func:`apply_parameter` does the same.

Flat encoding: Plutus Core specification, appendix "Serialising Plutus Core
terms and programs using the flat format"
(https://plutus.cardano.intersectmbo.org/resources/plutus-core-spec.pdf,
Plutus Core 1.1.0). The applied term starts 4 bits later than the original
term (after the Apply tag), so the padding before each byte-string constant
changes. The transcoder copies every other bit unchanged and writes each
padding again for its new position. The test suite checks the result against
``aiken blueprint apply`` (Aiken v1.1.21).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from vector_agent.identity.plutus_data import PlutusData, encode_data

__all__ = ["FlatError", "apply_parameter", "apply_parameters", "plutus_v3_script_hash"]

PLUTUS_V3_TAG = b"\x03"

_TERM_VAR, _TERM_DELAY, _TERM_LAMBDA, _TERM_APPLY, _TERM_CONSTANT = 0, 1, 2, 3, 4
_TERM_FORCE, _TERM_ERROR, _TERM_BUILTIN, _TERM_CONSTR, _TERM_CASE = 5, 6, 7, 8, 9

_TYPE_INTEGER, _TYPE_BYTESTRING, _TYPE_STRING, _TYPE_UNIT, _TYPE_BOOL = 0, 1, 2, 3, 4
_TYPE_LIST, _TYPE_PAIR, _TYPE_APPLY, _TYPE_DATA = 5, 6, 7, 8


class FlatError(ValueError):
    """The script is not a valid flat-encoded program in a CBOR byte string."""


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.length = len(data) * 8

    def bit(self) -> int:
        if self.pos >= self.length:
            raise FlatError("flat: unexpected end of program")
        value = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return value

    def filler(self) -> None:
        """Padding ``0* 1`` up to a byte boundary."""
        while self.bit() == 0:
            pass
        if self.pos % 8:
            raise FlatError("flat: padding does not end at a byte boundary")


class _BitWriter:
    def __init__(self) -> None:
        self.out = bytearray()
        self.current = 0
        self.used = 0

    def bit(self, value: int) -> None:
        self.current = (self.current << 1) | (value & 1)
        self.used += 1
        if self.used == 8:
            self.out.append(self.current)
            self.current = 0
            self.used = 0

    def bits(self, value: int, count: int) -> None:
        for shift in range(count - 1, -1, -1):
            self.bit((value >> shift) & 1)

    def filler(self) -> None:
        """Padding ``0* 1``: the byte ends with the 1 bit (0x01 when already aligned)."""
        while self.used != 7:
            self.bit(0)
        self.bit(1)

    def result(self) -> bytes:
        if self.used:
            raise FlatError("flat: output does not end at a byte boundary")
        return bytes(self.out)


class _Transcoder:
    """Reads flat bits and writes the same value at the writer's position."""

    def __init__(self, reader: _BitReader, writer: _BitWriter) -> None:
        self.reader = reader
        self.writer = writer

    def bits(self, count: int) -> int:
        value = 0
        for _ in range(count):
            bit = self.reader.bit()
            self.writer.bit(bit)
            value = (value << 1) | bit
        return value

    def natural(self) -> None:
        """7-bit blocks, least significant first, each after a "more blocks" bit."""
        while self.bits(1) == 1:
            self.bits(7)
        self.bits(7)

    def bytestring(self) -> None:
        """Padding, then chunks of 1..255 bytes after their length byte, then a 0 byte."""
        self.reader.filler()
        self.writer.filler()
        size = self.bits(8)
        while size:
            for _ in range(size):
                self.bits(8)
            size = self.bits(8)

    def constant_type(self) -> tuple:
        tags = []
        while self.bits(1) == 1:
            tags.append(self.bits(4))
        position = 0

        def parse() -> tuple:
            nonlocal position
            if position >= len(tags):
                raise FlatError("flat: constant type ends early")
            tag = tags[position]
            position += 1
            if tag in (_TYPE_INTEGER, _TYPE_BYTESTRING, _TYPE_STRING, _TYPE_UNIT, _TYPE_BOOL, _TYPE_DATA):
                return (tag,)
            if tag == _TYPE_APPLY and position < len(tags):
                operator = tags[position]
                position += 1
                if operator == _TYPE_LIST:
                    return (_TYPE_LIST, parse())
                if operator == _TYPE_APPLY and position < len(tags) and tags[position] == _TYPE_PAIR:
                    position += 1
                    first = parse()
                    return (_TYPE_PAIR, first, parse())
            raise FlatError(f"flat: unsupported constant type tag {tag}")

        constant_type = parse()
        if position != len(tags):
            raise FlatError("flat: constant type has trailing tags")
        return constant_type

    def constant_value(self, constant_type: tuple) -> None:
        kind = constant_type[0]
        if kind == _TYPE_INTEGER:
            self.natural()
        elif kind in (_TYPE_BYTESTRING, _TYPE_STRING, _TYPE_DATA):
            self.bytestring()
        elif kind == _TYPE_UNIT:
            return
        elif kind == _TYPE_BOOL:
            self.bits(1)
        elif kind == _TYPE_LIST:
            while self.bits(1) == 1:
                self.constant_value(constant_type[1])
        else:  # pair
            self.constant_value(constant_type[1])
            self.constant_value(constant_type[2])

    def term(self) -> None:
        """One term. Iterative, so a deep program needs no deep call stack."""
        term, term_list = 0, 1
        work = [term]
        while work:
            if work.pop() == term_list:
                if self.bits(1) == 1:
                    work.extend((term_list, term))
                continue
            tag = self.bits(4)
            if tag == _TERM_VAR:
                self.natural()
            elif tag in (_TERM_DELAY, _TERM_LAMBDA, _TERM_FORCE):
                work.append(term)  # a de Bruijn binder has no bits
            elif tag == _TERM_APPLY:
                work.extend((term, term))
            elif tag == _TERM_CONSTANT:
                self.constant_value(self.constant_type())
            elif tag == _TERM_ERROR:
                pass
            elif tag == _TERM_BUILTIN:
                self.bits(7)
            elif tag == _TERM_CONSTR:
                self.natural()
                work.append(term_list)
            elif tag == _TERM_CASE:
                work.extend((term_list, term))
            else:
                raise FlatError(f"flat: unknown term tag {tag}")


def _cbor_bytes_header(length: int) -> bytes:
    if length < 24:
        return bytes([0x40 | length])
    if length < 0x100:
        return bytes([0x58, length])
    if length < 0x10000:
        return bytes([0x59]) + length.to_bytes(2, "big")
    return bytes([0x5A]) + length.to_bytes(4, "big")


def _unwrap(compiled_code: bytes) -> bytes:
    """The flat program inside ``compiled_code`` (one definite CBOR byte string)."""
    if not compiled_code or compiled_code[0] >> 5 != 2:
        raise FlatError("compiledCode: expected a CBOR byte string")
    info = compiled_code[0] & 0x1F
    offset = 1
    if info < 24:
        length = info
    elif info <= 26:
        width = 1 << (info - 24)
        length = int.from_bytes(compiled_code[1 : 1 + width], "big")
        offset += width
    else:
        raise FlatError("compiledCode: expected a definite-length CBOR byte string")
    if offset + length != len(compiled_code):
        raise FlatError("compiledCode: CBOR byte string length does not match")
    return compiled_code[offset:]


def apply_parameter(compiled_code: bytes, parameter: PlutusData) -> bytes:
    """``compiled_code`` with one Plutus Data parameter applied, as ``aiken blueprint apply`` does."""
    reader = _BitReader(_unwrap(bytes(compiled_code)))
    writer = _BitWriter()
    copy = _Transcoder(reader, writer)
    copy.natural()  # version: major
    copy.natural()  # minor
    copy.natural()  # patch
    writer.bits(_TERM_APPLY, 4)
    copy.term()
    reader.filler()
    if reader.pos != reader.length:
        raise FlatError("flat: trailing bytes after the program")
    writer.bits(_TERM_CONSTANT, 4)
    writer.bit(1)  # type list [data]: one element ...
    writer.bits(_TYPE_DATA, 4)
    writer.bit(0)  # ... then the end of the list
    data = encode_data(parameter)
    writer.filler()
    for start in range(0, len(data), 255):
        chunk = data[start : start + 255]
        writer.bits(len(chunk), 8)
        for byte in chunk:
            writer.bits(byte, 8)
    writer.bits(0, 8)
    writer.filler()
    applied = writer.result()
    return _cbor_bytes_header(len(applied)) + applied


def apply_parameters(compiled_code: bytes, parameters: Sequence[PlutusData]) -> bytes:
    """Apply ``parameters`` in order: the first parameter of the validator first."""
    code = bytes(compiled_code)
    for parameter in parameters:
        code = apply_parameter(code, parameter)
    return code


def plutus_v3_script_hash(compiled_code: bytes) -> bytes:
    """``blake2b_224(0x03 || compiled_code)``: the script hash and policy ID."""
    return hashlib.blake2b(PLUTUS_V3_TAG + bytes(compiled_code), digest_size=28).digest()
