"""Plutus-compatible CBOR serialization.

Aiken/Plutus uses indefinite-length CBOR arrays for constructor fields
(non-empty constructors) and definite-length empty arrays for nullary
constructors.  Python's ``cbor2`` library uses definite-length arrays by
default, producing different bytes and therefore different hashes.

This module provides helpers that match the on-chain serialization exactly.

Evidence from Aiken stdlib (``cbor.test.ak``):

- ``serialise(Some(42)) == #"d8799f182aff"``  → indefinite array (``9f … ff``)
- ``serialise(None)     == #"d87a80"``         → definite empty array (``80``)
"""

from __future__ import annotations

import cbor2


def plutus_serialise_data(tag: int, fields: list) -> bytes:
    """Serialize a Plutus Data constructor matching Aiken's ``builtin.serialise_data()``.

    For constructor indices 0–6 the CBOR tag is ``121 + index``.

    Non-empty fields are encoded as an **indefinite-length** array::

        Tag(121+n) + 0x9f + field₁_cbor + field₂_cbor + … + 0xff

    Empty fields use a **definite-length** empty array::

        Tag(121+n) + 0x80

    Args:
        tag: Constructor index (0 → Tag 121, 1 → Tag 122, …).
        fields: Plutus Data field values (``bytes``, ``int``, or nested
                ``cbor2.CBORTag`` for nested constructors).
    """
    cbor_tag = 121 + tag
    if not fields:
        return cbor2.dumps(cbor2.CBORTag(cbor_tag, []))

    result = bytearray()
    result += b"\xd8" + bytes([cbor_tag])  # Tag header
    result += b"\x9f"  # indefinite-length array start
    for field in fields:
        if isinstance(field, cbor2.CBORTag):
            # Nested constructor — recurse
            inner_tag = field.tag - 121
            inner_fields = field.value if isinstance(field.value, list) else [field.value]
            result += plutus_serialise_data(inner_tag, inner_fields)
        else:
            result += cbor2.dumps(field)
    result += b"\xff"  # break
    return bytes(result)
