"""Identifiers, DIDs, key hashes and the adoption allowlist.

- Identifier (Part 1 §3.1): ``vector-id = hex(blake2b_256(serialise(seed)))``,
  where ``serialise(seed)`` is the Plutus Data CBOR of ``Constr 0 [tx_id,
  output_index]``. Attestation and delegation token names use the same
  derivation (Part 2 §4.1, §5.2).
- DNS-safe form (Part 1 §3.2): RFC 4648 base32, lowercase, without padding.
- DID syntax (Part 1 §3, ABNF of RFC 5234 with RFC 7405 case-sensitive strings).
- Allowlist Merkle tree (Part 2 §3.4).
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from vector_agent.identity.plutus_data import Constr, encode_data

__all__ = [
    "ParsedDid",
    "allowlist_leaf",
    "allowlist_proof",
    "allowlist_root",
    "attestation_id",
    "blake2b_224",
    "blake2b_256",
    "delegation_id",
    "dns_safe",
    "is_vector_id",
    "key_hash",
    "legacy_vector_did",
    "parse_vector_did",
    "serialise_seed",
    "vector_did",
    "vector_did_key_url",
    "vector_id_from_seed",
    "verify_allowlist_proof",
]

_VECTOR_ID = re.compile(r"[0-9a-f]{64}")
_LOWHEX56 = re.compile(r"[0-9a-f]{56}")
_DID = re.compile(r"did:vector:(?:(testnet):|agent:([0-9a-f]{56}):)?([0-9a-f]{64})")


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=28).digest()


def _hex_bytes(value: bytes | str, size: int, name: str) -> bytes:
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != size:
        raise ValueError(f"{name}: expected {size} bytes, got {len(raw)}")
    return raw


def is_vector_id(value: object) -> bool:
    """True for 64 lowercase hexadecimal characters."""
    return isinstance(value, str) and _VECTOR_ID.fullmatch(value) is not None


def serialise_seed(tx_id: bytes | str, index: int) -> bytes:
    """``serialise(seed)``: ``D8 79 9F 58 20 <tx_id> <index> FF``."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ValueError("output index must be a non-negative integer")
    return encode_data(Constr(0, (_hex_bytes(tx_id, 32, "tx_id"), index)))


def vector_id_from_seed(tx_id: bytes | str, index: int) -> str:
    """The identifier that a registration spending ``tx_id#index`` gets (Part 1 §3.1)."""
    return blake2b_256(serialise_seed(tx_id, index)).hex()


#: The token name of an attestation or a delegation: the same seed derivation.
attestation_id = vector_id_from_seed
delegation_id = vector_id_from_seed


def dns_safe(vector_id: str) -> str:
    """RFC 4648 base32 of the 32 bytes, lowercase, without padding (52 characters)."""
    if not is_vector_id(vector_id):
        raise ValueError("expected a vector-id: 64 lowercase hexadecimal characters")
    return base64.b32encode(bytes.fromhex(vector_id)).decode("ascii").rstrip("=").lower()


def key_hash(public_key: bytes | str) -> str:
    """``blake2b_224`` of an Ed25519 (32-byte) or compressed P-256 (33-byte) key."""
    raw = bytes.fromhex(public_key) if isinstance(public_key, str) else bytes(public_key)
    if len(raw) not in (32, 33):
        raise ValueError(f"public key: expected 32 or 33 bytes, got {len(raw)}")
    return blake2b_224(raw).hex()


def vector_did(vector_id: str) -> str:
    """The canonical DID ``did:vector:<vector-id>``."""
    if not is_vector_id(vector_id):
        raise ValueError("expected a vector-id: 64 lowercase hexadecimal characters")
    return f"did:vector:{vector_id}"


def legacy_vector_did(policy_id: str, vector_id: str) -> str:
    """The legacy form ``did:vector:agent:<policy>:<vector-id>``."""
    if not isinstance(policy_id, str) or _LOWHEX56.fullmatch(policy_id) is None:
        raise ValueError("expected a policy ID: 56 lowercase hexadecimal characters")
    if not is_vector_id(vector_id):
        raise ValueError("expected a vector-id: 64 lowercase hexadecimal characters")
    return f"did:vector:agent:{policy_id}:{vector_id}"


def vector_did_key_url(vector_id: str, public_key: bytes | str) -> str:
    """``did:vector:<vector-id>#<key hash>``: the DID URL of a listed key."""
    return f"{vector_did(vector_id)}#{key_hash(public_key)}"


@dataclass(frozen=True)
class ParsedDid:
    """A DID that matches Part 1 §3. ``form`` is ``canonical``, ``legacy`` or ``network``."""

    form: str
    vector_id: str
    policy_id: str | None = None
    network: str | None = None


def parse_vector_did(did: str) -> ParsedDid | None:
    """Parse a ``did:vector`` DID; None when it does not match the ABNF (all lowercase)."""
    if not isinstance(did, str):
        return None
    match = _DID.fullmatch(did)
    if match is None:
        return None
    network, policy_id, vector_id = match.groups()
    if network is not None:
        return ParsedDid("network", vector_id, network=network)
    if policy_id is not None:
        return ParsedDid("legacy", vector_id, policy_id=policy_id)
    return ParsedDid("canonical", vector_id)


# ---------------------------------------------------------------------------
# Allowlist Merkle tree (Part 2 §3.4)
# ---------------------------------------------------------------------------


def _node(left: bytes, right: bytes) -> bytes:
    return blake2b_256(min(left, right) + max(left, right))


def allowlist_leaf(vector_id: str) -> bytes:
    """``blake2b_256(id)`` of the 32 identifier bytes."""
    return blake2b_256(_hex_bytes(vector_id, 32, "vector_id"))


def _levels(ids: Iterable[str]) -> list[list[bytes]]:
    leaves = sorted(allowlist_leaf(i) for i in ids)
    if not leaves:
        raise ValueError("the allowlist is empty")
    if len(set(leaves)) != len(leaves):
        raise ValueError("the allowlist lists an identifier twice")
    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        upper = [_node(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2:
            upper.append(current[-1])  # a last node without a pair moves up unchanged
        levels.append(upper)
    return levels


def allowlist_root(ids: Iterable[str]) -> bytes:
    """The Merkle root of the allowlist."""
    return _levels(ids)[-1][0]


def allowlist_proof(ids: Iterable[str], vector_id: str) -> list[bytes]:
    """The paired nodes from the leaf of ``vector_id`` upward."""
    levels = _levels(ids)
    leaf = allowlist_leaf(vector_id)
    try:
        position = levels[0].index(leaf)
    except ValueError:
        raise ValueError(f"{vector_id} is not on the allowlist") from None
    proof = []
    for level in levels[:-1]:
        sibling = position ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        position //= 2
    return proof


def verify_allowlist_proof(root: bytes | str, vector_id: str, proof: Sequence[bytes]) -> bool:
    """The on-chain check: fold the proof from ``blake2b_256(id)`` and compare with the root."""
    node = allowlist_leaf(vector_id)
    for sibling in proof:
        node = _node(node, bytes(sibling))
    return node == _hex_bytes(root, 32, "root")
