"""Identifiers, DIDs, key hashes and the allowlist tree (Part 1 §3, Part 2 §3.4)."""

from __future__ import annotations

import pytest

from vector_agent.identity import (
    allowlist_proof,
    allowlist_root,
    dns_safe,
    key_hash,
    legacy_vector_did,
    parse_vector_did,
    vector_did,
    vector_id_from_seed,
    verify_allowlist_proof,
)
from vector_agent.identity.ids import allowlist_leaf, blake2b_256, serialise_seed

ID_ZERO = "a2e5e227858e84f1a8f9b0c1246e6cbc9336d707d43ba43d0e1cb7c51c45f4c9"
ID_AB = "3ddd07517205dd8a745887c33a09da0e4a5d63dca1f151ceeedaeeda0551c52b"
LEGACY = "be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"


def test_part1_identifier_vectors() -> None:
    assert serialise_seed(bytes(32), 0).hex() == "d8799f5820" + "00" * 32 + "00ff"
    assert serialise_seed(bytes([0xAB]) * 32, 24).hex() == "d8799f5820" + "ab" * 32 + "1818ff"
    assert vector_id_from_seed(bytes(32), 0) == ID_ZERO
    assert vector_id_from_seed("ab" * 32, 24) == ID_AB


def test_part1_dns_safe_vectors() -> None:
    assert dns_safe(ID_ZERO) == "uls6ej4fr2cpdkhzwdasi3tmxsjtnvyh2q52ipiods34khcf6teq"
    assert dns_safe(ID_AB) == "hxoqoulsaxoyu5cyq7btuco2bzff2y64uhyvdtxo3lxnubkryuvq"
    with pytest.raises(ValueError):
        dns_safe(ID_ZERO.upper())


def test_dids() -> None:
    assert vector_did(ID_ZERO) == f"did:vector:{ID_ZERO}"
    assert legacy_vector_did(LEGACY, ID_ZERO) == f"did:vector:agent:{LEGACY}:{ID_ZERO}"
    assert parse_vector_did(f"did:vector:{ID_ZERO}").form == "canonical"
    legacy = parse_vector_did(f"did:vector:agent:{LEGACY}:{ID_ZERO}")
    assert legacy.form == "legacy" and legacy.policy_id == LEGACY and legacy.vector_id == ID_ZERO
    assert parse_vector_did(f"did:vector:testnet:{ID_ZERO}").network == "testnet"
    for bad in (f"did:vector:{ID_ZERO.upper()}", f"did:vector:{ID_ZERO}0", "did:web:example.org", f"DID:vector:{ID_ZERO}"):
        assert parse_vector_did(bad) is None
    with pytest.raises(ValueError):
        vector_did("00")


def test_key_hash() -> None:
    assert key_hash(bytes(32)) == "f9dca21a6c826ec8acb4cf395cbc24351937bfe6560b2683ab8b415f"
    assert key_hash((bytes(33)).hex()) == "489cfecfec6eb8710b4fde13ef6344e814ad4a2c0d65af7b90c6e165"
    with pytest.raises(ValueError):
        key_hash(bytes(31))


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 13])
def test_allowlist_proofs(count: int) -> None:
    ids = [vector_id_from_seed(bytes([i]) * 32, i) for i in range(count)]
    root = allowlist_root(ids)
    for vector_id in ids:
        proof = allowlist_proof(ids, vector_id)
        assert verify_allowlist_proof(root, vector_id, proof)
        assert not verify_allowlist_proof(root, ID_AB, proof)
    if count == 1:
        assert root == allowlist_leaf(ids[0])
    if count == 3:
        leaves = sorted(allowlist_leaf(i) for i in ids)
        pair = blake2b_256(min(leaves[0], leaves[1]) + max(leaves[0], leaves[1]))
        assert root == blake2b_256(min(pair, leaves[2]) + max(pair, leaves[2]))


def test_allowlist_errors() -> None:
    with pytest.raises(ValueError, match="empty"):
        allowlist_root([])
    with pytest.raises(ValueError, match="twice"):
        allowlist_root([ID_ZERO, ID_ZERO])
    with pytest.raises(ValueError, match="not on the allowlist"):
        allowlist_proof([ID_ZERO], ID_AB)
