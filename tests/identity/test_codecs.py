"""Plutus Data and the typed codecs against the golden CBOR fixtures.

``fixtures/cbor-fixtures.json`` is a byte copy of Apex-Fusion/agents-marketplace
``contracts/identity-marketplace/fixtures/cbor-fixtures.json`` at commit
``b5d66a6`` (the file last changed in ``a96201d``; git blob ``175f6db5``). The
Aiken tests in ``lib/identity_marketplace/cbor_fixtures.ak`` wrote it with
``cbor.serialise``. Every fixture must decode and encode back to the same bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vector_agent.identity import plutus_data as pd
from vector_agent.identity import types as t

FIXTURES_FILE = Path(__file__).parent / "fixtures" / "cbor-fixtures.json"
FIXTURES = json.loads(FIXTURES_FILE.read_text())["fixtures"]

DECODERS = {
    "vector_identity/types.IdentityDatum": t.IdentityDatum.from_cbor,
    "vector_identity/types.LegacyDatum": t.LegacyDatum.from_cbor,
    "vector_identity/redeemers.IdentityMint": t.decode_identity_mint,
    "vector_identity/redeemers.IdentitySpend": t.IdentitySpend.from_cbor,
    "identity_marketplace/types.AttestationDatum": t.AttestationDatum.from_cbor,
    "identity_marketplace/types.AttestationMint": t.decode_attestation_mint,
    "identity_marketplace/types.AttestationSpend": t.decode_attestation_spend,
    "identity_marketplace/types.DelegationDatum": t.DelegationDatum.from_cbor,
    "identity_marketplace/types.DelegationMint": t.decode_delegation_mint,
    "identity_marketplace/types.VaultDatum": t.decode_vault_datum,
    "identity_marketplace/types.VaultSpend": t.decode_vault_spend,
    "identity_marketplace/types.EscrowDatum": t.EscrowDatum.from_cbor,
    "identity_marketplace/types.EscrowRedeemer": t.EscrowRedeemer.from_cbor,
    "identity_marketplace/types.AdvertDatum": t.AdvertDatum.from_cbor,
    "identity_marketplace/types.AdvertRedeemer": t.decode_advert_redeemer,
}


def _encode(value) -> bytes:
    if hasattr(value, "to_cbor"):
        return value.to_cbor()
    return pd.encode_data(value.to_data())


def test_fixture_file_is_the_pinned_copy() -> None:
    digest = hashlib.sha256(FIXTURES_FILE.read_bytes()).hexdigest()
    assert digest == "4a7bf768af8d9cac859024016eddfc0b29c079b659a47650b69c5f4efc449486"
    assert len(FIXTURES) == 44


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_plutus_data_round_trip(name: str) -> None:
    raw = bytes.fromhex(FIXTURES[name]["cbor"])
    assert pd.encode_data(pd.decode_data(raw)) == raw


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_typed_round_trip(name: str) -> None:
    fixture = FIXTURES[name]
    raw = bytes.fromhex(fixture["cbor"])
    value = DECODERS[fixture["type"]](raw)
    assert _encode(value) == raw


def test_decoded_values() -> None:
    record = t.IdentityDatum.from_cbor(FIXTURES["identity_datum_full"]["cbor"])
    assert record.controller == bytes([0x11]) * 32
    assert record.keys[1].key_type == t.KeyType.P256 and len(record.keys[1].pop) == 64
    assert record.parties[0].organisation == b"did:web:example.org"
    revoked = t.IdentityDatum.from_cbor(FIXTURES["identity_datum_revoked_tombstone"]["cbor"])
    assert isinstance(revoked.status, t.Revoked) and revoked.status.successor == bytes([0x99]) * 32
    spend = t.IdentitySpend.from_cbor(FIXTURES["identity_spend_recover_init"]["cbor"])
    assert spend == t.IdentitySpend("RecoverInit", guardians=(0, 3))
    escrow = t.EscrowDatum.from_cbor(FIXTURES["escrow_datum_with_refund"]["cbor"])
    assert isinstance(escrow.refund.address.payment, t.ScriptCredential)
    assert isinstance(escrow.refund.address.stake, t.InlineStake)
    assert t.decode_vault_datum(FIXTURES["vault_datum_returned"]["cbor"]) == t.VaultReturned(
        t.AgentDelegator(bytes([0xC3]) * 32)
    )


def test_encoder_forms() -> None:
    assert pd.encode_data(0).hex() == "00"
    assert pd.encode_data(-1).hex() == "20"
    assert pd.encode_data(2**64 - 1).hex() == "1bffffffffffffffff"
    assert pd.encode_data(2**64).hex() == "c249010000000000000000"
    assert pd.encode_data(-(2**64) - 1).hex() == "c349010000000000000000"
    assert pd.encode_data([]).hex() == "80"
    assert pd.encode_data([1]).hex() == "9f01ff"
    assert pd.encode_data(pd.Constr(7)).hex() == "d9050080"
    assert pd.encode_data(pd.Constr(128, (1,))).hex() == "d8668218809f01ff"
    assert pd.encode_data(pd.PlutusMap(((1, b""),))).hex() == "a10140"
    long = bytes(range(65))
    encoded = pd.encode_data(long)
    assert encoded[:3] == bytes.fromhex("5f5840") and encoded[-3:] == bytes.fromhex("4140ff")
    assert pd.decode_data(encoded) == long
    for value in (2**64, -(2**64) - 1, pd.Constr(128, (1,)), pd.PlutusMap(((1, b""),)), long, [pd.Constr(0)]):
        assert pd.decode_data(pd.encode_data(value)) == value


def test_decoder_accepts_ledger_forms() -> None:
    assert pd.decode_data(bytes.fromhex("8101")) == [1]  # definite array
    assert pd.decode_data(bytes.fromhex("d8798101")) == pd.Constr(0, (1,))  # definite fields
    assert pd.decode_data(bytes.fromhex("bf0102ff")) == pd.PlutusMap(((1, 2),))
    assert pd.decode_data(bytes.fromhex("1800")) == 0  # a non-shortest integer


@pytest.mark.parametrize(
    "hex_value",
    ["", "60", "f6", "f97e00", "d8199f01ff", "5841" + "00" * 65, "5f5841" + "00" * 65 + "ff", "0001"],
)
def test_decoder_rejects(hex_value: str) -> None:
    with pytest.raises(pd.PlutusDataError):
        pd.decode_data(bytes.fromhex(hex_value))


def test_encoder_rejects_non_data() -> None:
    with pytest.raises(pd.PlutusDataError):
        pd.encode_data(True)
    with pytest.raises(pd.PlutusDataError):
        pd.encode_data("text")


def test_typed_decoder_messages() -> None:
    with pytest.raises(pd.PlutusDataError, match="IdentityDatum: 1 fields"):
        t.IdentityDatum.from_cbor(pd.encode_data(pd.Constr(0, (b"",))))
    bad_signer = pd.Constr(3)
    with pytest.raises(pd.PlutusDataError, match="unknown constructor 3"):
        t.signer_from_data(bad_signer)
    with pytest.raises(ValueError, match="actor is required"):
        t.IdentitySpend("Suspend")
