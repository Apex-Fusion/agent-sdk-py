"""Cross-platform CBOR serialization tests.

Verifies that Python's Plutus CBOR serialization matches Aiken's
builtin.serialise_data() for known inputs.  Expected hex values come from
Aiken stdlib tests (``cbor.test.ak``).
"""


import cbor2

from vector_agent.chain.plutus_cbor import plutus_serialise_data


class TestPlutusSerialiseData:
    """Test plutus_serialise_data matches Aiken's builtin.serialise_data()."""

    def test_some_42_matches_aiken(self):
        """serialise(Some(42)) == #"d8799f182aff" per Aiken cbor.test.ak."""
        result = plutus_serialise_data(0, [42])
        assert result.hex() == "d8799f182aff"

    def test_none_matches_aiken(self):
        """serialise(None) == #"d87a80" per Aiken cbor.test.ak."""
        result = plutus_serialise_data(1, [])
        assert result.hex() == "d87a80"

    def test_output_reference_encoding(self):
        """OutputReference { tx_id: 32 zero bytes, output_index: 0 }.

        Constr(0, [ByteArray(32 zeros), Int(0)])
        CBOR: d879 9f 5820 <32 zeros> 00 ff
        """
        tx_hash = bytes(32)
        result = plutus_serialise_data(0, [tx_hash, 0])
        expected = "d8799f5820" + "00" * 32 + "00ff"
        assert result.hex() == expected

    def test_output_reference_nonzero_index(self):
        """OutputReference with output_index=1."""
        tx_hash = bytes(32)
        result = plutus_serialise_data(0, [tx_hash, 1])
        expected = "d8799f5820" + "00" * 32 + "01ff"
        assert result.hex() == expected

    def test_nested_empty_constructor(self):
        """Constr(0, [Constr(0, [])]) — nested empty constructor."""
        inner = cbor2.CBORTag(121, [])
        result = plutus_serialise_data(0, [inner])
        # Tag 121 + indef + (Tag 121 + empty definite) + break
        assert result.hex() == "d8799fd87980ff"

    def test_nested_nonempty_constructor(self):
        """Constr(0, [Constr(1, [42])]) — nested non-empty constructor."""
        inner = cbor2.CBORTag(122, [42])
        result = plutus_serialise_data(0, [inner])
        # Outer: d879 9f ... ff
        # Inner: d87a 9f 182a ff
        assert result.hex() == "d8799fd87a9f182affff"

    def test_definite_vs_indefinite_differ(self):
        """Confirm definite and indefinite encodings produce different bytes."""
        tx_hash = bytes(32)
        wrong = cbor2.dumps(cbor2.CBORTag(121, [tx_hash, 0]))
        right = plutus_serialise_data(0, [tx_hash, 0])
        assert wrong != right
        # Definite uses 0x82, indefinite uses 0x9f...0xff
        assert wrong[2:3] == b"\x82"
        assert right[2:3] == b"\x9f"
        assert right[-1:] == b"\xff"


class TestTokenNameDerivation:
    """Module-6 token names: the old helper's encoding equals the codec's encoding."""

    def test_seed_token_names_use_the_indefinite_output_reference(self):
        from vector_agent.governance import critique_token_name, proposal_token_name
        from vector_agent.identity.ids import blake2b_256
        from vector_agent.identity.types import OutputReference

        seed = OutputReference(bytes([0xAB]) * 32, 3)
        digest = blake2b_256(plutus_serialise_data(0, [seed.tx_id, seed.index]))[:27]
        assert proposal_token_name(seed) == b"prop_" + digest
        assert critique_token_name(seed) == b"crit_" + digest
        assert proposal_token_name(OutputReference(bytes([0xAA]) * 32, 0)) != proposal_token_name(
            OutputReference(bytes([0xBB]) * 32, 0)
        )

    def test_endorsement_and_activity_names(self):
        from vector_agent.governance import activity_token_name, endorsement_token_name
        from vector_agent.identity.ids import blake2b_256
        from vector_agent.identity.types import OutputReference

        agent = bytes([0xA1]) * 32
        seed = OutputReference(bytes(32), 0)
        assert endorsement_token_name(agent, seed) == b"gend_" + blake2b_256(agent + seed.to_cbor())[:27]
        assert activity_token_name(agent) == b"pact_" + blake2b_256(agent)[:27]
        assert len(activity_token_name(agent)) == 32
