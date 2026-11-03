"""Module-6 codecs, token names and the datum builders.

The expected CBOR and token names come from the reference builders of the
Module-6 contracts (vector-agent-modules ``91e3823``,
``Module-6/scripts/governance_identity.py`` with ``vector_identity.serialise_data``,
which writes the bytes of Aiken ``cbor.serialise``).
"""

from __future__ import annotations

import cbor2
import pytest

from vector_agent.governance import (
    ActivityDatum,
    CritiqueDatum,
    CritiqueKind,
    CritiqueType,
    EndorsementDatum,
    GovernanceConfig,
    GovernanceCrossRefs,
    GovernanceOracleDatum,
    GovernanceParams,
    ProposalAction,
    ProposalDatum,
    ProposalPriority,
    ProposalState,
    ProposalType,
    StateKind,
    activity_token_name,
    agent_id,
    build_activity_datum,
    build_critique_datum,
    build_cross_refs_datum,
    build_endorsement_datum,
    build_governance_config,
    build_governance_params,
    build_oracle_datum,
    build_proposal_datum,
    build_treasury_batch_datum,
    critique_token_name,
    endorsement_token_name,
    proposal_token_name,
)
from vector_agent.identity.constants import LEGACY_REGISTRY_HASH
from vector_agent.identity.plutus_data import Constr, PlutusDataError, encode_data
from vector_agent.identity.types import KeyCredential, OutputReference

h = bytes.fromhex
SEED = OutputReference(h("ab" * 32), 3)
AGENT = h("a1" * 32)
KEY = KeyCredential(h("b2" * 28))
LO = 1_762_485_540_000

#: Reference CBOR (governance_identity.py at 91e3823).
PROPOSAL_CBOR = (
    "d8799f5820" + "a1" * 32 + "d8799f581c" + "b2" * 28 + "ff5820" + "c3" * 32
    + "d8799f524d494e5f50524f504f53414c5f5354414b451a017d78401a01c9c380ff"
    + "5f5840697066733a2f2f" + "51" * 57 + "4d" + "51" * 13 + "ff"
    + "1a017d78401b0000019a5c5314a01a240c8400d87a80029fd8799f5820" + "d4" * 32 + "01ffff"
    + "d87a9f5820" + "e5" * 32 + "ffff"
)
ACTIVITY_CBOR = (
    "d8799f5820" + "a1" * 32 + "d8799f581c" + "b2" * 28 + "ff021b0000019a5c5314a05820" + "f6" * 32 + "ff"
)
CRITIQUE_CBOR = (
    "d8799f5820" + "a1" * 32 + "d8799f581c" + "b2" * 28 + "ffd8799f5820" + "ab" * 32 + "03ff5820" + "c3" * 32
    + "48697066733a2f2f63d87b9f5820" + "e5" * 32 + "ff1a004c4b401b0000019a5c5314a0d87a80ff"
)
ENDORSEMENT_CBOR = (
    "d8799f5820" + "a1" * 32 + "d8799f581c" + "b2" * 28 + "ffd8799f5820" + "ab" * 32
    + "03ff1a009896801b0000019a5c5314a0ff"
)
CROSS_REFS_CBOR = "d8799f" + "".join("581c" + f"{i:02x}" * 28 for i in range(1, 6)) + "ff"
AMEND_CBOR = (
    "d87b9f5820" + "c3" * 32 + "49697066733a2f2f76329fd8799f5820" + "ab" * 32 + "03ffffff"
)


def test_token_names_match_the_reference_builders() -> None:
    assert proposal_token_name(SEED).hex() == "70726f705feefc453a50a290d5336c806d6bf5a15e439f5a2749887d9efb3580"
    assert critique_token_name(SEED).hex() == "637269745feefc453a50a290d5336c806d6bf5a15e439f5a2749887d9efb3580"
    assert endorsement_token_name(AGENT, SEED).hex() == (
        "67656e645f5bd2d557dfbea1ff5053783cfb91e903d26da658e659a48d0f9cff"
    )
    assert activity_token_name(AGENT).hex() == "706163745ff65ecdfc7dc414d7816eb3b9248488094e00fb6b69e67da0509cb6"
    for name in (proposal_token_name(SEED), activity_token_name(AGENT)):
        assert len(name) == 32


def proposal() -> ProposalDatum:
    return ProposalDatum(
        proposer_did=AGENT,
        proposer_credential=KEY,
        proposal_hash=h("c3" * 32),
        proposal_type=ProposalType.parameter_change("MIN_PROPOSAL_STAKE", 25_000_000, 30_000_000),
        storage_uri=b"ipfs://" + b"Q" * 70,
        stake_amount=25_000_000,
        submitted_at=LO,
        review_window=604_800_000,
        priority=ProposalPriority.EMERGENCY,
        amendment_count=2,
        incorporated_critiques=(OutputReference(h("d4" * 32), 1),),
        state=ProposalState.amended(h("e5" * 32)),
    )


def test_datums_match_the_reference_builders() -> None:
    datum = proposal()
    assert datum.to_cbor_hex() == PROPOSAL_CBOR
    assert ProposalDatum.from_cbor(PROPOSAL_CBOR) == datum
    activity = ActivityDatum(AGENT, KEY, 2, LO, h("f6" * 32))
    assert activity.to_cbor_hex() == ACTIVITY_CBOR and ActivityDatum.from_cbor(ACTIVITY_CBOR) == activity
    critique = CritiqueDatum(AGENT, KEY, SEED, h("c3" * 32), b"ipfs://c", CritiqueType.amendment(h("e5" * 32)), 5_000_000, LO, True)
    assert critique.to_cbor_hex() == CRITIQUE_CBOR and CritiqueDatum.from_cbor(CRITIQUE_CBOR) == critique
    endorsement = EndorsementDatum(AGENT, KEY, SEED, 10_000_000, LO)
    assert endorsement.to_cbor_hex() == ENDORSEMENT_CBOR
    assert EndorsementDatum.from_cbor(ENDORSEMENT_CBOR) == endorsement
    refs = GovernanceCrossRefs(*(bytes([i]) * 28 for i in range(1, 6)))
    assert refs.to_cbor_hex() == CROSS_REFS_CBOR and GovernanceCrossRefs.from_cbor(CROSS_REFS_CBOR) == refs
    assert encode_data(ProposalAction.amend(h("c3" * 32), "ipfs://v2", [SEED])).hex() == AMEND_CBOR


def test_redeemer_constructors() -> None:
    assert ProposalAction.SUBMIT == Constr(0) and ProposalAction.WITHDRAW == Constr(1)
    assert ProposalAction.adopt(bytes(32), 5) == Constr(3, (bytes(32), 5))
    assert ProposalAction.reject(bytes(32)) == Constr(4, (bytes(32),))
    assert ProposalAction.EXPIRE == Constr(5) and ProposalAction.EXPIRE_STALE == Constr(6)
    assert ProposalAction.extend_review(9) == Constr(7, (9,)) and ProposalAction.SPEND_ACTIVITY == Constr(8)
    assert encode_data(ProposalAction.SPEND_ACTIVITY).hex() == "d9050180"


def test_old_layouts_do_not_decode() -> None:
    four_field_activity = encode_data(Constr(0, (AGENT, KEY.to_data(), 1, LO)))
    with pytest.raises(PlutusDataError, match="4 fields"):
        ActivityDatum.from_cbor(four_field_activity)
    four_field_refs = encode_data(Constr(0, tuple(bytes([i]) * 28 for i in range(1, 5))))
    with pytest.raises(PlutusDataError, match="4 fields"):
        GovernanceCrossRefs.from_cbor(four_field_refs)


def test_states_and_critique_types() -> None:
    assert ProposalState.OPEN.active and ProposalState.amended(bytes(32)).active
    assert not ProposalState.WITHDRAWN.active and ProposalState.adopted(bytes(32)).kind == StateKind.ADOPTED
    with pytest.raises(ValueError, match="needs"):
        ProposalState(StateKind.REJECTED)
    with pytest.raises(ValueError, match="has no"):
        ProposalState(StateKind.OPEN, bytes(32))
    assert CritiqueType.OPPOSING.kind == CritiqueKind.OPPOSING
    with pytest.raises(ValueError, match="suggested change"):
        CritiqueType(CritiqueKind.SUPPORTIVE, bytes(32))


def test_agent_identifiers() -> None:
    hexid = AGENT.hex()
    assert agent_id(f"did:vector:{hexid}") == AGENT == agent_id(hexid) == agent_id(AGENT)
    assert agent_id(f"did:vector:agent:{LEGACY_REGISTRY_HASH}:{hexid}") == AGENT
    for bad in (f"did:vector:testnet:{hexid}", f"did:vector:agent:{'00' * 28}:{hexid}", hexid.upper(), "agent-1", AGENT[:31]):
        with pytest.raises(ValueError):
            agent_id(bad)


def test_module6_parameter_values() -> None:
    params = GovernanceParams(*range(1, 22))
    assert params.module6_value(b"MIN_PROPOSAL_STAKE") == 1
    assert params.module6_value(b"COOLDOWN_BETWEEN_PROPOSALS") == 8
    assert params.module6_value(b"EMERGENCY_REVIEW_WINDOW") == 17
    assert params.module6_value(b"JURY_SIZE") is None and params.module6_value(b"GAME_ACTIVATION") is None
    assert GovernanceParams.from_cbor(params.to_cbor()) == params


def test_config_parameter_is_the_deploy_script_form() -> None:
    values = [bytes([i]) * 28 for i in range(11)]
    config = GovernanceConfig(*values)
    # deploy_common.build_governance_config_cbor: cbor2.dumps(CBORTag(121, fields))
    assert config.parameter_cbor() == cbor2.dumps(cbor2.CBORTag(121, values))
    assert config.parameter_cbor()[:3] == bytes.fromhex("d8798b")
    assert config.to_cbor()[:3] == bytes.fromhex("d8799f")
    assert GovernanceConfig.from_cbor(config.parameter_cbor()) == config
    with pytest.raises(ValueError, match="28 bytes"):
        GovernanceConfig(*values[:10], bytes(32))


def test_datum_builders_write_the_codec_bytes() -> None:
    raw = build_proposal_datum(
        f"did:vector:{AGENT.hex()}",
        KEY.hash,
        h("c3" * 32),
        ProposalType.parameter_change("MIN_PROPOSAL_STAKE", 25_000_000, 30_000_000),
        b"ipfs://" + b"Q" * 70,
        25_000_000,
        LO,
        604_800_000,
        ProposalPriority.EMERGENCY,
        2,
        [OutputReference(h("d4" * 32), 1)],
        ProposalState.amended(h("e5" * 32)),
    )
    assert raw.to_cbor().hex() == PROPOSAL_CBOR  # the 77-byte URI is in 64-byte chunks
    assert build_activity_datum(AGENT, KEY.hash, 2, LO, h("f6" * 32)).to_cbor().hex() == ACTIVITY_CBOR
    critique = build_critique_datum(
        AGENT, KEY.hash, f"{'ab' * 32}#3", h("c3" * 32), "ipfs://c", CritiqueType.amendment(h("e5" * 32)), 5_000_000, LO, True
    )
    assert critique.to_cbor().hex() == CRITIQUE_CBOR
    endorsement = build_endorsement_datum(AGENT, KEY.hash, {"tx_hash": "ab" * 32, "output_index": 3}, 10_000_000, LO)
    assert endorsement.to_cbor().hex() == ENDORSEMENT_CBOR
    assert build_cross_refs_datum(*(bytes([i]) * 28 for i in range(1, 6))).to_cbor().hex() == CROSS_REFS_CBOR


def test_config_params_oracle_and_treasury_builders() -> None:
    hashes = {name: bytes([i]) * 28 for i, name in enumerate(("refs", "oracle", "params", "treasury", "record", "identity"), 1)}
    config = build_governance_config(
        hashes["refs"], hashes["oracle"], hashes["params"], hashes["treasury"], hashes["record"], hashes["identity"]
    )
    fields = config.data.value
    assert len(fields) == 11 and fields[-1] == hashes["identity"] and fields[1] == bytes(28)
    assert cbor2.dumps(config.data) == GovernanceConfig.from_cbor(config.to_cbor()).parameter_cbor()
    params = build_governance_params()
    assert len(params.data.value) == 21 and GovernanceParams.from_cbor(params.to_cbor()).min_proposal_stake == 25_000_000
    oracle = build_oracle_datum(KEY.hash, hashes["treasury"])
    assert oracle.data.value[0].tag == 121  # a verification-key credential (the deploy script checks it)
    assert GovernanceOracleDatum.from_cbor(oracle.to_cbor()) == GovernanceOracleDatum(KEY, hashes["treasury"], True)
    assert build_treasury_batch_datum(2, False).to_cbor().hex() == "d8799f02d87980ff"
    with pytest.raises(ValueError, match="32 bytes"):
        build_activity_datum(b"not an identifier", KEY.hash, 1, LO)
