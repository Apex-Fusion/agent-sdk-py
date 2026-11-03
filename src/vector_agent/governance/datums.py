"""Datum builders for the Self-Improvement module (Module-6).

Each function returns a PyCardano ``RawPlutusData`` whose ``data`` is the cbor2
tree of the datum, in the layouts of the Module-6 deployment that reads
identity records (:mod:`vector_agent.governance.types`):

- PyCardano writes the datum with the bytes of Aiken ``cbor.serialise``
  (``RawPlutusData.to_cbor()``; a byte string over 64 bytes in chunks).
- ``build_governance_config`` gives the 11-field ``GovernanceConfig``
  (``identity_hash`` last). ``cbor2.dumps(config.data)`` is the parameter CBOR
  of the Module-6 deploy script (a definite array); see
  :meth:`~vector_agent.governance.types.GovernanceConfig.parameter_cbor`.
- An agent identifier is a ``did:vector`` DID, 64 hexadecimal characters or
  32 bytes. A credential is the 28-byte hash of a verification key.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import cbor2
from pycardano.plutus import RawPlutusData
from pycardano.serialization import ByteString

from vector_agent.governance.builders import as_ref
from vector_agent.governance.types import (
    ActivityDatum,
    CritiqueDatum,
    CritiqueType,
    EndorsementDatum,
    GovernanceConfig,
    GovernanceCrossRefs,
    GovernanceOracleDatum,
    GovernanceParams,
    ProposalDatum,
    ProposalPriority,
    ProposalState,
    ProposalType,
    TreasuryBatchDatum,
    agent_id,
    utf8,
)
from vector_agent.identity.plutus_data import Constr, PlutusData, PlutusMap
from vector_agent.identity.types import KeyCredential, OutputReference

__all__ = [
    "build_activity_datum",
    "build_critique_datum",
    "build_cross_refs_datum",
    "build_endorsement_datum",
    "build_governance_config",
    "build_governance_params",
    "build_oracle_datum",
    "build_proposal_datum",
    "build_treasury_batch_datum",
    "to_raw_plutus_data",
]

_ZERO = bytes(28)


def _tree(value: PlutusData):
    if isinstance(value, Constr):
        fields = [_tree(f) for f in value.fields]
        if value.index <= 6:
            return cbor2.CBORTag(121 + value.index, fields)
        if value.index <= 127:
            return cbor2.CBORTag(1280 + value.index - 7, fields)
        return cbor2.CBORTag(102, [value.index, fields])
    if isinstance(value, (bytes, bytearray)):
        return ByteString(bytes(value)) if len(value) > 64 else bytes(value)
    if isinstance(value, (list, tuple)):
        return [_tree(v) for v in value]
    if isinstance(value, PlutusMap):
        return {_tree(k): _tree(v) for k, v in value.entries}
    return value


def to_raw_plutus_data(value: PlutusData) -> RawPlutusData:
    """Plutus Data of :mod:`vector_agent.identity.plutus_data` as PyCardano
    ``RawPlutusData``. Byte strings over 64 bytes become PyCardano
    ``ByteString`` values, which PyCardano writes in 64-byte chunks."""
    return RawPlutusData(_tree(value))


def _key(key_hash: bytes) -> KeyCredential:
    raw = bytes(key_hash)
    if len(raw) != 28:
        raise ValueError("a verification key hash has 28 bytes")
    return KeyCredential(raw)


def _seed(value: OutputReference | str | Mapping) -> OutputReference:
    return as_ref(value)


def build_proposal_datum(
    proposer_did: str | bytes,
    proposer_key_hash: bytes,
    proposal_hash: bytes,
    proposal_type: ProposalType,
    storage_uri: str | bytes,
    stake_amount: int,
    submitted_at: int,
    review_window: int,
    priority: ProposalPriority = ProposalPriority.STANDARD,
    amendment_count: int = 0,
    incorporated_critiques: Sequence[OutputReference] = (),
    state: ProposalState = ProposalState.OPEN,
) -> RawPlutusData:
    """``ProposalDatum`` (12 fields). Times are POSIX ms; ``submitted_at`` is
    ``lo`` of the submission."""
    datum = ProposalDatum(
        agent_id(proposer_did),
        _key(proposer_key_hash),
        bytes(proposal_hash),
        proposal_type,
        utf8(storage_uri),
        int(stake_amount),
        int(submitted_at),
        int(review_window),
        ProposalPriority(priority),
        int(amendment_count),
        tuple(_seed(r) for r in incorporated_critiques),
        state,
    )
    return to_raw_plutus_data(datum.to_data())


def build_activity_datum(
    agent_did: str | bytes,
    agent_key_hash: bytes,
    active_proposal_count: int,
    last_proposal_slot: int,
    next_did: bytes = b"",
) -> RawPlutusData:
    """``ProposerActivityDatum`` (5 fields, ``next_did`` last): a node of the
    activity list. ``last_proposal_slot`` is POSIX ms."""
    datum = ActivityDatum(
        agent_id(agent_did), _key(agent_key_hash), int(active_proposal_count), int(last_proposal_slot), bytes(next_did)
    )
    return to_raw_plutus_data(datum.to_data())


def build_critique_datum(
    critic_did: str | bytes,
    critic_key_hash: bytes,
    proposal_seed: OutputReference | str | Mapping,
    critique_hash: bytes,
    storage_uri: str | bytes,
    critique_type: CritiqueType,
    stake_amount: int,
    submitted_at: int,
    incorporated: bool = False,
) -> RawPlutusData:
    """``CritiqueDatum`` (9 fields). ``proposal_seed`` is the seed of the proposal."""
    datum = CritiqueDatum(
        agent_id(critic_did),
        _key(critic_key_hash),
        _seed(proposal_seed),
        bytes(critique_hash),
        utf8(storage_uri),
        critique_type,
        int(stake_amount),
        int(submitted_at),
        bool(incorporated),
    )
    return to_raw_plutus_data(datum.to_data())


def build_endorsement_datum(
    endorser_did: str | bytes,
    endorser_key_hash: bytes,
    proposal_seed: OutputReference | str | Mapping,
    stake_amount: int,
    created_at: int,
) -> RawPlutusData:
    """``GovernanceEndorsementDatum`` (5 fields). ``proposal_seed`` is the seed of the proposal."""
    datum = EndorsementDatum(
        agent_id(endorser_did), _key(endorser_key_hash), _seed(proposal_seed), int(stake_amount), int(created_at)
    )
    return to_raw_plutus_data(datum.to_data())


def build_governance_config(
    refs_token_policy: bytes,
    governance_oracle_hash: bytes,
    governance_params_hash: bytes,
    governance_treasury_hash: bytes,
    record_token_policy: bytes,
    identity_hash: bytes,
    *,
    prediction_validator_hash: bytes = _ZERO,
    reputation_validator_hash: bytes = _ZERO,
    jury_pool_hash: bytes = _ZERO,
    credibility_pool_hash: bytes = _ZERO,
    protocol_params_hash: bytes = _ZERO,
) -> RawPlutusData:
    """``GovernanceConfig`` (11 fields, ``identity_hash`` last), the parameter
    of every Module-6 validator. The five hashes that the deploy script keeps
    at zero are keyword arguments."""
    config = GovernanceConfig(
        refs_token_policy=refs_token_policy,
        prediction_validator_hash=prediction_validator_hash,
        reputation_validator_hash=reputation_validator_hash,
        jury_pool_hash=jury_pool_hash,
        governance_oracle_hash=governance_oracle_hash,
        governance_params_hash=governance_params_hash,
        governance_treasury_hash=governance_treasury_hash,
        credibility_pool_hash=credibility_pool_hash,
        protocol_params_hash=protocol_params_hash,
        record_token_policy=record_token_policy,
        identity_hash=identity_hash,
    )
    return to_raw_plutus_data(config.to_data())


def build_cross_refs_datum(
    proposal_validator_hash: bytes,
    critique_validator_hash: bytes,
    proposal_mint_hash: bytes,
    critique_mint_hash: bytes,
    endorsement_validator_hash: bytes,
) -> RawPlutusData:
    """``GovernanceCrossRefs`` (5 fields, ``endorsement_validator_hash`` last)."""
    refs = GovernanceCrossRefs(
        proposal_validator_hash,
        critique_validator_hash,
        proposal_mint_hash,
        critique_mint_hash,
        endorsement_validator_hash,
    )
    return to_raw_plutus_data(refs.to_data())


def build_governance_params(
    min_proposal_stake: int = 25_000_000,
    min_critique_stake: int = 5_000_000,
    min_governance_endorsement: int = 10_000_000,
    min_review_window: int = 259_200_000,  # ~3 days in POSIX ms
    max_review_window: int = 2_419_200_000,  # ~28 days in POSIX ms
    max_amendments: int = 5,
    max_active_proposals: int = 3,
    proposal_cooldown: int = 86_400_000,  # ~24 hours in POSIX ms
    proposer_reward_share: int = 7_000,
    critic_reward_share: int = 2_000,
    protocol_fee_rate: int = 1_000,
    min_adoption_reward: int = 50_000_000,
    max_adoption_reward: int = 500_000_000,
    max_incorporated_critiques: int = 10,
    max_treasury_request: int = 10_000_000_000,
    emergency_stake_multiplier: int = 5_000,
    emergency_review_window: int = 43_200_000,  # ~12 hours in POSIX ms
    param_execution_delay: int = 604_800_000,  # ~7 days in POSIX ms
    min_prediction_pool: int = 100_000_000,
    credibility_pool_low_threshold: int = 500_000_000,
    credibility_pool_critical_threshold: int = 100_000_000,
) -> RawPlutusData:
    """``GovernanceParams`` (21 fields). Times are POSIX milliseconds."""
    params = GovernanceParams(
        min_proposal_stake,
        min_critique_stake,
        min_governance_endorsement,
        min_review_window,
        max_review_window,
        max_amendments,
        max_active_proposals,
        proposal_cooldown,
        proposer_reward_share,
        critic_reward_share,
        protocol_fee_rate,
        min_adoption_reward,
        max_adoption_reward,
        max_incorporated_critiques,
        max_treasury_request,
        emergency_stake_multiplier,
        emergency_review_window,
        param_execution_delay,
        min_prediction_pool,
        credibility_pool_low_threshold,
        credibility_pool_critical_threshold,
    )
    return to_raw_plutus_data(params.to_data())


def build_treasury_batch_datum(batch_id: int, active: bool = True) -> RawPlutusData:
    """``TreasuryBatchDatum { batch_id, active }``."""
    return to_raw_plutus_data(TreasuryBatchDatum(int(batch_id), bool(active)).to_data())


def build_oracle_datum(oracle_vkey_hash: bytes, treasury_script_hash: bytes, active: bool = True) -> RawPlutusData:
    """``GovernanceOracleDatum``: the oracle key credential, the treasury script
    hash and whether the oracle is active."""
    datum = GovernanceOracleDatum(_key(oracle_vkey_hash), bytes(treasury_script_hash), bool(active))
    return to_raw_plutus_data(datum.to_data())
