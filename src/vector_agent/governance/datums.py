"""Datum builders for Game 6: Governance Suggestion Engine.

Each function constructs a CBOR-encoded datum matching the corresponding
Aiken on-chain type. Use ``cbor2.dumps(datum.data)`` to get raw bytes.
"""

import cbor2
from pycardano.plutus import PlutusData, RawPlutusData

from vector_agent.governance.types import ProposalPriority, ProposalState


def _unwrap(val):
    """Unwrap RawPlutusData to get the inner CBOR tag for nesting."""
    if isinstance(val, RawPlutusData):
        return val.data
    return val


def _plutus_bool(val: bool):
    """Encode a Python bool as a Plutus Bool constructor.

    In Aiken/Plutus, Bool is a sum type:
      False = Constructor 0 = CBORTag(121, [])
      True  = Constructor 1 = CBORTag(122, [])
    """
    return cbor2.CBORTag(122, []) if val else cbor2.CBORTag(121, [])


def build_proposal_datum(
    proposer_did: str,
    proposer_vkey_hash: bytes,
    proposal_hash: bytes,
    proposal_type: PlutusData,
    storage_uri: str,
    stake_amount: int,
    submitted_at: int,
    review_window: int,
    priority: PlutusData = None,
    amendment_count: int = 0,
    incorporated_critiques: list = None,
    state: PlutusData = None,
) -> RawPlutusData:
    """Build a ProposalDatum (§4.1)."""
    if priority is None:
        priority = ProposalPriority.STANDARD
    if incorporated_critiques is None:
        incorporated_critiques = []
    if state is None:
        state = ProposalState.OPEN

    credential = cbor2.CBORTag(121, [proposer_vkey_hash])

    return RawPlutusData(
        cbor2.CBORTag(
            121,
            [
                proposer_did if isinstance(proposer_did, bytes) else proposer_did.encode("utf-8"),
                credential,
                proposal_hash,
                _unwrap(proposal_type),
                storage_uri if isinstance(storage_uri, bytes) else storage_uri.encode("utf-8"),
                stake_amount,
                submitted_at,
                review_window,
                _unwrap(priority),
                amendment_count,
                incorporated_critiques,
                _unwrap(state),
            ],
        )
    )


def build_critique_datum(
    critic_did: str,
    critic_vkey_hash: bytes,
    proposal_ref_tx: bytes,
    proposal_ref_idx: int,
    critique_hash: bytes,
    storage_uri: str,
    critique_type: PlutusData,
    stake_amount: int,
    submitted_at: int,
    incorporated: bool = False,
) -> RawPlutusData:
    """Build a CritiqueDatum (§4.2)."""
    credential = cbor2.CBORTag(121, [critic_vkey_hash])
    output_ref = cbor2.CBORTag(121, [proposal_ref_tx, proposal_ref_idx])

    return RawPlutusData(
        cbor2.CBORTag(
            121,
            [
                critic_did if isinstance(critic_did, bytes) else critic_did.encode("utf-8"),
                credential,
                output_ref,
                critique_hash,
                storage_uri if isinstance(storage_uri, bytes) else storage_uri.encode("utf-8"),
                _unwrap(critique_type),
                stake_amount,
                submitted_at,
                _plutus_bool(incorporated),
            ],
        )
    )


def build_endorsement_datum(
    endorser_did: str,
    endorser_vkey_hash: bytes,
    proposal_ref_tx: bytes,
    proposal_ref_idx: int,
    stake_amount: int,
    created_at: int,
) -> RawPlutusData:
    """Build a GovernanceEndorsementDatum (§4.3)."""
    credential = cbor2.CBORTag(121, [endorser_vkey_hash])
    output_ref = cbor2.CBORTag(121, [proposal_ref_tx, proposal_ref_idx])

    return RawPlutusData(
        cbor2.CBORTag(
            121,
            [
                endorser_did if isinstance(endorser_did, bytes) else endorser_did.encode("utf-8"),
                credential,
                output_ref,
                stake_amount,
                created_at,
            ],
        )
    )


def build_governance_config(
    proposal_hash: bytes,
    critique_hash: bytes,
    prediction_hash: bytes,
    registry_policy: bytes,
    registry_hash: bytes,
    reputation_hash: bytes,
    jury_hash: bytes,
    oracle_hash: bytes,
    params_hash: bytes,
    treasury_hash: bytes,
    credibility_hash: bytes,
    protocol_params_hash: bytes,
) -> RawPlutusData:
    """Build a GovernanceConfig for parameterizing validators (§11.2)."""
    return RawPlutusData(
        cbor2.CBORTag(
            121,
            [
                proposal_hash,
                critique_hash,
                prediction_hash,
                registry_policy,
                registry_hash,
                reputation_hash,
                jury_hash,
                oracle_hash,
                params_hash,
                treasury_hash,
                credibility_hash,
                protocol_params_hash,
            ],
        )
    )


def build_governance_params(
    min_proposal_stake: int = 25_000_000,
    min_critique_stake: int = 5_000_000,
    min_governance_endorsement: int = 10_000_000,
    min_review_window: int = 302_400,
    max_review_window: int = 2_592_000,
    max_amendments: int = 5,
    max_active_proposals: int = 3,
    proposal_cooldown: int = 6_171,
    proposer_reward_share: int = 7_000,
    critic_reward_share: int = 2_000,
    protocol_fee_rate: int = 1_000,
    min_adoption_reward: int = 50_000_000,
    max_adoption_reward: int = 500_000_000,
    max_incorporated_critiques: int = 10,
    max_treasury_request: int = 10_000_000_000,
    emergency_stake_multiplier: int = 5_000,
    emergency_review_window: int = 43_200,
    param_execution_delay: int = 604_800,
    min_prediction_pool: int = 100_000_000,
    credibility_pool_low_threshold: int = 500_000_000,
    credibility_pool_critical_threshold: int = 100_000_000,
) -> RawPlutusData:
    """Build a GovernanceParams datum (§4.5)."""
    return RawPlutusData(
        cbor2.CBORTag(
            121,
            [
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
            ],
        )
    )


def build_treasury_batch_datum(
    batch_id: int, active: bool = True
) -> RawPlutusData:
    """Build a TreasuryBatchDatum (§9.4)."""
    return RawPlutusData(
        cbor2.CBORTag(121, [batch_id, _plutus_bool(active)])
    )


def build_oracle_datum(
    oracle_vkey_hash: bytes,
    treasury_script_hash: bytes,
    active: bool = True,
) -> RawPlutusData:
    """Build a GovernanceOracleDatum (§4.4)."""
    credential = cbor2.CBORTag(121, [oracle_vkey_hash])
    return RawPlutusData(
        cbor2.CBORTag(
            121, [credential, treasury_script_hash, _plutus_bool(active)]
        )
    )
