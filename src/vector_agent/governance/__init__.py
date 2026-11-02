"""Self-Improvement module (Module-6, "Game 6") clients on the deployment that
reads identity records (``did:vector``).

- :class:`Governance`: builders of every Module-6 transaction. Each returns an
  unsigned :class:`~vector_agent.identity.BuiltTx` with the key hashes that
  must sign it.
- :class:`GovernanceClient`: the flows of a :class:`~vector_agent.VectorAgent`
  (lock, then create), signed with the agent wallet and submitted.
- :class:`GovernanceIndexer`: read proposals, critiques and endorsements.

Usage::

    from vector_agent import VectorAgent
    from vector_agent.governance import GovernanceClient, GovernanceDeployment, ProposalType

    async with VectorAgent() as agent:
        gov = GovernanceClient(agent, GovernanceDeployment.from_env())
        result = await gov.submit_proposal(
            proposer_did="did:vector:<64 hex>",
            proposal_hash=bytes(32),
            storage_uri="ipfs://Qm...",
            proposal_type=ProposalType.general_suggestion(),
        )
        seed = result["seed"]  # critiques and endorsements name the proposal by its seed
"""

from vector_agent.governance.blueprint import ValidatorInfo, read_blueprint
from vector_agent.governance.builders import (
    ACTIVITY_LOVELACE,
    DEFAULT_REVIEW_WINDOW_MS,
    DEFAULT_VALID_FOR_S,
    POSITION_DEPOSIT,
    Governance,
    as_ref,
    payout_address,
)
from vector_agent.governance.client import GovernanceClient
from vector_agent.governance.context import ActivityList, GovernanceContext, Position
from vector_agent.governance.datums import (
    build_activity_datum,
    build_critique_datum,
    build_cross_refs_datum,
    build_endorsement_datum,
    build_governance_config,
    build_governance_params,
    build_oracle_datum,
    build_proposal_datum,
    build_treasury_batch_datum,
)
from vector_agent.governance.deployment import ENV_VARS, GovernanceDeployment
from vector_agent.governance.errors import GovernanceConfigError, GovernanceLookupError, GovernanceRuleError
from vector_agent.governance.indexer import GovernanceIndexer
from vector_agent.governance.scripts import GOVERNANCE_BLUEPRINT_SHA256, GovernanceScripts
from vector_agent.governance.types import (
    ActivityDatum,
    CritiqueAction,
    CritiqueDatum,
    CritiqueKind,
    CritiqueType,
    EndorsementAction,
    EndorsementDatum,
    GovernanceConfig,
    GovernanceCrossRefs,
    GovernanceOracleDatum,
    GovernanceParams,
    ProposalAction,
    ProposalDatum,
    ProposalKind,
    ProposalPriority,
    ProposalState,
    ProposalType,
    StateKind,
    TreasuryBatchDatum,
    activity_token_name,
    agent_id,
    critique_token_name,
    endorsement_token_name,
    proposal_token_name,
)

__all__ = [
    "ACTIVITY_LOVELACE",
    "DEFAULT_REVIEW_WINDOW_MS",
    "DEFAULT_VALID_FOR_S",
    "ENV_VARS",
    "GOVERNANCE_BLUEPRINT_SHA256",
    "POSITION_DEPOSIT",
    "ActivityDatum",
    "ActivityList",
    "CritiqueAction",
    "CritiqueDatum",
    "CritiqueKind",
    "CritiqueType",
    "EndorsementAction",
    "EndorsementDatum",
    "Governance",
    "GovernanceClient",
    "GovernanceConfig",
    "GovernanceConfigError",
    "GovernanceContext",
    "GovernanceCrossRefs",
    "GovernanceDeployment",
    "GovernanceIndexer",
    "GovernanceLookupError",
    "GovernanceOracleDatum",
    "GovernanceParams",
    "GovernanceRuleError",
    "GovernanceScripts",
    "Position",
    "ProposalAction",
    "ProposalDatum",
    "ProposalKind",
    "ProposalPriority",
    "ProposalState",
    "ProposalType",
    "StateKind",
    "TreasuryBatchDatum",
    "ValidatorInfo",
    "activity_token_name",
    "agent_id",
    "as_ref",
    "build_activity_datum",
    "build_critique_datum",
    "build_cross_refs_datum",
    "build_endorsement_datum",
    "build_governance_config",
    "build_governance_params",
    "build_oracle_datum",
    "build_proposal_datum",
    "build_treasury_batch_datum",
    "critique_token_name",
    "endorsement_token_name",
    "payout_address",
    "proposal_token_name",
    "read_blueprint",
]
