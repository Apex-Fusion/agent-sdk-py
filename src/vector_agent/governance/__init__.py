"""Game 6: Governance Suggestion Engine — Python SDK.

High-level client for submitting proposals, critiques, endorsements,
and Foundation oracle actions on the Vector blockchain.

Usage::

    from vector_agent import VectorAgent
    from vector_agent.governance import GovernanceClient, ProposalType

    async with VectorAgent() as agent:
        gov = GovernanceClient(agent)
        result = await gov.submit_proposal(
            proposer_did="my_agent_did",
            proposal_hash=b"...",
            proposal_type=ProposalType.general_suggestion(),
            storage_uri="ipfs://Qm...",
        )
"""

from vector_agent.governance.types import (
    ProposalType,
    ProposalPriority,
    ProposalState,
    ProposalAction,
    CritiqueType,
    CritiqueAction,
    EndorsementAction,
)
from vector_agent.governance.datums import (
    build_proposal_datum,
    build_critique_datum,
    build_endorsement_datum,
    build_governance_config,
    build_governance_params,
    build_treasury_batch_datum,
    build_oracle_datum,
)
from vector_agent.governance.blueprint import (
    ValidatorInfo,
    read_blueprint,
)
from vector_agent.governance.client import GovernanceClient
from vector_agent.governance.indexer import GovernanceIndexer

__all__ = [
    "GovernanceClient",
    "GovernanceIndexer",
    "ProposalType",
    "ProposalPriority",
    "ProposalState",
    "ProposalAction",
    "CritiqueType",
    "CritiqueAction",
    "EndorsementAction",
    "build_proposal_datum",
    "build_critique_datum",
    "build_endorsement_datum",
    "build_governance_config",
    "build_governance_params",
    "build_treasury_batch_datum",
    "build_oracle_datum",
    "ValidatorInfo",
    "read_blueprint",
]
