"""Off-chain copies of the Module-6 contract rules that the builders check first.

A builder that breaks one of them would only produce a transaction that the
ledger rejects, so the builders refuse early with the broken rule. The rules
follow ``lib/governance_suggestion`` (``proposal_validation``,
``activity_tracking``, ``critique_validation``, ``params``, ``emergency``) and
``lib/shared/identity`` of the Module-6 contracts (vector-agent-modules
``91e3823``).
"""

from __future__ import annotations

from collections.abc import Sequence

from vector_agent.governance.errors import GovernanceLookupError, GovernanceRuleError
from vector_agent.governance.types import (
    ActivityDatum,
    CritiqueDatum,
    CritiqueKind,
    EndorsementDatum,
    GovernanceParams,
    ProposalDatum,
    ProposalKind,
    ProposalPriority,
    StateKind,
)
from vector_agent.identity.constants import PURPOSE_TRANSACTION
from vector_agent.identity.context import AuthenticOutput
from vector_agent.identity.ids import blake2b_224, vector_did
from vector_agent.identity.rules import Effective, active_key, effective
from vector_agent.identity.types import Credential, IdentityDatum, KeyCredential, Subagent

__all__ = [
    "GOVERNABLE_PARAMS",
    "check_critique",
    "check_distinct_parties",
    "check_endorsement",
    "check_proposal",
    "check_rate_limit",
    "declared_key",
    "emergency_stake",
    "require_active",
]

#: ``params.is_governable_param``: the names that a ParameterChange proposal can name.
GOVERNABLE_PARAMS = frozenset(
    name.encode()
    for name in (
        "MIN_CLAIM_STAKE",
        "MIN_CHALLENGE_WINDOW",
        "JURY_SIZE",
        "JURY_FEE_RATE",
        "MIN_SELF_STAKE",
        "MIN_ENDORSEMENT",
        "DECAY_RATE",
        "MAX_ENDORSEMENT_MULTIPLIER",
        "MIN_PROPOSAL_STAKE",
        "MIN_CRITIQUE_STAKE",
        "MIN_GOVERNANCE_ENDORSEMENT",
        "MIN_REVIEW_WINDOW",
        "MAX_REVIEW_WINDOW",
        "MAX_AMENDMENTS",
        "MAX_ACTIVE_PROPOSALS",
        "COOLDOWN_BETWEEN_PROPOSALS",
        "PROPOSER_REWARD_SHARE",
        "CRITIC_REWARD_SHARE",
        "PROTOCOL_FEE_RATE",
        "MIN_ADOPTION_REWARD",
        "MAX_ADOPTION_REWARD",
        "MAX_INCORPORATED_CRITIQUES",
        "MAX_TREASURY_REQUEST",
        "EMERGENCY_STAKE_MULTIPLIER",
        "EMERGENCY_REVIEW_WINDOW",
        "TREASURY_BATCH_SIZE",
        "MIN_TREASURY_BATCHES",
        "ADOPTION_REWARD_BASE",
        "GAME_ACTIVATION",
    )
)


def _did(agent: bytes) -> str:
    return vector_did(agent.hex()) if len(agent) == 32 else agent.hex()


def _fail(what: str, problems: Sequence[str]) -> None:
    if problems:
        raise GovernanceRuleError(f"{what} does not meet the contract rules: " + "; ".join(problems))


# ---------------------------------------------------------------------------
# Identity (shared/identity.ak, Part 2 §7 Module-6 row)
# ---------------------------------------------------------------------------


def require_active(chain: Sequence[AuthenticOutput[IdentityDatum]], lo: int, hi: int) -> None:
    """The record ``chain[0]`` has effective status Active over ``[lo, hi]``
    (``vector_identity.effective``); ``chain[1:]`` are its ancestors."""
    if not chain:
        raise GovernanceLookupError("no identity record")
    by_id = {record.id: record.datum for record in chain}
    try:
        status = effective(chain[0].datum, by_id.get, lo, hi)
    except LookupError as exc:
        raise GovernanceLookupError(f"{_did(chain[0].id)}: {exc}") from exc
    if status != Effective.ACTIVE:
        raise GovernanceRuleError(
            f"{_did(chain[0].id)} is {status.value} over the validity range; Module-6 needs an Active agent"
        )


def declared_key(record: AuthenticOutput[IdentityDatum], credential: Credential) -> bytes:
    """``identity.declared_credential``: a verification key whose hash is the
    hash of the controller or of a listed Ed25519 key with the transaction
    purpose. Returns the key hash, which must sign."""
    if not isinstance(credential, KeyCredential):
        raise GovernanceRuleError(
            f"the credential is a script credential; {_did(record.id)} needs its controller key or a listed key "
            "with the transaction purpose"
        )
    key_hash = credential.hash
    if key_hash != blake2b_224(record.datum.controller) and not active_key(record.datum, key_hash, PURPOSE_TRANSACTION):
        raise GovernanceRuleError(
            f"the key hash {key_hash.hex()} is not the controller of {_did(record.id)} or a listed key with the "
            "transaction purpose"
        )
    return key_hash


# ---------------------------------------------------------------------------
# Proposals (proposal_validation.ak, emergency.ak, activity_tracking.ak)
# ---------------------------------------------------------------------------


def emergency_stake(params: GovernanceParams) -> int:
    """``min_proposal_stake * emergency_stake_multiplier / 1000``."""
    return params.min_proposal_stake * params.emergency_stake_multiplier // 1000


def _type_problem(datum: ProposalDatum, params: GovernanceParams) -> str | None:
    """``validate_proposal_type``."""
    kind, values = datum.proposal_type.kind, datum.proposal_type.fields
    if kind == ProposalKind.PARAMETER_CHANGE:
        return None if values[0] in GOVERNABLE_PARAMS else f"{values[0]!r} is not a governable parameter"
    if kind == ProposalKind.TREASURY_SPEND:
        ok = 0 < values[0] <= params.max_treasury_request
        return None if ok else f"the treasury amount must be in (0, {params.max_treasury_request}]"
    if kind == ProposalKind.PROTOCOL_UPGRADE:
        return None if len(values[0]) == 32 else "the upgrade description hash is not 32 bytes"
    if kind == ProposalKind.GAME_ACTIVATION:
        return None if values[0] > 0 else "the game id must be positive"
    return None


def check_proposal(datum: ProposalDatum, params: GovernanceParams) -> None:
    """The rules of ``validate_submit_proposal`` that read only the datum and the
    parameters: stake, hash, type, URI, review window and the initial state."""
    problems = []
    if len(datum.proposer_did) != 32:
        problems.append("proposer_did is not a 32-byte identifier")
    if len(datum.proposal_hash) != 32:
        problems.append("proposal_hash is not 32 bytes")
    if not datum.storage_uri:
        problems.append("storage_uri is empty")
    type_problem = _type_problem(datum, params)
    if type_problem:
        problems.append(type_problem)
    if datum.priority == ProposalPriority.STANDARD:
        if datum.stake_amount < params.min_proposal_stake:
            problems.append(f"the stake is below {params.min_proposal_stake}")
        if not params.min_review_window <= datum.review_window <= params.max_review_window:
            problems.append(f"the review window must be in [{params.min_review_window}, {params.max_review_window}] ms")
    else:
        if datum.proposal_type.kind not in (ProposalKind.PARAMETER_CHANGE, ProposalKind.PROTOCOL_UPGRADE):
            problems.append("an emergency proposal is a ParameterChange or a ProtocolUpgrade")
        if datum.stake_amount < emergency_stake(params):
            problems.append(f"the stake of an emergency proposal is below {emergency_stake(params)}")
        if datum.review_window != params.emergency_review_window:
            problems.append(f"the review window of an emergency proposal is {params.emergency_review_window} ms")
    if datum.state.kind != StateKind.OPEN:
        problems.append("a new proposal is Open")
    if datum.amendment_count != 0 or datum.incorporated_critiques:
        problems.append("a new proposal has no amendment and no incorporated critique")
    _fail("the proposal", problems)


def check_rate_limit(node: ActivityDatum | None, agent: bytes, params: GovernanceParams, lo: int) -> None:
    """``validate_submit_activity`` for the node of the agent: fewer than
    ``max_active_proposals`` active proposals and the cooldown since the last one."""
    if node is None:
        return
    if node.agent_did != agent:
        raise GovernanceRuleError(f"the activity node of {_did(node.agent_did)} is not the node of {_did(agent)}")
    if node.active_proposal_count >= params.max_active_proposals:
        raise GovernanceRuleError(
            f"{_did(agent)} has {node.active_proposal_count} active proposals; the limit is "
            f"{params.max_active_proposals}"
        )
    allowed = node.last_proposal_slot + params.proposal_cooldown
    if lo < allowed:
        raise GovernanceRuleError(f"the proposal cooldown of {_did(agent)} ends at {allowed} (POSIX ms); lo is {lo}")


# ---------------------------------------------------------------------------
# Critiques and endorsements (critique_validation.ak)
# ---------------------------------------------------------------------------


def check_critique(datum: CritiqueDatum, proposal: ProposalDatum, params: GovernanceParams) -> None:
    """``validate_submit_critique`` besides identity, signature and the rule of different parties."""
    problems = []
    if len(datum.critic_did) != 32:
        problems.append("critic_did is not a 32-byte identifier")
    if not proposal.state.active:
        problems.append(f"the proposal is {proposal.state.kind.name}, not Open or Amended")
    if datum.stake_amount < params.min_critique_stake:
        problems.append(f"the stake is below {params.min_critique_stake}")
    if len(datum.critique_hash) != 32:
        problems.append("critique_hash is not 32 bytes")
    if datum.incorporated:
        problems.append("a new critique is not incorporated")
    if datum.critic_did == proposal.proposer_did and datum.critique_type.kind != CritiqueKind.AMENDMENT:
        problems.append("the proposer can submit only an Amendment critique of its own proposal")
    _fail("the critique", problems)


def check_endorsement(datum: EndorsementDatum, proposal: ProposalDatum, params: GovernanceParams) -> None:
    """``validate_submit_endorsement`` besides identity, signature and the rule of different parties."""
    problems = []
    if len(datum.endorser_did) != 32:
        problems.append("endorser_did is not a 32-byte identifier")
    if not proposal.state.active:
        problems.append(f"the proposal is {proposal.state.kind.name}, not Open or Amended")
    if datum.stake_amount < params.min_governance_endorsement:
        problems.append(f"the stake is below {params.min_governance_endorsement}")
    if datum.endorser_did == proposal.proposer_did:
        problems.append("an agent cannot endorse its own proposal")
    _fail("the endorsement", problems)


def _parent(record: IdentityDatum) -> bytes | None:
    return record.lineage.parent if isinstance(record.lineage, Subagent) else None


def check_distinct_parties(
    agent: AuthenticOutput[IdentityDatum],
    credential: Credential,
    proposal: ProposalDatum,
    proposer: AuthenticOutput[IdentityDatum],
) -> None:
    """``critique_validation.distinct_parties``: the agent (its record and its
    declared credential) and the proposer are different parties. The rule
    fails when the identifiers are equal, the controller keys are equal, the
    credential is the proposer credential, one record is a direct subagent of
    the other, or both are subagents of the same parent."""
    agent_parent, proposer_parent = _parent(agent.datum), _parent(proposer.datum)
    problems = []
    if agent.id == proposal.proposer_did:
        problems.append("the agent is the proposer")
    if agent.datum.controller == proposer.datum.controller:
        problems.append("the agent and the proposer have the same controller key")
    if credential == proposal.proposer_credential:
        problems.append("the credential of the agent is the proposer credential")
    if agent_parent == proposal.proposer_did:
        problems.append("the agent is a subagent of the proposer")
    if proposer_parent == agent.id:
        problems.append("the proposer is a subagent of the agent")
    if agent_parent is not None and agent_parent == proposer_parent:
        problems.append("the agent and the proposer are subagents of the same parent")
    if problems:
        raise GovernanceRuleError("the agent and the proposer are not different parties: " + "; ".join(problems))
