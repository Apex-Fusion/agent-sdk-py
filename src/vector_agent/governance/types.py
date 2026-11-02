"""On-chain types of the Self-Improvement module (Module-6, "Game 6").

Field order and constructor order are part of the on-chain format. They follow
``lib/governance_suggestion/types.ak`` of the Module-6 contracts
(Apex-Fusion/vector-agent-modules ``Module-6/contracts/governance-suggestion``
at commit ``91e3823``: the blueprint that :mod:`vector_agent.governance.scripts`
embeds).

- An agent identifier in a datum (``proposer_did``, ``critic_did``,
  ``endorser_did``, ``agent_did``) is the 32-byte identifier of an identity
  record (``did:vector``, Part 2 §7 of ``docs/IDENTITY_REGISTRY.md``). Positions
  of the old Module-6 deployment hold other bytes: the decoders accept any
  bytes, the builders accept only identifiers.
- Every time in a datum is POSIX time in milliseconds. ``submitted_at`` and
  ``created_at`` are the lower bound ``lo`` of the creation transaction.
- A critique or an endorsement names its proposal by the seed: the output
  reference that the SubmitProposal of the proposal spent. The proposal holds
  the token :func:`proposal_token_name` of the seed.

A record type is ``Constr 0`` with its fields in order. The constructors of a
sum type are numbered from 0 in the order shown. ``Bool`` is ``False = 0``,
``True = 1``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, fields
from enum import IntEnum

from vector_agent.identity.constants import LEGACY_REGISTRY_HASH
from vector_agent.identity.ids import blake2b_256, parse_vector_did
from vector_agent.identity.plutus_data import Constr, PlutusData, encode_data
from vector_agent.identity.types import (
    Credential,
    KeyCredential,
    OutputReference,
    ScriptCredential,
    _bool,
    _bool_data,
    _bytes,
    _Codec,
    _fields,
    _int,
    _list,
    _variant,
    credential_from_data,
)

__all__ = [
    "ACTIVITY_HEAD_TOKEN",
    "ORACLE_TOKEN",
    "PARAMS_TOKEN",
    "ActivityDatum",
    "Credential",
    "CritiqueAction",
    "CritiqueDatum",
    "CritiqueKind",
    "CritiqueType",
    "EndorsementAction",
    "EndorsementDatum",
    "GovernanceConfig",
    "GovernanceCrossRefs",
    "GovernanceOracleDatum",
    "GovernanceParams",
    "KeyCredential",
    "OutputReference",
    "ProposalAction",
    "ProposalDatum",
    "ProposalKind",
    "ProposalPriority",
    "ProposalState",
    "ProposalType",
    "ScriptCredential",
    "StateKind",
    "TreasuryBatchDatum",
    "activity_token_name",
    "agent_id",
    "critique_token_name",
    "endorsement_token_name",
    "proposal_token_name",
    "utf8",
]

#: Asset name of the record token of the GovernanceParams record (``record_auth.params_token_name``).
PARAMS_TOKEN = b"params"
#: Asset name of the record token of the oracle record (``record_auth.oracle_token_name``).
ORACLE_TOKEN = b"oracle"
#: Asset name of the record token of the head of the activity list (``utils.activity_head_token``).
ACTIVITY_HEAD_TOKEN = b"activity"

_ZERO_HASH = bytes(28)


def utf8(value: str | bytes) -> bytes:
    """UTF-8 bytes of text; bytes stay as they are."""
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def agent_id(value: str | bytes) -> bytes:
    """The 32-byte agent identifier of ``did:vector:<id>``, the legacy form
    ``did:vector:agent:<legacy policy>:<id>``, 64 lowercase hexadecimal
    characters or 32 bytes (Part 1 §3 of ``docs/did-vector-method.md``). The
    reserved ``testnet`` form and a legacy form with another policy are refused."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 32:
            raise ValueError(f"an agent identifier has 32 bytes, got {len(raw)}")
        return raw
    if not isinstance(value, str):
        raise TypeError("an agent identifier is a did:vector DID, 64 hexadecimal characters or 32 bytes")
    text = value.strip()
    parsed = parse_vector_did(text if text.startswith("did:") else f"did:vector:{text}")
    if parsed is None:
        raise ValueError(f"{text!r} is not a did:vector DID or 64 lowercase hexadecimal characters")
    if parsed.form == "network":
        raise ValueError(f"{text!r} uses the reserved testnet form")
    if parsed.form == "legacy" and parsed.policy_id != LEGACY_REGISTRY_HASH:
        raise ValueError(f"{text!r} names another policy than the legacy registry")
    return bytes.fromhex(parsed.vector_id)


# ---------------------------------------------------------------------------
# Token names (lib/governance_suggestion/utils.ak)
# ---------------------------------------------------------------------------


def _token(prefix: bytes, data: bytes) -> bytes:
    """``token_naming.derive_token_name(prefix, data, 27)``."""
    return prefix + blake2b_256(data)[:27]


def proposal_token_name(seed: OutputReference) -> bytes:
    """``"prop_" ++ blake2b_256(serialise(seed))[0..27]``: the token of the
    proposal whose SubmitProposal spent ``seed``."""
    return _token(b"prop_", encode_data(seed.to_data()))


def critique_token_name(locked: OutputReference) -> bytes:
    """``"crit_" ++ blake2b_256(serialise(locked))[0..27]``: the token of the
    critique whose MintCritiqueToken spent ``locked``."""
    return _token(b"crit_", encode_data(locked.to_data()))


def endorsement_token_name(endorser_did: bytes, proposal_ref: OutputReference) -> bytes:
    """``"gend_" ++ blake2b_256(endorser_did ++ serialise(proposal_ref))[0..27]``:
    the token of the endorsement of ``endorser_did`` for the proposal with the
    seed ``proposal_ref``."""
    return _token(b"gend_", bytes(endorser_did) + encode_data(proposal_ref.to_data()))


def activity_token_name(agent_did: bytes) -> bytes:
    """``"pact_" ++ blake2b_256(agent_did)[0..27]``: the token of the node of
    the agent in the activity list."""
    return _token(b"pact_", bytes(agent_did))


# ---------------------------------------------------------------------------
# §4.1 Proposals
# ---------------------------------------------------------------------------


class ProposalKind(IntEnum):
    """Constructors of ``ProposalType``."""

    PARAMETER_CHANGE = 0
    TREASURY_SPEND = 1
    PROTOCOL_UPGRADE = 2
    GAME_ACTIVATION = 3
    GENERAL_SUGGESTION = 4


_PROPOSAL_ARITIES = (3, 2, 1, 1, 0)


@dataclass(frozen=True)
class ProposalType(_Codec):
    """``ProposalType``: the kind and its fields in order.

    ``ParameterChange { param_name, current_value, proposed_value }``,
    ``TreasurySpend { amount, recipient_description }``,
    ``ProtocolUpgrade { upgrade_description_hash }``, ``GameActivation { game_id }``
    and ``GeneralSuggestion``.
    """

    kind: ProposalKind
    fields: tuple[PlutusData, ...] = ()

    @classmethod
    def parameter_change(cls, param_name: str | bytes, current_value: int, proposed_value: int) -> ProposalType:
        return cls(ProposalKind.PARAMETER_CHANGE, (utf8(param_name), int(current_value), int(proposed_value)))

    @classmethod
    def treasury_spend(cls, amount: int, recipient_description: str | bytes) -> ProposalType:
        return cls(ProposalKind.TREASURY_SPEND, (int(amount), utf8(recipient_description)))

    @classmethod
    def protocol_upgrade(cls, upgrade_description_hash: bytes) -> ProposalType:
        return cls(ProposalKind.PROTOCOL_UPGRADE, (bytes(upgrade_description_hash),))

    @classmethod
    def game_activation(cls, game_id: int) -> ProposalType:
        return cls(ProposalKind.GAME_ACTIVATION, (int(game_id),))

    @classmethod
    def general_suggestion(cls) -> ProposalType:
        return cls(ProposalKind.GENERAL_SUGGESTION)

    def to_data(self) -> Constr:
        return Constr(int(self.kind), tuple(self.fields))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "ProposalType") -> ProposalType:
        index, values = _variant(data, path, _PROPOSAL_ARITIES)
        kind = ProposalKind(index)
        kinds = {
            ProposalKind.PARAMETER_CHANGE: (_bytes, _int, _int),
            ProposalKind.TREASURY_SPEND: (_int, _bytes),
            ProposalKind.PROTOCOL_UPGRADE: (_bytes,),
            ProposalKind.GAME_ACTIVATION: (_int,),
            ProposalKind.GENERAL_SUGGESTION: (),
        }[kind]
        return cls(kind, tuple(read(v, f"{path}[{i}]") for i, (read, v) in enumerate(zip(kinds, values, strict=True))))


class ProposalPriority(IntEnum):
    """``ProposalPriority``: ``Standard`` or ``Emergency``."""

    STANDARD = 0
    EMERGENCY = 1


class StateKind(IntEnum):
    """Constructors of ``ProposalState``."""

    OPEN = 0
    AMENDED = 1
    ADOPTED = 2
    REJECTED = 3
    EXPIRED = 4
    WITHDRAWN = 5


_STATES_WITH_HASH = frozenset({StateKind.AMENDED, StateKind.ADOPTED, StateKind.REJECTED})


@dataclass(frozen=True)
class ProposalState(_Codec):
    """``ProposalState``. ``hash`` is ``previous_hash`` of ``Amended`` and the
    reasoning hash of ``Adopted`` and ``Rejected``; the other states have none."""

    kind: StateKind = StateKind.OPEN
    hash: bytes | None = None

    def __post_init__(self) -> None:
        if (self.hash is not None) != (self.kind in _STATES_WITH_HASH):
            raise ValueError(f"the state {self.kind.name} {'needs' if self.hash is None else 'has no'} hash")

    @classmethod
    def amended(cls, previous_hash: bytes) -> ProposalState:
        return cls(StateKind.AMENDED, bytes(previous_hash))

    @classmethod
    def adopted(cls, reasoning_hash: bytes) -> ProposalState:
        return cls(StateKind.ADOPTED, bytes(reasoning_hash))

    @classmethod
    def rejected(cls, reasoning_hash: bytes) -> ProposalState:
        return cls(StateKind.REJECTED, bytes(reasoning_hash))

    @property
    def active(self) -> bool:
        """``utils.is_proposal_active``: Open or Amended."""
        return self.kind in (StateKind.OPEN, StateKind.AMENDED)

    def to_data(self) -> Constr:
        return Constr(int(self.kind), () if self.hash is None else (self.hash,))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "ProposalState") -> ProposalState:
        index, values = _variant(data, path, (0, 1, 1, 1, 0, 0))
        return cls(StateKind(index), _bytes(values[0], f"{path}.hash") if values else None)


ProposalState.OPEN = ProposalState()
ProposalState.EXPIRED = ProposalState(StateKind.EXPIRED)
ProposalState.WITHDRAWN = ProposalState(StateKind.WITHDRAWN)


def _out_refs(data: PlutusData, path: str) -> tuple[OutputReference, ...]:
    return _list(data, path, OutputReference.from_data)


@dataclass(frozen=True)
class ProposalDatum(_Codec):
    """``ProposalDatum`` (12 fields)."""

    proposer_did: bytes
    proposer_credential: Credential
    proposal_hash: bytes
    proposal_type: ProposalType
    storage_uri: bytes
    stake_amount: int
    submitted_at: int
    review_window: int
    priority: ProposalPriority = ProposalPriority.STANDARD
    amendment_count: int = 0
    incorporated_critiques: tuple[OutputReference, ...] = ()
    state: ProposalState = ProposalState.OPEN

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.proposer_did,
                self.proposer_credential.to_data(),
                self.proposal_hash,
                self.proposal_type.to_data(),
                self.storage_uri,
                self.stake_amount,
                self.submitted_at,
                self.review_window,
                Constr(int(self.priority)),
                self.amendment_count,
                [r.to_data() for r in self.incorporated_critiques],
                self.state.to_data(),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "ProposalDatum") -> ProposalDatum:
        f = _fields(data, path, 0, 12)
        priority, _ = _variant(f[8], f"{path}.priority", (0, 0))
        return cls(
            proposer_did=_bytes(f[0], f"{path}.proposer_did"),
            proposer_credential=credential_from_data(f[1], f"{path}.proposer_credential"),
            proposal_hash=_bytes(f[2], f"{path}.proposal_hash"),
            proposal_type=ProposalType.from_data(f[3], f"{path}.proposal_type"),
            storage_uri=_bytes(f[4], f"{path}.storage_uri"),
            stake_amount=_int(f[5], f"{path}.stake_amount"),
            submitted_at=_int(f[6], f"{path}.submitted_at"),
            review_window=_int(f[7], f"{path}.review_window"),
            priority=ProposalPriority(priority),
            amendment_count=_int(f[9], f"{path}.amendment_count"),
            incorporated_critiques=_out_refs(f[10], f"{path}.incorporated_critiques"),
            state=ProposalState.from_data(f[11], f"{path}.state"),
        )


# ---------------------------------------------------------------------------
# §4.6 Activity list
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActivityDatum(_Codec):
    """``ProposerActivityDatum`` (5 fields): an entry of the activity list.

    The head has ``agent_did == b""``; a node holds the activity of one agent.
    ``last_proposal_slot`` is POSIX milliseconds (``lo`` of the last
    submission). ``next_did`` is the identifier of the next node in ascending
    byte order, or ``b""`` for the last entry.
    """

    agent_did: bytes
    agent_credential: Credential
    active_proposal_count: int
    last_proposal_slot: int
    next_did: bytes = b""

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.agent_did,
                self.agent_credential.to_data(),
                self.active_proposal_count,
                self.last_proposal_slot,
                self.next_did,
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "ProposerActivityDatum") -> ActivityDatum:
        f = _fields(data, path, 0, 5)
        return cls(
            agent_did=_bytes(f[0], f"{path}.agent_did"),
            agent_credential=credential_from_data(f[1], f"{path}.agent_credential"),
            active_proposal_count=_int(f[2], f"{path}.active_proposal_count"),
            last_proposal_slot=_int(f[3], f"{path}.last_proposal_slot"),
            next_did=_bytes(f[4], f"{path}.next_did"),
        )


# ---------------------------------------------------------------------------
# §4.2 Critiques and §4.3 endorsements
# ---------------------------------------------------------------------------


class CritiqueKind(IntEnum):
    """Constructors of ``CritiqueType``."""

    SUPPORTIVE = 0
    OPPOSING = 1
    AMENDMENT = 2


@dataclass(frozen=True)
class CritiqueType(_Codec):
    """``CritiqueType``: ``Supportive``, ``Opposing`` or ``Amendment { suggested_change_hash }``."""

    kind: CritiqueKind = CritiqueKind.SUPPORTIVE
    suggested_change_hash: bytes | None = None

    def __post_init__(self) -> None:
        if (self.suggested_change_hash is not None) != (self.kind == CritiqueKind.AMENDMENT):
            raise ValueError("only an Amendment critique has a suggested change hash")

    @classmethod
    def amendment(cls, suggested_change_hash: bytes) -> CritiqueType:
        return cls(CritiqueKind.AMENDMENT, bytes(suggested_change_hash))

    def to_data(self) -> Constr:
        return Constr(int(self.kind), () if self.suggested_change_hash is None else (self.suggested_change_hash,))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "CritiqueType") -> CritiqueType:
        index, values = _variant(data, path, (0, 0, 1))
        return cls(CritiqueKind(index), _bytes(values[0], f"{path}.suggested_change_hash") if values else None)


CritiqueType.SUPPORTIVE = CritiqueType(CritiqueKind.SUPPORTIVE)
CritiqueType.OPPOSING = CritiqueType(CritiqueKind.OPPOSING)


@dataclass(frozen=True)
class CritiqueDatum(_Codec):
    """``CritiqueDatum`` (9 fields). ``proposal_ref`` is the seed of the proposal."""

    critic_did: bytes
    critic_credential: Credential
    proposal_ref: OutputReference
    critique_hash: bytes
    storage_uri: bytes
    critique_type: CritiqueType
    stake_amount: int
    submitted_at: int
    incorporated: bool = False

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.critic_did,
                self.critic_credential.to_data(),
                self.proposal_ref.to_data(),
                self.critique_hash,
                self.storage_uri,
                self.critique_type.to_data(),
                self.stake_amount,
                self.submitted_at,
                _bool_data(self.incorporated),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "CritiqueDatum") -> CritiqueDatum:
        f = _fields(data, path, 0, 9)
        return cls(
            critic_did=_bytes(f[0], f"{path}.critic_did"),
            critic_credential=credential_from_data(f[1], f"{path}.critic_credential"),
            proposal_ref=OutputReference.from_data(f[2], f"{path}.proposal_ref"),
            critique_hash=_bytes(f[3], f"{path}.critique_hash"),
            storage_uri=_bytes(f[4], f"{path}.storage_uri"),
            critique_type=CritiqueType.from_data(f[5], f"{path}.critique_type"),
            stake_amount=_int(f[6], f"{path}.stake_amount"),
            submitted_at=_int(f[7], f"{path}.submitted_at"),
            incorporated=_bool(f[8], f"{path}.incorporated"),
        )


@dataclass(frozen=True)
class EndorsementDatum(_Codec):
    """``GovernanceEndorsementDatum`` (5 fields). ``proposal_ref`` is the seed of the proposal."""

    endorser_did: bytes
    endorser_credential: Credential
    proposal_ref: OutputReference
    stake_amount: int
    created_at: int

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.endorser_did,
                self.endorser_credential.to_data(),
                self.proposal_ref.to_data(),
                self.stake_amount,
                self.created_at,
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "GovernanceEndorsementDatum") -> EndorsementDatum:
        f = _fields(data, path, 0, 5)
        return cls(
            endorser_did=_bytes(f[0], f"{path}.endorser_did"),
            endorser_credential=credential_from_data(f[1], f"{path}.endorser_credential"),
            proposal_ref=OutputReference.from_data(f[2], f"{path}.proposal_ref"),
            stake_amount=_int(f[3], f"{path}.stake_amount"),
            created_at=_int(f[4], f"{path}.created_at"),
        )


# ---------------------------------------------------------------------------
# §4.4 Oracle, §4.5 parameters, §9.4 treasury batches
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceOracleDatum(_Codec):
    """``GovernanceOracleDatum``: the oracle credential (a verification key for
    the validators), the treasury script hash and whether the oracle is active."""

    oracle_credential: Credential
    treasury_script_hash: bytes
    oracle_active: bool = True

    def to_data(self) -> Constr:
        return Constr(
            0, (self.oracle_credential.to_data(), self.treasury_script_hash, _bool_data(self.oracle_active))
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "GovernanceOracleDatum") -> GovernanceOracleDatum:
        f = _fields(data, path, 0, 3)
        return cls(
            credential_from_data(f[0], f"{path}.oracle_credential"),
            _bytes(f[1], f"{path}.treasury_script_hash"),
            _bool(f[2], f"{path}.oracle_active"),
        )


@dataclass(frozen=True)
class TreasuryBatchDatum(_Codec):
    """``TreasuryBatchDatum { batch_id, active }``."""

    batch_id: int
    active: bool = True

    def to_data(self) -> Constr:
        return Constr(0, (self.batch_id, _bool_data(self.active)))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "TreasuryBatchDatum") -> TreasuryBatchDatum:
        f = _fields(data, path, 0, 2)
        return cls(_int(f[0], f"{path}.batch_id"), _bool(f[1], f"{path}.active"))


@dataclass(frozen=True)
class GovernanceParams(_Codec):
    """``GovernanceParams`` (21 fields). Times are POSIX milliseconds, shares and
    rates are basis points, amounts are base units (1 AP3X = 1,000,000)."""

    min_proposal_stake: int
    min_critique_stake: int
    min_governance_endorsement: int
    min_review_window: int
    max_review_window: int
    max_amendments: int
    max_active_proposals: int
    proposal_cooldown: int
    proposer_reward_share: int
    critic_reward_share: int
    protocol_fee_rate: int
    min_adoption_reward: int
    max_adoption_reward: int
    max_incorporated_critiques: int
    max_treasury_request: int
    emergency_stake_multiplier: int
    emergency_review_window: int
    param_execution_delay: int
    min_prediction_pool: int
    credibility_pool_low_threshold: int
    credibility_pool_critical_threshold: int

    def to_data(self) -> Constr:
        return Constr(0, tuple(getattr(self, f.name) for f in fields(self)))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "GovernanceParams") -> GovernanceParams:
        names = [f.name for f in fields(cls)]
        values = _fields(data, path, 0, len(names))
        return cls(*(_int(v, f"{path}.{name}") for v, name in zip(values, names, strict=True)))

    def module6_value(self, param_name: bytes) -> int | None:
        """``params.module6_param_value``: the value of a Module-6 parameter name
        (17 names map to the first 17 fields), else None."""
        index = _MODULE6_PARAMS.get(bytes(param_name))
        return None if index is None else getattr(self, fields(self)[index].name)


#: ``params.module6_param_value``: the parameter names and their field index.
_MODULE6_PARAMS = {
    name.encode(): index
    for index, name in enumerate(
        (
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
        )
    )
}


# ---------------------------------------------------------------------------
# §11.2 Configuration and the cross references
# ---------------------------------------------------------------------------


def _hash28(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 28:
        raise ValueError(f"{name}: expected 28 bytes, got {len(raw)}")
    return raw


@dataclass(frozen=True)
class GovernanceConfig(_Codec):
    """``GovernanceConfig`` (11 fields): the parameter of every Module-6
    validator. ``identity_hash`` (last) is the identity registry script hash.

    The deploy script of Module-6 keeps ``prediction_validator_hash``,
    ``reputation_validator_hash``, ``jury_pool_hash``, ``credibility_pool_hash``
    and ``protocol_params_hash`` at zero.
    """

    refs_token_policy: bytes
    prediction_validator_hash: bytes
    reputation_validator_hash: bytes
    jury_pool_hash: bytes
    governance_oracle_hash: bytes
    governance_params_hash: bytes
    governance_treasury_hash: bytes
    credibility_pool_hash: bytes
    protocol_params_hash: bytes
    record_token_policy: bytes
    identity_hash: bytes

    def __post_init__(self) -> None:
        for f in fields(self):
            object.__setattr__(self, f.name, _hash28(getattr(self, f.name), f.name))

    @property
    def module3_deployed(self) -> bool:
        """The validators skip the Module-3 checks while ``reputation_validator_hash`` is zero."""
        return self.reputation_validator_hash != _ZERO_HASH

    def to_data(self) -> Constr:
        return Constr(0, tuple(getattr(self, f.name) for f in fields(self)))

    def parameter_cbor(self) -> bytes:
        """The CBOR of the validator parameter, in the form that the Module-6
        deploy script gives to ``aiken blueprint apply``
        (``scripts/deploy_common.py`` ``build_governance_config_cbor``): tag 121
        and a definite array of the 11 byte strings.

        ``aiken blueprint apply`` keeps the CBOR form of its argument, so the
        script hashes depend on it: the indefinite form of :meth:`to_cbor` gives
        other scripts than the deployed ones.
        """
        values = [getattr(self, f.name) for f in fields(self)]
        return bytes([0xD8, 0x79, 0x80 + len(values)]) + b"".join(b"\x58\x1c" + value for value in values)

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "GovernanceConfig") -> GovernanceConfig:
        names = [f.name for f in fields(cls)]
        values = _fields(data, path, 0, len(names))
        return cls(*(_bytes(v, f"{path}.{name}", 28) for v, name in zip(values, names, strict=True)))


@dataclass(frozen=True)
class GovernanceCrossRefs(_Codec):
    """``GovernanceCrossRefs`` (5 fields): the hashes that the validators read at
    run time. ``endorsement_validator_hash`` is last; a 4-field datum of an older
    deployment does not decode."""

    proposal_validator_hash: bytes
    critique_validator_hash: bytes
    proposal_mint_hash: bytes
    critique_mint_hash: bytes
    endorsement_validator_hash: bytes

    def __post_init__(self) -> None:
        for f in fields(self):
            object.__setattr__(self, f.name, _hash28(getattr(self, f.name), f.name))

    def to_data(self) -> Constr:
        return Constr(0, tuple(getattr(self, f.name) for f in fields(self)))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "GovernanceCrossRefs") -> GovernanceCrossRefs:
        names = [f.name for f in fields(cls)]
        values = _fields(data, path, 0, len(names))
        return cls(*(_bytes(v, f"{path}.{name}", 28) for v, name in zip(values, names, strict=True)))


# ---------------------------------------------------------------------------
# Redeemers
# ---------------------------------------------------------------------------


class ProposalAction:
    """Redeemers of the proposal validator and the proposal mint policy (``ProposalAction``)."""

    SUBMIT = Constr(0)
    WITHDRAW = Constr(1)
    EXPIRE = Constr(5)
    EXPIRE_STALE = Constr(6)
    SPEND_ACTIVITY = Constr(8)

    @staticmethod
    def amend(new_hash: bytes, new_uri: str | bytes, incorporated: Sequence[OutputReference] = ()) -> Constr:
        """``AmendProposal { new_hash, new_uri, incorporated }``."""
        return Constr(2, (bytes(new_hash), utf8(new_uri), [r.to_data() for r in incorporated]))

    @staticmethod
    def adopt(reasoning_hash: bytes, reward_amount: int) -> Constr:
        """``AdoptProposal { reasoning_hash, reward_amount }``."""
        return Constr(3, (bytes(reasoning_hash), int(reward_amount)))

    @staticmethod
    def reject(reasoning_hash: bytes) -> Constr:
        """``RejectProposal { reasoning_hash }``."""
        return Constr(4, (bytes(reasoning_hash),))

    @staticmethod
    def extend_review(additional_ms: int) -> Constr:
        """``ExtendReview { additional_slots }``: the field holds milliseconds."""
        return Constr(7, (int(additional_ms),))


class CritiqueAction:
    """Redeemers of the critique validator (``CritiqueAction``)."""

    MINT = Constr(0)
    WITHDRAW = Constr(1)
    INCORPORATE = Constr(2)
    BURN = Constr(4)

    @staticmethod
    def reward(reward_share: int) -> Constr:
        """``RewardCritique { reward_share }``."""
        return Constr(3, (int(reward_share),))


class EndorsementAction:
    """Redeemers of the endorsement validator (``GovernanceEndorsementAction``)."""

    MINT = Constr(0)
    WITHDRAW = Constr(1)
    BURN = Constr(2)
