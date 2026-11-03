"""The Module-6 context: deployment, scripts, clock and ledger reads.

The Module-6 validators accept an output only when it is at the exact script
address and holds the right token:

- an identity record (``vector_identity.find_record``): at the exact identity
  address (``Script(identity_hash)``, no stake part), exactly one token of the
  identity policy, named by the identifier, and an inline datum;
- the parameters and the oracle record (``record_auth.find_record``): at the
  holder script with the record token ``params`` or ``oracle`` of
  ``record_token_policy`` (quantity 1);
- the cross references (``utils.get_cross_refs``): a token of
  ``refs_token_policy``. The client also needs the 5-field datum to name the
  validators of this deployment;
- the head of the activity list: at the proposal validator with the record
  token ``activity``; a node: at the proposal validator with exactly the
  activity token of its agent;
- a submitted proposal, critique or endorsement: at its validator with its
  token (``prop_``, ``crit_``, ``gend_``).

Outputs that only look like these are ignored.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property
from typing import Generic, TypeVar

from pycardano import Address, ScriptHash, UTxO
from pycardano.backend.base import ChainContext
from pycardano.plutus import script_hash as pycardano_script_hash

from vector_agent.governance.deployment import ENV_VARS, GovernanceDeployment
from vector_agent.governance.errors import GovernanceConfigError, GovernanceLookupError, GovernanceRuleError
from vector_agent.governance.scripts import GovernanceScripts
from vector_agent.governance.types import (
    ACTIVITY_HEAD_TOKEN,
    ORACLE_TOKEN,
    PARAMS_TOKEN,
    ActivityDatum,
    CritiqueDatum,
    EndorsementDatum,
    GovernanceConfig,
    GovernanceCrossRefs,
    GovernanceOracleDatum,
    GovernanceParams,
    ProposalDatum,
    activity_token_name,
    agent_id,
    proposal_token_name,
)
from vector_agent.identity.chain import Ledger, OgmiosKoiosLedger, SlotClock
from vector_agent.identity.constants import DEFAULT_KOIOS_URL, DEFAULT_OGMIOS_URL, MAX_DEPTH
from vector_agent.identity.context import AuthenticOutput, ScriptSource, datum_bytes, utxo_ref
from vector_agent.identity.ids import blake2b_256, vector_did
from vector_agent.identity.plutus_data import PlutusDataError, decode_data
from vector_agent.identity.scripts import enterprise_address
from vector_agent.identity.types import IdentityDatum, OutputReference, Subagent

__all__ = [
    "ActivityList",
    "GovernanceContext",
    "Position",
    "policy_tokens",
]

D = TypeVar("D")


def policy_tokens(utxo: UTxO, policy: bytes) -> dict[bytes, int]:
    """The tokens of ``policy`` in an output: {asset name: quantity}."""
    amount = utxo.output.amount
    if isinstance(amount, int):
        return {}
    bundle = amount.multi_asset.get(ScriptHash(bytes(policy)), {})
    return {bytes(name.payload): int(quantity) for name, quantity in bundle.items() if int(quantity) != 0}


def _lovelace(utxo: UTxO) -> int:
    amount = utxo.output.amount
    return amount if isinstance(amount, int) else amount.coin


def _payment_script(utxo: UTxO) -> bytes | None:
    part = utxo.output.address.payment_part
    return bytes(part.payload) if isinstance(part, ScriptHash) else None


@dataclass(frozen=True)
class Position(Generic[D]):
    """An output at a Module-6 validator and its decoded datum. ``token`` is
    the position token (``prop_``, ``crit_``, ``gend_``, ``pact_``), or None for
    a lock and for the head of the activity list."""

    utxo: UTxO
    datum: D
    token: bytes | None = None

    @property
    def ref(self) -> OutputReference:
        return utxo_ref(self.utxo)

    @property
    def lovelace(self) -> int:
        return _lovelace(self.utxo)


@dataclass(frozen=True)
class ActivityList:
    """The activity list at the proposal validator (``activity_tracking.ak``):
    the head and the nodes in list order, that is in ascending byte order of
    the agent identifier."""

    head: Position[ActivityDatum]
    nodes: tuple[Position[ActivityDatum], ...] = ()

    @property
    def entries(self) -> tuple[Position[ActivityDatum], ...]:
        return (self.head, *self.nodes)

    def node(self, agent: bytes) -> Position[ActivityDatum] | None:
        """The node of ``agent``, or None before its first proposal."""
        return next((n for n in self.nodes if n.datum.agent_did == agent), None)

    def predecessor(self, agent: bytes) -> Position[ActivityDatum]:
        """The entry P after which the first submission of ``agent`` (X) inserts
        the node of X: ``P.agent_did < X`` and (``P.next_did == b""`` or
        ``X < P.next_did``). An agent with a node has no predecessor: the
        contract accepts one node per agent."""
        if self.node(agent) is not None:
            raise GovernanceRuleError(
                f"{vector_did(agent.hex())} already has a node in the activity list; its next submission spends it"
            )
        for entry in self.entries:
            datum = entry.datum
            if datum.agent_did < agent and (datum.next_did == b"" or agent < datum.next_did):
                return entry
        raise GovernanceLookupError(f"the activity list has no predecessor for {vector_did(agent.hex())}")

    def submission_input(self, agent: bytes) -> Position[ActivityDatum]:
        """The entry that a submission of ``agent`` spends: its node, or for its
        first proposal its predecessor."""
        node = self.node(agent)
        return node if node is not None else self.predecessor(agent)


class GovernanceContext:
    """Deployment, scripts, clock and ledger reads that the Module-6 builders share."""

    def __init__(
        self,
        ledger: Ledger,
        deployment: GovernanceDeployment | None = None,
        *,
        clock: SlotClock | None = None,
    ) -> None:
        self.ledger = ledger
        self.deployment = deployment if deployment is not None else GovernanceDeployment.from_env()
        self._clock = clock

    @classmethod
    def connect(
        cls,
        deployment: GovernanceDeployment | None = None,
        *,
        ogmios_url: str = DEFAULT_OGMIOS_URL,
        koios_url: str = DEFAULT_KOIOS_URL,
        koios_token: str | None = None,
        context: ChainContext | None = None,
        submit_url: str | None = None,
    ) -> GovernanceContext:
        """A context on Ogmios and Koios (Vector mainnet by default)."""
        ledger = OgmiosKoiosLedger(
            ogmios_url=ogmios_url,
            koios_url=koios_url,
            koios_token=koios_token,
            context=context,
            submit_url=submit_url,
        )
        return cls(ledger, deployment)

    @cached_property
    def scripts(self) -> GovernanceScripts:
        return self.deployment.scripts()

    @property
    def config(self) -> GovernanceConfig:
        return self.scripts.config

    @property
    def clock(self) -> SlotClock:
        if self._clock is None:
            self._clock = SlotClock.from_context(self.ledger.context)
        return self._clock

    def address_of(self, address: str | Address) -> Address:
        return address if isinstance(address, Address) else Address.from_primitive(address)

    # ------------------------------------------------------------------
    # Scripts
    # ------------------------------------------------------------------

    def script_source(self, name: str) -> ScriptSource:
        """The script ``name`` from its configured reference output, else the script itself."""
        info = self.scripts.by_name(name)
        ref = self.deployment.reference(name)
        if ref is None:
            return ScriptSource(info.plutus_script)
        utxo = self.ledger.utxo(ref)
        variable = ENV_VARS[f"{name}_ref"]
        if utxo is None:
            raise GovernanceConfigError(f"{variable}: {ref} is spent or unknown")
        script = utxo.output.script
        if script is None or bytes(pycardano_script_hash(script).payload) != info.hash:
            raise GovernanceConfigError(f"{variable}: {ref} does not hold the script {info.hash_hex}")
        return ScriptSource(info.plutus_script, utxo)

    # ------------------------------------------------------------------
    # Identity records
    # ------------------------------------------------------------------

    @property
    def identity_address(self) -> Address:
        return enterprise_address(self.config.identity_hash)

    def find_record(self, agent: str | bytes) -> AuthenticOutput[IdentityDatum] | None:
        """The record output of ``agent`` (live record or tombstone), or None."""
        name = agent_id(agent)
        identity_hash = self.config.identity_hash
        address = self.identity_address
        found = []
        for utxo in self.ledger.token_utxos(identity_hash, name):
            if utxo.output.address != address or policy_tokens(utxo, identity_hash) != {name: 1}:
                continue
            raw = datum_bytes(utxo)
            if raw is None:
                continue
            try:
                found.append(AuthenticOutput(utxo, IdentityDatum.from_cbor(raw), name))
            except (PlutusDataError, ValueError) as exc:
                raise GovernanceLookupError(f"the record of {vector_did(name.hex())} does not decode: {exc}") from exc
        if len(found) > 1:
            raise GovernanceLookupError(f"{vector_did(name.hex())}: more than one record output")
        return found[0] if found else None

    def record(self, agent: str | bytes) -> AuthenticOutput[IdentityDatum]:
        found = self.find_record(agent)
        if found is None:
            raise GovernanceLookupError(
                f"no identity record of {vector_did(agent_id(agent).hex())} at the identity address "
                f"{self.identity_address}"
            )
        return found

    def record_chain(self, agent: str | bytes) -> list[AuthenticOutput[IdentityDatum]]:
        """The record of ``agent`` and the records of its ancestors (at most 4),
        which ``vector_identity.effective`` reads."""
        chain = [self.record(agent)]
        while isinstance(chain[-1].datum.lineage, Subagent):
            if len(chain) > MAX_DEPTH:
                raise GovernanceLookupError(f"the lineage of {vector_did(agent_id(agent).hex())} is deeper than 4")
            chain.append(self.record(chain[-1].datum.lineage.parent))
        return chain

    # ------------------------------------------------------------------
    # Records of the deployment
    # ------------------------------------------------------------------

    def _holder_record(
        self, holder: bytes, token: bytes, ref: OutputReference | None, variable: str
    ) -> UTxO:
        policy = self.config.record_token_policy
        if ref is not None:
            utxo = self.ledger.utxo(ref)
            if utxo is None or _payment_script(utxo) != holder or policy_tokens(utxo, policy).get(token) != 1:
                raise GovernanceConfigError(f"{variable}: {ref} does not hold the {token.decode()} record")
            return utxo
        for utxo in self.ledger.utxos_at(str(enterprise_address(holder))):
            if policy_tokens(utxo, policy).get(token) == 1 and utxo.output.datum is not None:
                return utxo
        raise GovernanceLookupError(
            f"no {token.decode()} record at {enterprise_address(holder)}: no output there holds the record "
            f"token {policy.hex()}.{token.decode()}"
        )

    def params_record(self) -> AuthenticOutput[GovernanceParams]:
        """The parameters record (``params.read_governance_params``)."""
        utxo = self._holder_record(
            self.config.governance_params_hash, PARAMS_TOKEN, self.deployment.params_utxo, ENV_VARS["params_utxo"]
        )
        return AuthenticOutput(utxo, _decode(utxo, GovernanceParams.from_cbor, "the parameters record"), PARAMS_TOKEN)

    def oracle_record(self) -> AuthenticOutput[GovernanceOracleDatum]:
        """The oracle record that adoption, rejection and review extension read."""
        utxo = self._holder_record(
            self.config.governance_oracle_hash, ORACLE_TOKEN, self.deployment.oracle_utxo, ENV_VARS["oracle_utxo"]
        )
        datum = _decode(utxo, GovernanceOracleDatum.from_cbor, "the oracle record")
        return AuthenticOutput(utxo, datum, ORACLE_TOKEN)

    def cross_refs_record(self) -> UTxO:
        """The output with a ``refs_token_policy`` token whose 5-field datum names
        the validators of this deployment."""
        expected = self.scripts.cross_refs
        policy = self.config.refs_token_policy
        ref = self.deployment.cross_refs_utxo
        if ref is not None:
            candidates = [u for u in [self.ledger.utxo(ref)] if u is not None]
        else:
            candidates = self.ledger.utxos_at(str(enterprise_address(self.config.governance_oracle_hash)))
        matches = [u for u in candidates if policy_tokens(u, policy) and _cross_refs(u) == expected]
        if not matches:
            where = f"{ENV_VARS['cross_refs_utxo']} {ref}" if ref is not None else "the oracle holder address"
            raise GovernanceLookupError(
                f"no cross references of this deployment at {where}: no output with a {policy.hex()} token names "
                f"proposal_spend {expected.proposal_validator_hash.hex()}, critique_spend "
                f"{expected.critique_validator_hash.hex()}, proposal_mint {expected.proposal_mint_hash.hex()}, "
                f"critique_mint {expected.critique_mint_hash.hex()} and endorsement_spend "
                f"{expected.endorsement_validator_hash.hex()}"
            )
        return min(matches, key=lambda u: (bytes(u.input.transaction_id), u.input.index))

    # ------------------------------------------------------------------
    # The activity list
    # ------------------------------------------------------------------

    def activity_list(self) -> ActivityList:
        """The activity list from the outputs at the proposal validator.

        The client walks from the head through ``next_did``. Each named node
        must exist, the order must be strictly ascending, and every node must be
        on the walk. A list that breaks these rules cannot come from the
        contract rules, so the client refuses it."""
        proposal_spend = self.scripts.proposal_spend
        mint_policy = self.scripts.proposal_mint.hash
        record_policy = self.config.record_token_policy
        heads: list[Position[ActivityDatum]] = []
        nodes: dict[bytes, Position[ActivityDatum]] = {}
        for utxo in self.ledger.utxos_at(str(proposal_spend.address)):
            if utxo.output.address != proposal_spend.address:
                continue
            head_tokens = policy_tokens(utxo, record_policy).get(ACTIVITY_HEAD_TOKEN, 0)
            tokens = policy_tokens(utxo, mint_policy)
            if not head_tokens and not any(name.startswith(b"pact_") for name in tokens):
                continue  # proposals and locks
            datum = _decode(utxo, ActivityDatum.from_cbor, f"the activity list entry {utxo_ref(utxo)}")
            if head_tokens:
                if head_tokens != 1 or tokens or datum.agent_did != b"":
                    raise GovernanceLookupError(f"{utxo_ref(utxo)} holds the activity record token but is not a head")
                heads.append(Position(utxo, datum))
                continue
            if not datum.agent_did or tokens != {activity_token_name(datum.agent_did): 1}:
                raise GovernanceLookupError(f"{utxo_ref(utxo)} holds an activity token but is not a node of its agent")
            if datum.agent_did in nodes:
                raise GovernanceLookupError(f"{vector_did(datum.agent_did.hex())} has several activity nodes")
            nodes[datum.agent_did] = Position(utxo, datum, activity_token_name(datum.agent_did))
        if not heads:
            raise GovernanceLookupError(
                f"no head of the activity list at {proposal_spend.address}: no output there holds the record "
                f"token {record_policy.hex()}.{ACTIVITY_HEAD_TOKEN.decode()}"
            )
        if len(heads) > 1:
            raise GovernanceLookupError("several outputs hold the activity record token")
        ordered: list[Position[ActivityDatum]] = []
        previous, following = heads[0].datum.agent_did, heads[0].datum.next_did
        while following:
            node = nodes.get(following)
            if node is None:
                raise GovernanceLookupError(f"the activity list names {following.hex()}, which has no node")
            if not previous < following:
                raise GovernanceLookupError("the activity list is not in ascending order")
            ordered.append(node)
            previous, following = node.datum.agent_did, node.datum.next_did
        if len(ordered) != len(nodes):
            raise GovernanceLookupError("some activity nodes are not on the list that starts at the head")
        return ActivityList(heads[0], tuple(ordered))

    # ------------------------------------------------------------------
    # Positions
    # ------------------------------------------------------------------

    def _position(self, ref: OutputReference, script_name: str, decode, what: str, prefix: bytes) -> Position:
        utxo = self.ledger.utxo(ref)
        script = self.scripts.by_name(script_name)
        if utxo is None:
            raise GovernanceLookupError(f"the {what} {ref} is spent or unknown")
        if utxo.output.address != script.address:
            raise GovernanceLookupError(f"{ref} is not at the {what} validator {script.hash_hex}")
        datum = _decode(utxo, decode, f"the {what} {ref}")
        mint = self.scripts.critique_mint.hash if prefix in (b"crit_", b"gend_") else self.scripts.proposal_mint.hash
        names = [n for n, q in policy_tokens(utxo, mint).items() if n.startswith(prefix) and q == 1]
        return Position(utxo, datum, names[0] if len(names) == 1 else None)

    def proposal(self, ref: OutputReference) -> Position[ProposalDatum]:
        """The proposal output ``ref`` (a submitted proposal or a lock)."""
        return self._position(ref, "proposal_spend", ProposalDatum.from_cbor, "proposal", b"prop_")

    def critique(self, ref: OutputReference) -> Position[CritiqueDatum]:
        return self._position(ref, "critique_spend", CritiqueDatum.from_cbor, "critique", b"crit_")

    def endorsement(self, ref: OutputReference) -> Position[EndorsementDatum]:
        return self._position(ref, "endorsement_spend", EndorsementDatum.from_cbor, "endorsement", b"gend_")

    def proposal_by_seed(self, seed: OutputReference) -> Position[ProposalDatum] | None:
        """The current output of the proposal with the seed ``seed``: it holds
        ``proposal_token_name(seed)``, also after amendments. None when no such
        proposal exists."""
        name = proposal_token_name(seed)
        address = self.scripts.proposal_spend.address
        for utxo in self.ledger.token_utxos(self.scripts.proposal_mint.hash, name):
            if utxo.output.address == address and policy_tokens(utxo, self.scripts.proposal_mint.hash) == {name: 1}:
                return Position(utxo, _decode(utxo, ProposalDatum.from_cbor, f"the proposal {utxo_ref(utxo)}"), name)
        return None

    def active_proposals(self) -> list[Position[ProposalDatum]]:
        """The submitted proposals in state Open or Amended."""
        out = []
        address = self.scripts.proposal_spend.address
        mint = self.scripts.proposal_mint.hash
        for utxo in self.ledger.utxos_at(str(address)):
            tokens = policy_tokens(utxo, mint)
            if utxo.output.address != address or len(tokens) != 1:
                continue
            ((name, quantity),) = tokens.items()
            if not name.startswith(b"prop_") or quantity != 1:
                continue
            datum = _decode_or_none(utxo, ProposalDatum.from_cbor)
            if datum is not None and datum.state.active:
                out.append(Position(utxo, datum, name))
        return out

    def reputation_stake(self, agent: bytes) -> UTxO | None:
        """The Module-3 stake of ``agent`` that an emergency proposal reads
        (``emergency.verify_proposer_reputation``) while Module-3 is deployed: at
        the reputation validator, the stake token ``rstk_`` of the agent, the
        agent in the first datum field and at least 100 AP3X."""
        config = self.config
        if not config.module3_deployed:
            return None
        name = b"rstk_" + blake2b_256(agent)[:27]
        for utxo in self.ledger.token_utxos(config.reputation_validator_hash, name):
            if _payment_script(utxo) != config.reputation_validator_hash:
                continue
            if policy_tokens(utxo, config.reputation_validator_hash).get(name) != 1 or _lovelace(utxo) < 100_000_000:
                continue
            raw = datum_bytes(utxo)
            data = None if raw is None else decode_data(raw)
            fields = getattr(data, "fields", ())
            if fields and fields[0] == agent:
                return utxo
        return None


def _cross_refs(utxo: UTxO) -> GovernanceCrossRefs | None:
    return _decode_or_none(utxo, GovernanceCrossRefs.from_cbor)


def _decode(utxo: UTxO, decode: Callable[[bytes], D], what: str) -> D:
    raw = datum_bytes(utxo)
    if raw is None:
        raise GovernanceLookupError(f"{what} has no inline datum")
    try:
        return decode(raw)
    except (PlutusDataError, ValueError) as exc:
        raise GovernanceLookupError(f"{what} does not decode: {exc}") from exc


def _decode_or_none(utxo: UTxO, decode: Callable[[bytes], D]) -> D | None:
    raw = datum_bytes(utxo)
    if raw is None:
        return None
    try:
        return decode(raw)
    except (PlutusDataError, ValueError):
        return None
