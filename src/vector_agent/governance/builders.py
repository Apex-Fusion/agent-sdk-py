"""Module-6 transaction builders for the deployment that reads identity records.

Part 2 §7 of ``docs/IDENTITY_REGISTRY.md`` (Module-6 row) and the Module-6
contracts (vector-agent-modules ``91e3823``):

- A proposal submission, an amendment, a critique submission and an
  endorsement submission read the identity record of the agent and its
  ancestors (reference inputs). The record is Active over the whole validity
  range, which is at most one hour long. The credential in the datum is the
  controller key or a listed key with the transaction purpose, and that key
  signs. ``submitted_at`` and ``created_at`` are the lower bound ``lo``.
- A new position needs two transactions. The lock puts the datum at the
  validator and runs no script, so the builder checks every rule first. The
  creation spends the lock with the creation redeemer and mints the token.
- A proposal submission spends one entry of the activity list: the node of the
  proposer, or for its first proposal its predecessor in the list, and then
  inserts the node of the proposer (one activity token per agent, ever).
- A critique or an endorsement names its proposal by the seed: the lock that
  the SubmitProposal of the proposal spent (:func:`proposal_token_name`).
- Exits and settlements read no identity record. They return each stake to the
  credential in its datum.

Every builder returns an unsigned :class:`~vector_agent.identity.BuiltTx` with
every key hash that must sign it; the caller signs (:func:`add_signatures`).
Every transaction has the parameters record and the cross references as
reference inputs, because every Module-6 validator reads them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace

from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    Network,
    ScriptHash,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
    VerificationKeyHash,
)
from pycardano.serialization import RawCBOR

from vector_agent.governance.context import GovernanceContext, Position, policy_tokens
from vector_agent.governance.errors import GovernanceLookupError, GovernanceRuleError
from vector_agent.governance.rules import (
    check_critique,
    check_distinct_parties,
    check_endorsement,
    check_proposal,
    check_rate_limit,
    declared_key,
    emergency_stake,
    require_active,
)
from vector_agent.governance.types import (
    ActivityDatum,
    CritiqueAction,
    CritiqueDatum,
    CritiqueKind,
    CritiqueType,
    EndorsementAction,
    EndorsementDatum,
    ProposalAction,
    ProposalDatum,
    ProposalKind,
    ProposalPriority,
    ProposalState,
    ProposalType,
    activity_token_name,
    agent_id,
    critique_token_name,
    endorsement_token_name,
    proposal_token_name,
    utf8,
)
from vector_agent.identity.context import AuthenticOutput
from vector_agent.identity.ids import vector_did
from vector_agent.identity.plutus_data import Constr, encode_data
from vector_agent.identity.tx import BuiltTx, TxPlan, Window, build, make_window, min_lovelace
from vector_agent.identity.types import Credential, IdentityDatum, KeyCredential, OutputReference

__all__ = [
    "ACTIVITY_LOVELACE",
    "DEFAULT_REVIEW_WINDOW_MS",
    "DEFAULT_VALID_FOR_S",
    "POSITION_DEPOSIT",
    "Governance",
    "as_ref",
    "payout_address",
]

#: Seconds between the tip and the end of the validity range (the range starts
#: 60 s before the tip, so it lasts 31 minutes; the contracts allow one hour).
DEFAULT_VALID_FOR_S = 1_800
#: Base units on top of the stake in a new proposal, critique or endorsement.
POSITION_DEPOSIT = 2_000_000
#: Base units of a new node of the activity list.
ACTIVITY_LOVELACE = 2_000_000
#: Review window of a standard proposal when the caller names none: 7 days.
DEFAULT_REVIEW_WINDOW_MS = 604_800_000

#: A token name of the right length for the ledger minimum of a new position.
_TOKEN_PLACEHOLDER = bytes(32)


def as_ref(value: OutputReference | TransactionInput | Mapping | str) -> OutputReference:
    """An output reference from ``OutputReference``, a PyCardano
    ``TransactionInput``, ``{"tx_hash", "output_index"}`` or ``"<tx id>#<index>"``."""
    if isinstance(value, OutputReference):
        return value
    if isinstance(value, TransactionInput):
        return OutputReference(bytes(value.transaction_id.payload), value.index)
    if isinstance(value, Mapping):
        return OutputReference(bytes.fromhex(value["tx_hash"]), int(value["output_index"]))
    if isinstance(value, str):
        return OutputReference.parse(value)
    raise TypeError(f"not an output reference: {value!r}")


def payout_address(credential: Credential, change: Address) -> Address:
    """The address that receives a stake back: the change address when its
    payment key is the credential (the stake part stays), else the enterprise
    address of the key. The contracts check only the payment credential."""
    if not isinstance(credential, KeyCredential):
        raise GovernanceRuleError("the owner credential is a script credential; the SDK pays only key credentials")
    payment = change.payment_part
    if isinstance(payment, VerificationKeyHash) and bytes(payment.payload) == credential.hash:
        return change
    return Address(payment_part=VerificationKeyHash(credential.hash), network=Network.MAINNET)


def _inline(datum) -> RawCBOR:
    return RawCBOR(encode_data(datum.to_data()))


def _assets(policy: bytes, names: Mapping[bytes, int]) -> MultiAsset:
    return MultiAsset({ScriptHash(bytes(policy)): Asset({AssetName(n): q for n, q in names.items()})})


def _coin(utxo: UTxO) -> int:
    amount = utxo.output.amount
    return amount if isinstance(amount, int) else amount.coin


def _value_key(utxo: UTxO) -> tuple:
    """The value of an output as a comparable tuple."""
    amount = utxo.output.amount
    if isinstance(amount, int):
        return (amount, ())
    tokens = sorted(
        (bytes(pid.payload), bytes(name.payload), int(quantity))
        for pid, bundle in amount.multi_asset.items()
        for name, quantity in bundle.items()
    )
    return (amount.coin, tuple(tokens))


def _proposal_type(value) -> ProposalType:
    if value is None:
        return ProposalType.general_suggestion()
    if isinstance(value, ProposalType):
        return value
    if isinstance(value, Constr):
        return ProposalType.from_data(value)
    raise TypeError("proposal_type: expected a ProposalType")


def _critique_type(value) -> CritiqueType:
    if value is None:
        return CritiqueType.SUPPORTIVE
    if isinstance(value, CritiqueType):
        return value
    if isinstance(value, Constr):
        return CritiqueType.from_data(value)
    raise TypeError("critique_type: expected a CritiqueType")


def _hash32(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 32:
        raise GovernanceRuleError(f"{name} is not 32 bytes")
    return raw


def _did(agent: bytes) -> str:
    return vector_did(agent.hex()) if len(agent) == 32 else agent.hex()


class Governance:
    """Builders of every Module-6 transaction on one deployment."""

    def __init__(self, ctx: GovernanceContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def window(self, *, valid_for: int = DEFAULT_VALID_FOR_S, tip_slot: int | None = None) -> Window:
        """``[tip - 60 s, tip + valid_for]``, at most one hour."""
        return make_window(self.ctx, valid_for=valid_for, tip_slot=tip_slot)

    def _min(self, output: TransactionOutput) -> int:
        return min_lovelace(self.ctx, output)

    def _with_min(self, address: Address, coin: int, assets: MultiAsset | None, datum) -> TransactionOutput:
        """An output with at least the ledger minimum of base units."""
        output = TransactionOutput(address, Value(coin, assets) if assets else coin, datum=datum)
        floor = self._min(output)
        if floor > coin:
            output = TransactionOutput(address, Value(floor, assets) if assets else floor, datum=datum)
        return output

    def _continue(self, entry: UTxO, datum) -> TransactionOutput:
        """``settlement.continues``: the same address and tokens, at least the same base units."""
        amount = entry.output.amount
        assets = None if isinstance(amount, int) else amount.multi_asset
        return self._with_min(entry.output.address, _coin(entry), assets, _inline(datum))

    def _credential(self, funding: str | Address, key_hash: bytes | None) -> KeyCredential:
        if key_hash is not None:
            raw = bytes(key_hash)
            if len(raw) != 28:
                raise GovernanceRuleError("credential_key_hash is a 28-byte key hash")
            return KeyCredential(raw)
        payment = self.ctx.address_of(funding).payment_part
        if not isinstance(payment, VerificationKeyHash):
            raise GovernanceRuleError("the funding address has no payment key; pass credential_key_hash")
        return KeyCredential(bytes(payment.payload))

    def _identity(self, agent: bytes, window: Window) -> list[AuthenticOutput[IdentityDatum]]:
        if len(agent) != 32:
            raise GovernanceRuleError(f"{agent.hex()} is not the 32-byte identifier of an identity record")
        chain = self.ctx.record_chain(agent)
        require_active(chain, window.lo, window.hi)
        return chain

    def _plan(self, window: Window) -> tuple[TxPlan, object]:
        """A plan with the parameters record and the cross references as reference inputs."""
        params = self.ctx.params_record()
        plan = TxPlan(window)
        plan.reference(params.utxo, self.ctx.cross_refs_record())
        return plan, params.datum

    def _named_proposal(self, seed: OutputReference) -> Position[ProposalDatum]:
        proposal = self.ctx.proposal_by_seed(seed)
        if proposal is None:
            raise GovernanceLookupError(
                f"no proposal holds the token of the seed {seed}. A critique or an endorsement names its proposal "
                "by the seed: the lock that the SubmitProposal of the proposal spent"
            )
        return proposal

    def _lock_coin(self, address: Address, stake: int, policy: bytes, datum) -> int:
        """Stake plus the deposit, and at least the ledger minimum of the created
        position (the lock value with one 32-byte token)."""
        coin = stake + POSITION_DEPOSIT
        probe = TransactionOutput(address, Value(coin, _assets(policy, {_TOKEN_PLACEHOLDER: 1})), datum=_inline(datum))
        return max(coin, self._min(probe))

    def _lock(self, funding, address: Address, coin: int, datum, window: Window, change_address) -> BuiltTx:
        plan = TxPlan(window)
        plan.output(TransactionOutput(address, coin, datum=_inline(datum)))
        return build(self.ctx, plan, funding, change_address=change_address)

    def _locked(self, position: Position, what: str) -> None:
        amount = position.utxo.output.amount
        if not isinstance(amount, int) and any(q for bundle in amount.multi_asset.values() for q in bundle.values()):
            raise GovernanceRuleError(f"{position.ref} holds tokens: it is not a {what} lock")

    # ------------------------------------------------------------------
    # Proposals
    # ------------------------------------------------------------------

    def lock_proposal(
        self,
        funding: str | Address,
        *,
        proposer: str | bytes,
        proposal_hash: bytes,
        storage_uri: str | bytes,
        proposal_type: ProposalType | None = None,
        stake: int | None = None,
        review_window: int | None = None,
        priority: ProposalPriority = ProposalPriority.STANDARD,
        credential_key_hash: bytes | None = None,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 1 of a proposal: lock the ``ProposalDatum`` at the proposal validator.

        The builder checks every rule of SubmitProposal first: the record of
        ``proposer`` is Active over ``window``, the credential is declared
        (default: the payment key of ``funding``), the stake, the review window
        and the type are valid, and the activity list allows the submission.
        ``stake`` defaults to the minimum of the parameters record (standard) or
        the emergency stake; ``review_window`` (ms) defaults to 7 days (standard)
        or the emergency review window.
        """
        window = window or self.window()
        agent = agent_id(proposer)
        params = self.ctx.params_record().datum
        priority = ProposalPriority(priority)
        standard = priority == ProposalPriority.STANDARD
        if stake is None:
            stake = params.min_proposal_stake if standard else emergency_stake(params)
        if review_window is None:
            review_window = DEFAULT_REVIEW_WINDOW_MS if standard else params.emergency_review_window
        chain = self._identity(agent, window)
        credential = self._credential(funding, credential_key_hash)
        declared_key(chain[0], credential)
        datum = ProposalDatum(
            proposer_did=agent,
            proposer_credential=credential,
            proposal_hash=_hash32(proposal_hash, "proposal_hash"),
            proposal_type=_proposal_type(proposal_type),
            storage_uri=utf8(storage_uri),
            stake_amount=int(stake),
            submitted_at=window.lo,
            review_window=int(review_window),
            priority=priority,
        )
        check_proposal(datum, params)
        activity = self.ctx.activity_list()
        node = activity.node(agent)
        check_rate_limit(node.datum if node else None, agent, params, window.lo)
        activity.submission_input(agent)
        self._reputation_reference(datum)
        scripts = self.ctx.scripts
        coin = self._lock_coin(scripts.proposal_spend.address, datum.stake_amount, scripts.proposal_mint.hash, datum)
        return self._lock(funding, scripts.proposal_spend.address, coin, datum, window, change_address)

    def _reputation_reference(self, datum: ProposalDatum) -> UTxO | None:
        """The Module-3 stake that an emergency proposal reads while Module-3 is deployed."""
        if datum.priority != ProposalPriority.EMERGENCY or not self.ctx.config.module3_deployed:
            return None
        stake = self.ctx.reputation_stake(datum.proposer_did)
        if stake is None:
            raise GovernanceLookupError(
                f"an emergency proposal of {_did(datum.proposer_did)} reads its Module-3 stake (at least 100 AP3X); "
                "no such stake exists"
            )
        return stake

    def submit_proposal(
        self,
        funding: str | Address,
        lock: OutputReference | str,
        *,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 2 of a proposal (SubmitProposal).

        - Spends the lock with SubmitProposal and one entry of the activity list
          with SpendActivity: the node of the proposer, or for its first proposal
          its predecessor.
        - Mints the proposal token of the lock (the seed) and, for a first
          proposal, the activity token of the proposer.
        - Output 0: the proposal with ``submitted_at = lo``. Output 1: the node of
          the proposer (count plus one, ``last_proposal_slot = lo``). Output 2
          (first proposal only): the predecessor with ``next_did`` = the proposer.

        ``created_id`` is the proposal token name. Critiques and endorsements
        name the proposal by ``lock`` (the seed).
        """
        window = window or self.window()
        locked = self.ctx.proposal(as_ref(lock))
        self._locked(locked, "proposal")
        agent = locked.datum.proposer_did
        chain = self._identity(agent, window)
        signer = declared_key(chain[0], locked.datum.proposer_credential)
        datum = replace(locked.datum, submitted_at=window.lo)
        plan, params = self._plan(window)
        check_proposal(datum, params)
        activity = self.ctx.activity_list()
        node = activity.node(agent)
        check_rate_limit(node.datum if node else None, agent, params, window.lo)
        entry = activity.submission_input(agent)
        plan.reference(*(record.utxo for record in chain))
        stake = self._reputation_reference(datum)
        if stake is not None:
            plan.reference(stake)

        scripts = self.ctx.scripts
        source = self.ctx.script_source("proposal_spend")
        token = proposal_token_name(locked.ref)
        minted = {token: 1}
        plan.spend(locked.utxo, source, ProposalAction.SUBMIT)
        plan.output(
            self._with_min(
                locked.utxo.output.address,
                locked.lovelace,
                _assets(scripts.proposal_mint.hash, {token: 1}),
                _inline(datum),
            )
        )
        plan.spend(entry.utxo, source, ProposalAction.SPEND_ACTIVITY)
        if node is not None:
            continued = replace(node.datum, active_proposal_count=node.datum.active_proposal_count + 1)
            plan.output(self._continue(node.utxo, replace(continued, last_proposal_slot=window.lo)))
        else:
            name = activity_token_name(agent)
            minted[name] = 1
            new_node = ActivityDatum(agent, datum.proposer_credential, 1, window.lo, entry.datum.next_did)
            plan.output(
                self._with_min(
                    locked.utxo.output.address,
                    ACTIVITY_LOVELACE,
                    _assets(scripts.proposal_mint.hash, {name: 1}),
                    _inline(new_node),
                )
            )
            plan.output(self._continue(entry.utxo, replace(entry.datum, next_did=agent)))
        plan.mint(self.ctx.script_source("proposal_mint"), minted, ProposalAction.SUBMIT)
        plan.require(signer)
        plan.created_id = token
        return build(self.ctx, plan, funding, change_address=change_address)

    def amend_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        new_hash: bytes,
        new_uri: str | bytes,
        incorporate: Sequence[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """AmendProposal by the proposer, with the identity check of a submission.

        Spends the proposal and each critique of ``incorporate`` (IncorporateCritique).
        Output 0: the proposal in state Amended with the new hash and URI, one
        more amendment and the critiques appended. Then one output per critique:
        the same address and value, ``incorporated = True``.
        """
        window = window or self.window()
        position = self.ctx.proposal(as_ref(proposal))
        if position.token is None:
            raise GovernanceRuleError(f"{position.ref} holds no proposal token: it is not a submitted proposal")
        datum = position.datum
        chain = self._identity(datum.proposer_did, window)
        signer = declared_key(chain[0], datum.proposer_credential)
        plan, params = self._plan(window)
        new_hash = bytes(new_hash)
        new_uri = utf8(new_uri)
        critiques = [self.ctx.critique(as_ref(r)) for r in incorporate]
        refs = [c.ref for c in critiques]
        problems = []
        if not datum.state.active:
            problems.append(f"the proposal is {datum.state.kind.name}, not Open or Amended")
        if len(new_hash) != 32 or new_hash == datum.proposal_hash:
            problems.append("the new hash is 32 bytes and differs from the current hash")
        if not new_uri:
            problems.append("the new URI is empty")
        if datum.amendment_count + 1 > params.max_amendments:
            problems.append(f"the proposal already has {datum.amendment_count} of {params.max_amendments} amendments")
        if len(datum.incorporated_critiques) + len(refs) > params.max_incorporated_critiques:
            problems.append(f"more than {params.max_incorporated_critiques} incorporated critiques")
        if len(set(refs)) != len(refs):
            problems.append("a critique is listed twice")
        for critique in critiques:
            if critique.token is None:
                problems.append(f"{critique.ref} holds no critique token")
            if critique.datum.incorporated:
                problems.append(f"the critique {critique.ref} is already incorporated")
            if proposal_token_name(critique.datum.proposal_ref) != position.token:
                problems.append(f"the critique {critique.ref} names another proposal")
        shapes = [(c.datum.to_cbor(), _value_key(c.utxo)) for c in critiques]
        if len(set(shapes)) != len(shapes):
            problems.append("two critiques with the same datum and value cannot be incorporated together")
        if problems:
            raise GovernanceRuleError("the amendment does not meet the contract rules: " + "; ".join(problems))

        amended = replace(
            datum,
            proposal_hash=new_hash,
            storage_uri=new_uri,
            amendment_count=datum.amendment_count + 1,
            incorporated_critiques=(*datum.incorporated_critiques, *refs),
            state=ProposalState.amended(datum.proposal_hash),
        )
        plan.reference(*(record.utxo for record in chain))
        plan.spend(position.utxo, self.ctx.script_source("proposal_spend"), ProposalAction.amend(new_hash, new_uri, refs))
        plan.output(self._continue(position.utxo, amended))
        critique_source = self.ctx.script_source("critique_spend") if critiques else None
        for critique in critiques:
            plan.spend(critique.utxo, critique_source, CritiqueAction.INCORPORATE)
            output = critique.utxo.output
            plan.output(
                TransactionOutput(output.address, output.amount, datum=_inline(replace(critique.datum, incorporated=True)))
            )
        plan.require(signer)
        return build(self.ctx, plan, funding, change_address=change_address)

    # ------------------------------------------------------------------
    # Finalisations
    # ------------------------------------------------------------------

    def _settled(self, ref: OutputReference) -> tuple[str, Position]:
        utxo = self.ctx.ledger.utxo(ref)
        if utxo is None:
            raise GovernanceLookupError(f"the position {ref} is spent or unknown")
        if utxo.output.address == self.ctx.scripts.critique_spend.address:
            return "critique", self.ctx.critique(ref)
        if utxo.output.address == self.ctx.scripts.endorsement_spend.address:
            return "endorsement", self.ctx.endorsement(ref)
        raise GovernanceRuleError(f"{ref} is not at the critique or the endorsement validator")

    def _finalise(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        action: Constr,
        *,
        window: Window,
        settle: Iterable[OutputReference | str],
        signers: Iterable[bytes] = (),
        references: Iterable[UTxO] = (),
        change_address: str | Address | None,
    ) -> BuiltTx:
        """A finalisation (``validate_finalisation``): spend the proposal with
        ``action``, burn its token, spend the node of the proposer with
        SpendActivity and continue it with one active proposal less, and pay the
        stake to the proposer credential. Each position of ``settle`` (a critique
        or an endorsement) is spent with its burn redeemer: its tokens are burned
        and its stake goes to its credential. A position that names another
        proposal needs the signature of its credential (``settlement.settles``)."""
        position = self.ctx.proposal(as_ref(proposal))
        datum = position.datum
        if position.token is None:
            raise GovernanceRuleError(f"{position.ref} holds no proposal token: it is not a submitted proposal")
        if not datum.state.active:
            raise GovernanceRuleError(f"the proposal {position.ref} is {datum.state.kind.name}, not Open or Amended")
        node = self.ctx.activity_list().node(datum.proposer_did)
        if node is None:
            raise GovernanceLookupError(f"no activity node of the proposer {_did(datum.proposer_did)}")
        if node.datum.active_proposal_count < 1:
            raise GovernanceRuleError(f"the activity node of {_did(datum.proposer_did)} has no active proposal")
        change = self.ctx.address_of(change_address if change_address is not None else funding)
        plan, _ = self._plan(window)
        plan.reference(*references)
        scripts = self.ctx.scripts
        source = self.ctx.script_source("proposal_spend")
        plan.spend(position.utxo, source, action)
        plan.spend(node.utxo, source, ProposalAction.SPEND_ACTIVITY)
        plan.output(
            self._continue(node.utxo, replace(node.datum, active_proposal_count=node.datum.active_proposal_count - 1))
        )
        owed: dict[Credential, int] = {datum.proposer_credential: position.lovelace}
        burns: dict[bytes, int] = {}
        refs = [as_ref(r) for r in settle]
        if len(set(refs)) != len(refs):
            raise GovernanceRuleError("a position is listed twice")
        for ref in refs:
            kind, settled = self._settled(ref)
            if kind == "critique":
                owner, named, redeemer, spend = (
                    settled.datum.critic_credential,
                    settled.datum.proposal_ref,
                    CritiqueAction.BURN,
                    "critique_spend",
                )
            else:
                owner, named, redeemer, spend = (
                    settled.datum.endorser_credential,
                    settled.datum.proposal_ref,
                    EndorsementAction.BURN,
                    "endorsement_spend",
                )
            if proposal_token_name(named) != position.token:
                if not isinstance(owner, KeyCredential):
                    raise GovernanceRuleError(f"{ref} names another proposal and its credential is a script")
                plan.require(owner.hash)
            plan.spend(settled.utxo, self.ctx.script_source(spend), redeemer)
            for name, quantity in policy_tokens(settled.utxo, scripts.critique_mint.hash).items():
                burns[name] = burns.get(name, 0) - quantity
            owed[owner] = owed.get(owner, 0) + settled.lovelace
        for credential, amount in owed.items():
            plan.output(TransactionOutput(payout_address(credential, change), amount))
        plan.mint(self.ctx.script_source("proposal_mint"), {position.token: -1}, action)
        if burns:
            plan.mint(self.ctx.script_source("critique_mint"), burns, CritiqueAction.BURN)
        plan.require(*signers)
        return build(self.ctx, plan, funding, change_address=change_address)

    def withdraw_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        settle: Iterable[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """WithdrawProposal: the proposer credential signs; the stake returns to it."""
        position = self.ctx.proposal(as_ref(proposal))
        credential = position.datum.proposer_credential
        if not isinstance(credential, KeyCredential):
            raise GovernanceRuleError("the proposer credential is a script credential: it cannot sign")
        return self._finalise(
            funding,
            position.ref,
            ProposalAction.WITHDRAW,
            window=window or self.window(),
            settle=settle,
            signers=[credential.hash],
            change_address=change_address,
        )

    def expire_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        settle: Iterable[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """ExpireProposal (anybody): ``lo > submitted_at + review_window``."""
        window = window or self.window()
        position = self.ctx.proposal(as_ref(proposal))
        ends = position.datum.submitted_at + position.datum.review_window
        if window.lo <= ends:
            raise GovernanceRuleError(f"the review window of {position.ref} ends at {ends} (POSIX ms); lo is {window.lo}")
        return self._finalise(
            funding, position.ref, ProposalAction.EXPIRE, window=window, settle=settle, change_address=change_address
        )

    def expire_stale_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        settle: Iterable[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """ExpireStaleProposal (anybody): a ParameterChange of a Module-6 parameter
        whose value in the parameters record differs from ``current_value``."""
        window = window or self.window()
        position = self.ctx.proposal(as_ref(proposal))
        kind, values = position.datum.proposal_type.kind, position.datum.proposal_type.fields
        if kind != ProposalKind.PARAMETER_CHANGE:
            raise GovernanceRuleError("only a ParameterChange proposal can be stale")
        value = self.ctx.params_record().datum.module6_value(values[0])
        if value is None:
            raise GovernanceRuleError(f"{values[0]!r} is not a Module-6 parameter of the parameters record")
        if value == values[1]:
            raise GovernanceRuleError(f"{values[0]!r} still has the value {value}: the proposal is not stale")
        return self._finalise(
            funding, position.ref, ProposalAction.EXPIRE_STALE, window=window, settle=settle, change_address=change_address
        )

    def _oracle(self) -> tuple[UTxO, bytes]:
        oracle = self.ctx.oracle_record()
        credential = oracle.datum.oracle_credential
        if not oracle.datum.oracle_active:
            raise GovernanceRuleError("the oracle record is not active")
        if not isinstance(credential, KeyCredential):
            raise GovernanceRuleError("the oracle credential is a script credential; the validators need a key")
        return oracle.utxo, credential.hash

    def adopt_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        reasoning_hash: bytes,
        reward_amount: int,
        settle: Iterable[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """AdoptProposal: the oracle signs, the reward is within the parameter
        bounds, and the proposer stake returns to the proposer credential."""
        window = window or self.window()
        params = self.ctx.params_record().datum
        if not params.min_adoption_reward <= reward_amount <= params.max_adoption_reward:
            raise GovernanceRuleError(
                f"the reward must be in [{params.min_adoption_reward}, {params.max_adoption_reward}]"
            )
        if self.ctx.config.module3_deployed:
            raise GovernanceRuleError(
                "the deployment names a Module-3 reputation validator: an adoption also mints a history bonus, "
                "which this client does not build"
            )
        oracle, key = self._oracle()
        return self._finalise(
            funding,
            proposal,
            ProposalAction.adopt(_hash32(reasoning_hash, "reasoning_hash"), reward_amount),
            window=window,
            settle=settle,
            signers=[key],
            references=[oracle],
            change_address=change_address,
        )

    def reject_proposal(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        reasoning_hash: bytes,
        settle: Iterable[OutputReference | str] = (),
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """RejectProposal: the oracle signs; the stake returns to the proposer credential."""
        oracle, key = self._oracle()
        return self._finalise(
            funding,
            proposal,
            ProposalAction.reject(_hash32(reasoning_hash, "reasoning_hash")),
            window=window or self.window(),
            settle=settle,
            signers=[key],
            references=[oracle],
            change_address=change_address,
        )

    def extend_review(
        self,
        funding: str | Address,
        proposal: OutputReference | str,
        *,
        additional_ms: int,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """ExtendReview: the oracle signs; the proposal continues with the longer review window."""
        window = window or self.window()
        position = self.ctx.proposal(as_ref(proposal))
        datum = position.datum
        plan, params = self._plan(window)
        problems = []
        if position.token is None:
            problems.append("the output holds no proposal token")
        if not datum.state.active:
            problems.append(f"the proposal is {datum.state.kind.name}, not Open or Amended")
        if additional_ms <= 0:
            problems.append("the extension is positive")
        if datum.review_window + additional_ms > params.max_review_window:
            problems.append(f"the review window would exceed {params.max_review_window} ms")
        if problems:
            raise GovernanceRuleError("the extension does not meet the contract rules: " + "; ".join(problems))
        oracle, key = self._oracle()
        plan.reference(oracle)
        plan.spend(position.utxo, self.ctx.script_source("proposal_spend"), ProposalAction.extend_review(additional_ms))
        plan.output(self._continue(position.utxo, replace(datum, review_window=datum.review_window + additional_ms)))
        plan.require(key)
        return build(self.ctx, plan, funding, change_address=change_address)

    # ------------------------------------------------------------------
    # Critiques
    # ------------------------------------------------------------------

    def lock_critique(
        self,
        funding: str | Address,
        *,
        critic: str | bytes,
        proposal_seed: OutputReference | str,
        critique_hash: bytes,
        storage_uri: str | bytes,
        critique_type: CritiqueType | None = None,
        stake: int | None = None,
        credential_key_hash: bytes | None = None,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 1 of a critique: lock the ``CritiqueDatum`` at the critique
        validator, with ``proposal_ref = proposal_seed``. The builder checks the
        rules of MintCritiqueToken first. ``stake`` defaults to the minimum."""
        window = window or self.window()
        agent = agent_id(critic)
        seed = as_ref(proposal_seed)
        params = self.ctx.params_record().datum
        chain = self._identity(agent, window)
        credential = self._credential(funding, credential_key_hash)
        declared_key(chain[0], credential)
        proposal = self._named_proposal(seed)
        datum = CritiqueDatum(
            critic_did=agent,
            critic_credential=credential,
            proposal_ref=seed,
            critique_hash=_hash32(critique_hash, "critique_hash"),
            storage_uri=utf8(storage_uri),
            critique_type=_critique_type(critique_type),
            stake_amount=int(params.min_critique_stake if stake is None else stake),
            submitted_at=window.lo,
        )
        check_critique(datum, proposal.datum, params)
        if datum.critique_type.kind != CritiqueKind.AMENDMENT:
            check_distinct_parties(chain[0], credential, proposal.datum, self.ctx.record(proposal.datum.proposer_did))
        scripts = self.ctx.scripts
        coin = self._lock_coin(scripts.critique_spend.address, datum.stake_amount, scripts.critique_mint.hash, datum)
        return self._lock(funding, scripts.critique_spend.address, coin, datum, window, change_address)

    def submit_critique(
        self,
        funding: str | Address,
        lock: OutputReference | str,
        *,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 2 of a critique (MintCritiqueToken): spend the lock, mint the
        critique token through ``critique_mint`` and create the critique with
        ``submitted_at = lo``. Reference inputs: the record chain, the named
        proposal and, except for an Amendment critique, the proposer's record."""
        window = window or self.window()
        locked = self.ctx.critique(as_ref(lock))
        self._locked(locked, "critique")
        chain = self._identity(locked.datum.critic_did, window)
        signer = declared_key(chain[0], locked.datum.critic_credential)
        proposal = self._named_proposal(locked.datum.proposal_ref)
        datum = replace(locked.datum, submitted_at=window.lo)
        plan, params = self._plan(window)
        check_critique(datum, proposal.datum, params)
        plan.reference(*(record.utxo for record in chain), proposal.utxo)
        if datum.critique_type.kind != CritiqueKind.AMENDMENT:
            proposer = self.ctx.record(proposal.datum.proposer_did)
            check_distinct_parties(chain[0], datum.critic_credential, proposal.datum, proposer)
            plan.reference(proposer.utxo)
        mint = self.ctx.scripts.critique_mint.hash
        token = critique_token_name(locked.ref)
        plan.spend(locked.utxo, self.ctx.script_source("critique_spend"), CritiqueAction.MINT)
        plan.output(self._with_min(locked.utxo.output.address, locked.lovelace, _assets(mint, {token: 1}), _inline(datum)))
        plan.mint(self.ctx.script_source("critique_mint"), {token: 1}, CritiqueAction.MINT)
        plan.require(signer)
        plan.created_id = token
        return build(self.ctx, plan, funding, change_address=change_address)

    def withdraw_critique(
        self,
        funding: str | Address,
        critique: OutputReference | str,
        *,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """WithdrawCritique: the critic credential signs, the critique is not
        incorporated, and an active proposal is a reference input (the named
        proposal when it is still active). The critique token is burned and the
        stake goes to the critic credential."""
        window = window or self.window()
        position = self.ctx.critique(as_ref(critique))
        datum = position.datum
        if datum.incorporated:
            raise GovernanceRuleError(
                f"the critique {position.ref} is incorporated: it settles with the finalisation of its proposal"
            )
        if not isinstance(datum.critic_credential, KeyCredential):
            raise GovernanceRuleError("the critic credential is a script credential: it cannot sign")
        named = self.ctx.proposal_by_seed(datum.proposal_ref)
        active = named if named is not None and named.datum.state.active else next(iter(self.ctx.active_proposals()), None)
        if active is None:
            raise GovernanceLookupError(
                "a critique withdrawal reads an active proposal, and no proposal is Open or Amended; settle the "
                "critique with the finalisation of a proposal instead"
            )
        return self._exit(
            funding,
            position,
            "critique_spend",
            CritiqueAction.WITHDRAW,
            datum.critic_credential,
            window,
            change_address,
            [active.utxo],
        )

    def _exit(
        self,
        funding,
        position: Position,
        script: str,
        redeemer: Constr,
        owner: KeyCredential,
        window: Window,
        change_address,
        references: Sequence[UTxO] = (),
    ) -> BuiltTx:
        change = self.ctx.address_of(change_address if change_address is not None else funding)
        plan, _ = self._plan(window)
        plan.reference(*references)
        plan.spend(position.utxo, self.ctx.script_source(script), redeemer)
        held = policy_tokens(position.utxo, self.ctx.scripts.critique_mint.hash)
        if held:
            plan.mint(self.ctx.script_source("critique_mint"), {n: -q for n, q in held.items()}, redeemer)
        plan.output(TransactionOutput(payout_address(owner, change), position.lovelace))
        plan.require(owner.hash)
        return build(self.ctx, plan, funding, change_address=change_address)

    # ------------------------------------------------------------------
    # Endorsements
    # ------------------------------------------------------------------

    def lock_endorsement(
        self,
        funding: str | Address,
        *,
        endorser: str | bytes,
        proposal_seed: OutputReference | str,
        stake: int | None = None,
        credential_key_hash: bytes | None = None,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 1 of an endorsement: lock the endorsement datum at the endorsement
        validator, with ``proposal_ref = proposal_seed``. The builder checks the
        rules of MintEndorsementToken first. ``stake`` defaults to the minimum."""
        window = window or self.window()
        agent = agent_id(endorser)
        seed = as_ref(proposal_seed)
        params = self.ctx.params_record().datum
        chain = self._identity(agent, window)
        credential = self._credential(funding, credential_key_hash)
        declared_key(chain[0], credential)
        proposal = self._named_proposal(seed)
        stake_amount = int(params.min_governance_endorsement if stake is None else stake)
        datum = EndorsementDatum(agent, credential, seed, stake_amount, window.lo)
        check_endorsement(datum, proposal.datum, params)
        check_distinct_parties(chain[0], credential, proposal.datum, self.ctx.record(proposal.datum.proposer_did))
        scripts = self.ctx.scripts
        coin = self._lock_coin(scripts.endorsement_spend.address, stake_amount, scripts.critique_mint.hash, datum)
        return self._lock(funding, scripts.endorsement_spend.address, coin, datum, window, change_address)

    def submit_endorsement(
        self,
        funding: str | Address,
        lock: OutputReference | str,
        *,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """Step 2 of an endorsement (MintEndorsementToken): spend the lock, mint
        the endorsement token ``gend_`` through ``critique_mint`` and create the
        endorsement with ``created_at = lo``. Reference inputs: the record chain,
        the named proposal and the proposer's record."""
        window = window or self.window()
        locked = self.ctx.endorsement(as_ref(lock))
        self._locked(locked, "endorsement")
        chain = self._identity(locked.datum.endorser_did, window)
        signer = declared_key(chain[0], locked.datum.endorser_credential)
        proposal = self._named_proposal(locked.datum.proposal_ref)
        datum = replace(locked.datum, created_at=window.lo)
        plan, params = self._plan(window)
        check_endorsement(datum, proposal.datum, params)
        proposer = self.ctx.record(proposal.datum.proposer_did)
        check_distinct_parties(chain[0], datum.endorser_credential, proposal.datum, proposer)
        plan.reference(*(record.utxo for record in chain), proposal.utxo, proposer.utxo)
        mint = self.ctx.scripts.critique_mint.hash
        token = endorsement_token_name(datum.endorser_did, datum.proposal_ref)
        plan.spend(locked.utxo, self.ctx.script_source("endorsement_spend"), EndorsementAction.MINT)
        plan.output(self._with_min(locked.utxo.output.address, locked.lovelace, _assets(mint, {token: 1}), _inline(datum)))
        plan.mint(self.ctx.script_source("critique_mint"), {token: 1}, EndorsementAction.MINT)
        plan.require(signer)
        plan.created_id = token
        return build(self.ctx, plan, funding, change_address=change_address)

    def withdraw_endorsement(
        self,
        funding: str | Address,
        endorsement: OutputReference | str,
        *,
        window: Window | None = None,
        change_address: str | Address | None = None,
    ) -> BuiltTx:
        """WithdrawEndorsement (any time): the endorser credential signs; the
        endorsement token is burned and the stake goes to the endorser credential."""
        window = window or self.window()
        position = self.ctx.endorsement(as_ref(endorsement))
        credential = position.datum.endorser_credential
        if not isinstance(credential, KeyCredential):
            raise GovernanceRuleError("the endorser credential is a script credential: it cannot sign")
        return self._exit(
            funding, position, "endorsement_spend", EndorsementAction.WITHDRAW, credential, window, change_address
        )
