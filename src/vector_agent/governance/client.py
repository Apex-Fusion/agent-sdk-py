"""GovernanceClient: the Module-6 flows of a :class:`~vector_agent.VectorAgent`.

The client builds each transaction with :class:`~vector_agent.governance.Governance`
(the Module-6 deployment that reads identity records), signs it with the agent
wallet and the extra keys that the caller passes, and submits it.

- A new proposal, critique or endorsement takes two transactions: the lock,
  then the creation. The client waits until the lock is on the ledger, then
  plans a new validity range for the creation, so ``submitted_at`` and
  ``created_at`` are the lower bound of the creation.
- The credential in a new position is the wallet key, or ``credential_key``.
  The key must be the controller of the agent's record or a listed key with the
  transaction purpose.
- Critiques and endorsements name their proposal by its seed: the ``seed`` of
  the result of :meth:`GovernanceClient.submit_proposal`.

The deployment values come from :class:`GovernanceDeployment` (default:
``GovernanceDeployment.from_env()``). The new Module-6 deployment is not live,
so there are no default values.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterable, Sequence
from typing import Any

from pycardano.key import ExtendedSigningKey, SigningKey

from vector_agent.governance.builders import Governance, as_ref
from vector_agent.governance.context import GovernanceContext, Position
from vector_agent.governance.deployment import GovernanceDeployment
from vector_agent.governance.errors import GovernanceLookupError, GovernanceRuleError
from vector_agent.governance.types import (
    CritiqueDatum,
    CritiqueType,
    EndorsementDatum,
    ProposalDatum,
    ProposalPriority,
    ProposalType,
)
from vector_agent.identity.chain import Ledger, OgmiosKoiosLedger, SlotClock
from vector_agent.identity.constants import DEFAULT_KOIOS_URL
from vector_agent.identity.tx import BuiltTx
from vector_agent.identity.types import OutputReference

__all__ = ["GovernanceClient"]

Key = SigningKey | ExtendedSigningKey


def _key_hash(key: Key) -> bytes:
    vkey = key.to_verification_key()
    if isinstance(key, ExtendedSigningKey):
        vkey = vkey.to_non_extended()
    return bytes(vkey.hash().payload)


def _output_datum(built: BuiltTx, decode):
    datum = built.transaction.transaction_body.outputs[0].datum
    return decode(bytes(datum.cbor))


class GovernanceClient:
    """Module-6 flows of a connected :class:`~vector_agent.VectorAgent`.

    Args:
        agent: the agent; its wallet pays, signs and receives the stakes back.
        deployment: the Module-6 deployment (default: from the environment).
        ledger: ledger reads (default: Ogmios of the agent and Koios of
            ``VECTOR_KOIOS_URL``, Vector mainnet by default).
        attempts, delay: how often and how long to wait for a lock output.

    Example::

        async with VectorAgent() as agent:
            gov = GovernanceClient(agent, GovernanceDeployment.from_deploy_state("deploy_state.json"))
            proposal = await gov.submit_proposal("did:vector:<64 hex>", proposal_hash, "ipfs://Qm...")
            await gov.endorse_proposal("did:vector:<other agent>", proposal["seed"])
    """

    def __init__(
        self,
        agent: Any,
        deployment: GovernanceDeployment | None = None,
        *,
        ledger: Ledger | None = None,
        clock: SlotClock | None = None,
        attempts: int = 24,
        delay: float = 5.0,
    ) -> None:
        self.agent = agent
        if ledger is None:
            ledger = OgmiosKoiosLedger(
                ogmios_url=agent._ogmios_url,
                koios_url=os.environ.get("VECTOR_KOIOS_URL") or DEFAULT_KOIOS_URL,
                koios_token=os.environ.get("VECTOR_KOIOS_TOKEN") or None,
                context=agent.context,
            )
        self.ctx = GovernanceContext(ledger, deployment, clock=clock)
        self.builders = Governance(self.ctx)
        self.attempts = attempts
        self.delay = delay

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _wallet_address(self):
        return self.agent._wallet.payment_address

    async def _build(self, method, *args, **kwargs) -> BuiltTx:
        return await asyncio.to_thread(method, self._wallet_address, *args, **kwargs)

    async def _submit(self, built: BuiltTx, signing_keys: Iterable[Key] = ()) -> str:
        """Sign with the wallet key and ``signing_keys``, check the signers, submit."""
        keys = [self.agent._wallet.payment_signing_key, *signing_keys]
        missing = set(built.required_signers) - {_key_hash(k).hex() for k in keys}
        if missing:
            raise GovernanceRuleError(
                "the transaction needs the signatures of the key hashes " + ", ".join(sorted(missing))
                + "; pass their signing keys"
            )
        signed = built.sign(*keys)
        await self.agent.context.async_submit_tx_cbor(signed.to_cbor())
        return built.tx_id

    async def _lock_then_create(self, lock: BuiltTx, create, keys: Sequence[Key]) -> tuple[str, OutputReference, BuiltTx]:
        """Submit the lock, wait for it, build and submit the creation."""
        coin = lock.transaction.transaction_body.outputs[0].amount
        coin = coin if isinstance(coin, int) else coin.coin
        address = str(lock.transaction.transaction_body.outputs[0].address)
        self.agent.safety.enforce_transaction(coin)
        lock_tx = await self._submit(lock)
        self.agent.safety.record_transaction(lock_tx, coin, address)
        seed = OutputReference(bytes.fromhex(lock_tx), 0)
        await self._wait(seed)
        built = await self._build(create, seed)
        await self._submit(built, keys)
        return lock_tx, seed, built

    async def _wait(self, ref: OutputReference) -> None:
        for attempt in range(self.attempts):
            if await asyncio.to_thread(self.ctx.ledger.utxo, ref) is not None:
                return
            if attempt + 1 < self.attempts:
                await asyncio.sleep(self.delay)
        raise GovernanceLookupError(f"the output {ref} did not appear on the ledger")

    @staticmethod
    def _keys(credential_key: Key | None, signing_keys: Iterable[Key]) -> list[Key]:
        return [*([credential_key] if credential_key is not None else []), *signing_keys]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def get_proposals(self) -> list[Position[ProposalDatum]]:
        """The submitted proposals in state Open or Amended."""
        return await asyncio.to_thread(self.ctx.active_proposals)

    async def get_balance(self) -> dict:
        """The balance of the agent wallet."""
        balance = await self.agent.get_balance()
        return {"address": balance.address, "ada": balance.ada, "lovelace": balance.lovelace}

    # ------------------------------------------------------------------
    # Proposals
    # ------------------------------------------------------------------

    async def submit_proposal(
        self,
        proposer_did: str | bytes,
        proposal_hash: bytes,
        storage_uri: str | bytes,
        proposal_type: ProposalType | None = None,
        *,
        stake_lovelace: int | None = None,
        review_window: int | None = None,
        priority: ProposalPriority = ProposalPriority.STANDARD,
        credential_key: Key | None = None,
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """Lock and submit a proposal of ``proposer_did`` (identity check, activity
        list, ``submitted_at = lo``).

        Returns ``tx_hash``, ``lock_tx_hash``, ``seed`` (the name of the proposal
        for critiques and endorsements), ``proposal`` (its output), ``activity``
        (the node of the proposer), ``proposal_token_name``, ``script_address``
        and ``stake``.
        """
        lock = await self._build(
            self.builders.lock_proposal,
            proposer=proposer_did,
            proposal_hash=proposal_hash,
            storage_uri=storage_uri,
            proposal_type=proposal_type,
            stake=stake_lovelace,
            review_window=review_window,
            priority=priority,
            credential_key_hash=None if credential_key is None else _key_hash(credential_key),
        )
        lock_tx, seed, built = await self._lock_then_create(
            lock, self.builders.submit_proposal, self._keys(credential_key, signing_keys)
        )
        datum = _output_datum(built, ProposalDatum.from_cbor)
        return {
            "tx_hash": built.tx_id,
            "lock_tx_hash": lock_tx,
            "seed": str(seed),
            "proposal": f"{built.tx_id}#0",
            "activity": f"{built.tx_id}#1",
            "proposal_token_name": built.created_id,
            "script_address": str(self.ctx.scripts.proposal_spend.address),
            "stake": datum.stake_amount,
        }

    async def amend_proposal(
        self,
        proposal: OutputReference | str | dict,
        new_hash: bytes,
        new_uri: str | bytes,
        incorporate: Sequence[OutputReference | str | dict] = (),
        *,
        credential_key: Key | None = None,
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """AmendProposal (identity check of the proposer), with the critiques of ``incorporate``."""
        built = await self._build(
            self.builders.amend_proposal,
            as_ref(proposal),
            new_hash=new_hash,
            new_uri=new_uri,
            incorporate=[as_ref(r) for r in incorporate],
        )
        await self._submit(built, self._keys(credential_key, signing_keys))
        return {"tx_hash": built.tx_id, "proposal": f"{built.tx_id}#0"}

    async def _finalise(self, method, proposal, signing_keys: Sequence[Key], **kwargs) -> dict:
        built = await self._build(method, as_ref(proposal), **kwargs)
        await self._submit(built, signing_keys)
        return {"tx_hash": built.tx_id}

    async def withdraw_proposal(
        self, proposal: OutputReference | str | dict, *, settle: Sequence = (), signing_keys: Sequence[Key] = ()
    ) -> dict:
        """WithdrawProposal: the proposer credential signs; the stake returns to it."""
        return await self._finalise(
            self.builders.withdraw_proposal, proposal, signing_keys, settle=[as_ref(r) for r in settle]
        )

    async def expire_proposal(
        self, proposal: OutputReference | str | dict, *, settle: Sequence = (), signing_keys: Sequence[Key] = ()
    ) -> dict:
        """ExpireProposal (anybody) after the review window."""
        return await self._finalise(
            self.builders.expire_proposal, proposal, signing_keys, settle=[as_ref(r) for r in settle]
        )

    async def expire_stale_proposal(
        self, proposal: OutputReference | str | dict, *, settle: Sequence = (), signing_keys: Sequence[Key] = ()
    ) -> dict:
        """ExpireStaleProposal (anybody): a ParameterChange that names an old value."""
        return await self._finalise(
            self.builders.expire_stale_proposal, proposal, signing_keys, settle=[as_ref(r) for r in settle]
        )

    async def adopt_proposal(
        self,
        proposal: OutputReference | str | dict,
        reasoning_hash: bytes,
        reward_amount: int,
        *,
        settle: Sequence = (),
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """AdoptProposal: the oracle signs (the wallet key or one of ``signing_keys``)."""
        result = await self._finalise(
            self.builders.adopt_proposal,
            proposal,
            signing_keys,
            reasoning_hash=reasoning_hash,
            reward_amount=reward_amount,
            settle=[as_ref(r) for r in settle],
        )
        return {**result, "reward": reward_amount}

    async def reject_proposal(
        self,
        proposal: OutputReference | str | dict,
        reasoning_hash: bytes,
        *,
        settle: Sequence = (),
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """RejectProposal: the oracle signs."""
        return await self._finalise(
            self.builders.reject_proposal,
            proposal,
            signing_keys,
            reasoning_hash=reasoning_hash,
            settle=[as_ref(r) for r in settle],
        )

    async def extend_review(
        self, proposal: OutputReference | str | dict, additional_ms: int, *, signing_keys: Sequence[Key] = ()
    ) -> dict:
        """ExtendReview: the oracle signs; the review window grows by ``additional_ms``."""
        built = await self._build(self.builders.extend_review, as_ref(proposal), additional_ms=additional_ms)
        await self._submit(built, signing_keys)
        return {"tx_hash": built.tx_id, "proposal": f"{built.tx_id}#0"}

    # ------------------------------------------------------------------
    # Critiques
    # ------------------------------------------------------------------

    async def submit_critique(
        self,
        critic_did: str | bytes,
        proposal_seed: OutputReference | str | dict,
        critique_hash: bytes,
        storage_uri: str | bytes,
        critique_type: CritiqueType | None = None,
        *,
        stake_lovelace: int | None = None,
        credential_key: Key | None = None,
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """Lock and submit a critique of the proposal with the seed ``proposal_seed``."""
        lock = await self._build(
            self.builders.lock_critique,
            critic=critic_did,
            proposal_seed=as_ref(proposal_seed),
            critique_hash=critique_hash,
            storage_uri=storage_uri,
            critique_type=critique_type,
            stake=stake_lovelace,
            credential_key_hash=None if credential_key is None else _key_hash(credential_key),
        )
        lock_tx, _, built = await self._lock_then_create(
            lock, self.builders.submit_critique, self._keys(credential_key, signing_keys)
        )
        datum = _output_datum(built, CritiqueDatum.from_cbor)
        return {
            "tx_hash": built.tx_id,
            "lock_tx_hash": lock_tx,
            "critique": f"{built.tx_id}#0",
            "critique_token_name": built.created_id,
            "script_address": str(self.ctx.scripts.critique_spend.address),
            "stake": datum.stake_amount,
        }

    async def withdraw_critique(
        self, critique: OutputReference | str | dict, *, signing_keys: Sequence[Key] = ()
    ) -> dict:
        """WithdrawCritique: the critic credential signs; the stake returns to it."""
        built = await self._build(self.builders.withdraw_critique, as_ref(critique))
        await self._submit(built, signing_keys)
        return {"tx_hash": built.tx_id}

    # ------------------------------------------------------------------
    # Endorsements
    # ------------------------------------------------------------------

    async def endorse_proposal(
        self,
        endorser_did: str | bytes,
        proposal_seed: OutputReference | str | dict,
        *,
        stake_lovelace: int | None = None,
        credential_key: Key | None = None,
        signing_keys: Sequence[Key] = (),
    ) -> dict:
        """Lock and submit an endorsement of the proposal with the seed ``proposal_seed``."""
        lock = await self._build(
            self.builders.lock_endorsement,
            endorser=endorser_did,
            proposal_seed=as_ref(proposal_seed),
            stake=stake_lovelace,
            credential_key_hash=None if credential_key is None else _key_hash(credential_key),
        )
        lock_tx, _, built = await self._lock_then_create(
            lock, self.builders.submit_endorsement, self._keys(credential_key, signing_keys)
        )
        datum = _output_datum(built, EndorsementDatum.from_cbor)
        return {
            "tx_hash": built.tx_id,
            "lock_tx_hash": lock_tx,
            "endorsement": f"{built.tx_id}#0",
            "endorsement_token_name": built.created_id,
            "script_address": str(self.ctx.scripts.endorsement_spend.address),
            "stake": datum.stake_amount,
        }

    async def withdraw_endorsement(
        self, endorsement: OutputReference | str | dict, *, signing_keys: Sequence[Key] = ()
    ) -> dict:
        """WithdrawEndorsement (any time): the endorser credential signs; the stake returns to it."""
        built = await self._build(self.builders.withdraw_endorsement, as_ref(endorsement))
        await self._submit(built, signing_keys)
        return {"tx_hash": built.tx_id}
