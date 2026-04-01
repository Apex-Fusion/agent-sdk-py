"""GovernanceClient — high-level interface for governance actions.

Works with deployed contracts via their compiled script CBOR. Configure via
constructor args or environment variables.

When reference UTxOs are provided (via constructor or
:meth:`set_reference_utxos`), spend transactions use CIP-33 reference
scripts instead of embedding the full script in every transaction, reducing
size and fees by ~85%.
"""

import os

import cbor2
from pycardano import Address, Network
from pycardano.plutus import PlutusData, PlutusV3Script, RawPlutusData
from pycardano.plutus import script_hash as compute_script_hash

from vector_agent.agent import VectorAgent
from vector_agent.governance.types import (
    ProposalAction,
    CritiqueAction,
    EndorsementAction,
)
from vector_agent.governance.datums import (
    build_proposal_datum,
    build_critique_datum,
    build_endorsement_datum,
)


class GovernanceClient:
    """High-level client for governance interactions on Vector.

    Compiled script CBOR can be passed directly or read from environment
    variables: ``GOVERNANCE_PROPOSAL_CBOR``, ``GOVERNANCE_CRITIQUE_CBOR``,
    ``GOVERNANCE_ENDORSEMENT_CBOR``.

    When *reference_utxos* are supplied, spend transactions use CIP-33
    reference scripts for lower fees.  Reference UTxOs can also be set
    later via :meth:`set_reference_utxos`.

    Args:
        agent: A connected VectorAgent instance.
        proposal_script_cbor: Compiled CBOR hex of the proposal spend validator.
        critique_script_cbor: Compiled CBOR hex of the critique spend validator.
        endorsement_script_cbor: Compiled CBOR hex of the endorsement spend validator.
        reference_utxos: Optional dict mapping script names to UTxO refs, e.g.
            ``{"proposal": {"tx_hash": "ab..", "output_index": 0}, ...}``.

    Example::

        from vector_agent import VectorAgent
        from vector_agent.governance import GovernanceClient

        async with VectorAgent() as agent:
            gov = GovernanceClient(
                agent,
                proposal_script_cbor="59...",
                critique_script_cbor="59...",
                endorsement_script_cbor="59...",
            )
            result = await gov.submit_proposal(...)
    """

    def __init__(
        self,
        agent: VectorAgent,
        proposal_script_cbor: str | None = None,
        critique_script_cbor: str | None = None,
        endorsement_script_cbor: str | None = None,
        reference_utxos: dict | None = None,
    ):
        self.agent = agent
        self.proposal_cbor = (
            proposal_script_cbor
            or os.environ.get("GOVERNANCE_PROPOSAL_CBOR", "")
        )
        self.critique_cbor = (
            critique_script_cbor
            or os.environ.get("GOVERNANCE_CRITIQUE_CBOR", "")
        )
        self.endorsement_cbor = (
            endorsement_script_cbor
            or os.environ.get("GOVERNANCE_ENDORSEMENT_CBOR", "")
        )

        # Precompute script hashes for use with reference scripts
        self._script_hashes: dict[str, str] = {}
        for name, cbor_hex in [
            ("proposal", self.proposal_cbor),
            ("critique", self.critique_cbor),
            ("endorsement", self.endorsement_cbor),
        ]:
            if cbor_hex:
                script = PlutusV3Script(bytes.fromhex(cbor_hex))
                self._script_hashes[name] = str(compute_script_hash(script))

        # Reference UTxOs for CIP-33 reference script spending
        self._reference_utxos: dict[str, dict] = reference_utxos or {}

    def set_reference_utxos(self, reference_utxos: dict) -> None:
        """Update reference UTxO mappings after deployment.

        Args:
            reference_utxos: Dict mapping script names ("proposal",
                "critique", "endorsement") to UTxO refs
                ``{"tx_hash": "...", "output_index": N}``.
        """
        self._reference_utxos.update(reference_utxos)

    def _script_address(self, script_cbor: str) -> str:
        """Derive a bech32 script address from compiled CBOR hex."""
        script = PlutusV3Script(bytes.fromhex(script_cbor))
        script_hash = compute_script_hash(script)
        addr = Address(payment_part=script_hash, network=Network.MAINNET)
        return str(addr)

    # ========================================================================
    # Query Methods
    # ========================================================================

    async def get_proposals(self) -> list:
        """Query all proposal UTXOs at the proposal validator address."""
        return await self.agent.get_utxos(
            self._script_address(self.proposal_cbor)
        )

    async def get_balance(self) -> dict:
        """Get the agent's current balance."""
        balance = await self.agent.get_balance()
        return {
            "address": balance.address,
            "ada": balance.ada,
            "lovelace": balance.lovelace,
        }

    # ========================================================================
    # Proposal Actions
    # ========================================================================

    async def submit_proposal(
        self,
        proposer_did: str,
        proposal_hash: bytes,
        proposal_type: PlutusData,
        storage_uri: str,
        stake_lovelace: int = 25_000_000,
        review_window: int = 604_800,
        priority: PlutusData = None,
    ) -> dict:
        """Submit a new governance proposal.

        Args:
            proposer_did: DID of the proposing agent.
            proposal_hash: blake2b_256 hash of proposal document (32 bytes).
            proposal_type: ProposalType variant.
            storage_uri: IPFS/OriginTrail URI for full proposal.
            stake_lovelace: AP3X to stake in lovelace (default 25 AP3X).
            review_window: Review window in slots (default ~7 days).
            priority: ProposalPriority (default Standard).

        Returns:
            Dict with tx_hash, script_address, stake.
        """
        if len(proposal_hash) != 32:
            raise ValueError("proposal_hash must be 32 bytes (blake2b_256)")

        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())

        try:
            tip = await self.agent.context._ogmios.query_network_tip()
            current_slot = tip.get("slot", 0)
        except Exception:
            current_slot = 0

        datum = build_proposal_datum(
            proposer_did=proposer_did,
            proposer_vkey_hash=vkey_hash,
            proposal_hash=proposal_hash,
            proposal_type=proposal_type,
            storage_uri=storage_uri,
            stake_amount=stake_lovelace,
            submitted_at=current_slot,
            review_window=review_window,
            priority=priority,
        )

        result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="lock",
            datum=cbor2.dumps(datum.data),
            lovelace=stake_lovelace + 2_000_000,
        )

        return {
            "tx_hash": result.tx_hash,
            "script_address": self._script_address(self.proposal_cbor),
            "stake": stake_lovelace,
        }

    async def withdraw_proposal(self, utxo_ref: dict) -> dict:
        """Withdraw a proposal (proposer only). Stake is returned."""
        return await self._spend_at(
            self.proposal_cbor, ProposalAction.WITHDRAW, utxo_ref
        )

    async def amend_proposal(
        self,
        utxo_ref: dict,
        new_proposal_hash: bytes,
        new_storage_uri: str,
        incorporated_critique_refs: list = None,
    ) -> dict:
        """Amend a proposal with new content and incorporated critiques.

        Args:
            utxo_ref: Current proposal UTxO reference.
            new_proposal_hash: blake2b_256 hash of amended proposal (32 bytes).
            new_storage_uri: URI for amended proposal document.
            incorporated_critique_refs: List of dicts with tx_hash + output_index.
        """
        if len(new_proposal_hash) != 32:
            raise ValueError("new_proposal_hash must be 32 bytes")

        refs = incorporated_critique_refs or []
        cbor_refs = [
            cbor2.CBORTag(121, [bytes.fromhex(r["tx_hash"]), r["output_index"]])
            for r in refs
        ]

        redeemer = ProposalAction.amend(
            new_proposal_hash, new_storage_uri, cbor_refs
        )
        return await self._spend_at(self.proposal_cbor, redeemer, utxo_ref)

    async def expire_proposal(self, utxo_ref: dict) -> dict:
        """Expire a proposal after review window (callable by anyone)."""
        return await self._spend_at(
            self.proposal_cbor, ProposalAction.EXPIRE, utxo_ref
        )

    async def expire_stale_proposal(self, utxo_ref: dict) -> dict:
        """Expire a stale ParameterChange proposal (callable by anyone)."""
        return await self._spend_at(
            self.proposal_cbor, ProposalAction.EXPIRE_STALE, utxo_ref
        )

    # ========================================================================
    # Foundation Oracle Actions
    # ========================================================================

    async def adopt_proposal(
        self,
        utxo_ref: dict,
        reasoning_hash: bytes,
        reward_amount: int,
    ) -> dict:
        """Foundation adopts a proposal (oracle action).

        Args:
            utxo_ref: Proposal UTxO reference.
            reasoning_hash: blake2b_256 hash of adoption reasoning.
            reward_amount: AP3X reward in lovelace.
        """
        redeemer = ProposalAction.adopt(reasoning_hash, reward_amount)
        result = await self._spend_at(self.proposal_cbor, redeemer, utxo_ref)
        result["reward"] = reward_amount
        return result

    async def reject_proposal(
        self, utxo_ref: dict, reasoning_hash: bytes
    ) -> dict:
        """Foundation rejects a proposal (oracle action)."""
        return await self._spend_at(
            self.proposal_cbor,
            ProposalAction.reject(reasoning_hash),
            utxo_ref,
        )

    async def extend_review(
        self, utxo_ref: dict, additional_slots: int
    ) -> dict:
        """Foundation extends the review window (oracle action)."""
        return await self._spend_at(
            self.proposal_cbor,
            ProposalAction.extend_review(additional_slots),
            utxo_ref,
        )

    # ========================================================================
    # Critique Actions
    # ========================================================================

    async def submit_critique(
        self,
        critic_did: str,
        proposal_ref_tx: str,
        proposal_ref_idx: int,
        critique_hash: bytes,
        storage_uri: str,
        critique_type: PlutusData,
        stake_lovelace: int = 5_000_000,
    ) -> dict:
        """Submit a critique of an existing proposal.

        Args:
            critic_did: DID of the critiquing agent.
            proposal_ref_tx: Transaction hash of proposal UTxO (hex).
            proposal_ref_idx: Output index of proposal UTxO.
            critique_hash: blake2b_256 hash of critique document (32 bytes).
            storage_uri: URI for full critique document.
            critique_type: CritiqueType variant.
            stake_lovelace: AP3X to stake in lovelace (default 5 AP3X).
        """
        if len(critique_hash) != 32:
            raise ValueError("critique_hash must be 32 bytes")

        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())

        datum = build_critique_datum(
            critic_did=critic_did,
            critic_vkey_hash=vkey_hash,
            proposal_ref_tx=bytes.fromhex(proposal_ref_tx),
            proposal_ref_idx=proposal_ref_idx,
            critique_hash=critique_hash,
            storage_uri=storage_uri,
            critique_type=critique_type,
            stake_amount=stake_lovelace,
            submitted_at=0,
        )

        result = await self.agent.interact_contract(
            script_cbor=self.critique_cbor,
            script_type="PlutusV3",
            action="lock",
            datum=cbor2.dumps(datum.data),
            lovelace=stake_lovelace + 2_000_000,
        )

        return {
            "tx_hash": result.tx_hash,
            "script_address": self._script_address(self.critique_cbor),
            "stake": stake_lovelace,
        }

    async def withdraw_critique(self, utxo_ref: dict) -> dict:
        """Withdraw a critique (critic only). Stake returned."""
        return await self._spend_at(
            self.critique_cbor, CritiqueAction.WITHDRAW, utxo_ref
        )

    # ========================================================================
    # Endorsement Actions
    # ========================================================================

    async def endorse_proposal(
        self,
        endorser_did: str,
        proposal_ref_tx: str,
        proposal_ref_idx: int,
        stake_lovelace: int = 10_000_000,
    ) -> dict:
        """Endorse a proposal by staking AP3X."""
        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())

        datum = build_endorsement_datum(
            endorser_did=endorser_did,
            endorser_vkey_hash=vkey_hash,
            proposal_ref_tx=bytes.fromhex(proposal_ref_tx),
            proposal_ref_idx=proposal_ref_idx,
            stake_amount=stake_lovelace,
            created_at=0,
        )

        result = await self.agent.interact_contract(
            script_cbor=self.endorsement_cbor,
            script_type="PlutusV3",
            action="lock",
            datum=cbor2.dumps(datum.data),
            lovelace=stake_lovelace + 2_000_000,
        )

        return {
            "tx_hash": result.tx_hash,
            "script_address": self._script_address(self.endorsement_cbor),
            "stake": stake_lovelace,
        }

    async def withdraw_endorsement(self, utxo_ref: dict) -> dict:
        """Withdraw an endorsement (anytime)."""
        return await self._spend_at(
            self.endorsement_cbor, EndorsementAction.WITHDRAW, utxo_ref
        )

    # ========================================================================
    # Internal
    # ========================================================================

    def _script_name_for_cbor(self, script_cbor: str) -> str | None:
        """Return the script name ('proposal', 'critique', 'endorsement')
        that matches *script_cbor*, or ``None``."""
        for name, cbor_hex in [
            ("proposal", self.proposal_cbor),
            ("critique", self.critique_cbor),
            ("endorsement", self.endorsement_cbor),
        ]:
            if cbor_hex == script_cbor:
                return name
        return None

    async def _spend_at(
        self, script_cbor: str, redeemer: RawPlutusData, utxo_ref: dict
    ) -> dict:
        # Use reference script if available for this script
        script_name = self._script_name_for_cbor(script_cbor)
        ref_utxo = self._reference_utxos.get(script_name) if script_name else None

        if ref_utxo and script_name:
            result = await self.agent.interact_contract(
                script_hash=self._script_hashes[script_name],
                script_type="PlutusV3",
                action="spend",
                redeemer=cbor2.dumps(redeemer.data),
                utxo_ref=utxo_ref,
                reference_utxo=ref_utxo,
            )
        else:
            result = await self.agent.interact_contract(
                script_cbor=script_cbor,
                script_type="PlutusV3",
                action="spend",
                redeemer=cbor2.dumps(redeemer.data),
                utxo_ref=utxo_ref,
            )
        return {"tx_hash": result.tx_hash}
