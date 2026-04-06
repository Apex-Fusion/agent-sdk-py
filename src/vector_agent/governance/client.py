"""GovernanceClient — high-level interface for governance actions.

Works with deployed contracts via their compiled script CBOR. Configure via
constructor args or environment variables.

When reference UTxOs are provided (via constructor or
:meth:`set_reference_utxos`), spend transactions use CIP-33 reference
scripts instead of embedding the full script in every transaction, reducing
size and fees by ~85%.
"""

import hashlib
import os

import cbor2
from pycardano import Address, Network
from pycardano.hash import ScriptHash
from pycardano.plutus import PlutusData, PlutusV3Script, RawPlutusData
from pycardano.plutus import script_hash as compute_script_hash
from pycardano.transaction import (
    Asset,
    AssetName,
    MultiAsset,
    TransactionOutput,
    Value,
)

from vector_agent.agent import VectorAgent
from vector_agent.chain.plutus_cbor import plutus_serialise_data
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
        proposal_mint_cbor: str | None = None,
        critique_mint_cbor: str | None = None,
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
        self.proposal_mint_cbor = (
            proposal_mint_cbor
            or os.environ.get("GOVERNANCE_PROPOSAL_MINT_CBOR", "")
        )
        self.critique_mint_cbor = (
            critique_mint_cbor
            or os.environ.get("GOVERNANCE_CRITIQUE_MINT_CBOR", "")
        )

        # Precompute script hashes for use with reference scripts
        self._script_hashes: dict[str, str] = {}
        for name, cbor_hex in [
            ("proposal", self.proposal_cbor),
            ("critique", self.critique_cbor),
            ("endorsement", self.endorsement_cbor),
            ("proposal_mint", self.proposal_mint_cbor),
            ("critique_mint", self.critique_mint_cbor),
        ]:
            if cbor_hex:
                script = PlutusV3Script(bytes.fromhex(cbor_hex))
                self._script_hashes[name] = str(compute_script_hash(script))

        # Reference UTxOs for CIP-33 reference script spending
        self._reference_utxos: dict[str, dict] = reference_utxos or {}

        # Reference inputs included in every spend tx (e.g. GovernanceParams UTXO)
        self._governance_ref_inputs: list[dict] = []

    def set_governance_reference_inputs(self, ref_inputs: list[dict]) -> None:
        """Set reference inputs included in every spend transaction.

        These are UTxOs that validators read via reference inputs, such as
        the GovernanceParams UTXO and Oracle UTXO.

        Args:
            ref_inputs: List of dicts with ``tx_hash``, ``output_index``,
                and ``address`` (bech32 address of the UTxO).
        """
        self._governance_ref_inputs = ref_inputs

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

    # ------------------------------------------------------------------
    # Token name helpers (match on-chain utils.ak / activity_tracking.ak)
    # ------------------------------------------------------------------

    @staticmethod
    def _proposal_token_name(utxo_ref_tx: str, utxo_ref_idx: int) -> bytes:
        """Derive proposal token name: "prop_" + blake2b_256(serialise_data(oref))[0..28].

        Matches on-chain ``utils.proposal_token_name`` which uses
        ``builtin.serialise_data(output_reference)`` then blake2b_256.
        """
        # Aiken OutputReference = Constr(0, [tx_hash_bytes, idx])
        # Must use indefinite-length CBOR arrays to match Aiken's builtin.serialise_data()
        serialized = plutus_serialise_data(0, [bytes.fromhex(utxo_ref_tx), utxo_ref_idx])
        hash_bytes = hashlib.blake2b(serialized, digest_size=32).digest()
        return b"prop_" + hash_bytes[:27]

    @staticmethod
    def _activity_token_name(agent_did) -> bytes:
        """Derive activity token name: "pact_" + blake2b_256(agent_did)[0..27].

        Matches on-chain ``activity_tracking.activity_token_name_for``.
        """
        did_bytes = agent_did if isinstance(agent_did, bytes) else agent_did.encode()
        hash_bytes = hashlib.blake2b(did_bytes, digest_size=32).digest()
        return b"pact_" + hash_bytes[:27]

    @staticmethod
    def _critique_token_name(utxo_ref_tx: str, utxo_ref_idx: int) -> bytes:
        """Derive critique token name: "crit_" + blake2b_256(serialise_data(oref))[0..28]."""
        serialized = plutus_serialise_data(0, [bytes.fromhex(utxo_ref_tx), utxo_ref_idx])
        hash_bytes = hashlib.blake2b(serialized, digest_size=32).digest()
        return b"crit_" + hash_bytes[:27]

    @staticmethod
    def _endorsement_token_name(utxo_ref_tx: str, utxo_ref_idx: int) -> bytes:
        """Derive endorsement token name: "gend_" + blake2b_256(serialise_data(oref))[0..28]."""
        serialized = plutus_serialise_data(0, [bytes.fromhex(utxo_ref_tx), utxo_ref_idx])
        hash_bytes = hashlib.blake2b(serialized, digest_size=32).digest()
        return b"gend_" + hash_bytes[:27]

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
        review_window: int = 604_800_000,
        priority: PlutusData = None,
    ) -> dict:
        """Submit a new governance proposal.

        Args:
            proposer_did: DID of the proposing agent.
            proposal_hash: blake2b_256 hash of proposal document (32 bytes).
            proposal_type: ProposalType variant.
            storage_uri: IPFS/OriginTrail URI for full proposal.
            stake_lovelace: AP3X to stake in lovelace (default 25 AP3X).
            review_window: Review window in POSIX ms (default ~7 days).
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

    async def validated_submit_proposal(
        self,
        proposer_did: str,
        proposal_hash: bytes,
        proposal_type: PlutusData,
        storage_uri: str,
        stake_lovelace: int = 25_000_000,
        review_window: int = 604_800_000,
        priority: PlutusData = None,
    ) -> dict:
        """Submit a governance proposal with full on-chain validation.

        Two-step flow:
        1. Lock ProposalDatum at proposal_spend address
        2. Consume locked UTxO via proposal_spend validator + mint proposal
           token via proposal_mint + create activity tracking UTxO

        This produces a proper proposal token, enabling future withdraw/
        adopt/expire/reject actions.

        Args:
            proposer_did: DID of the proposing agent.
            proposal_hash: blake2b_256 hash of proposal document (32 bytes).
            proposal_type: ProposalType variant.
            storage_uri: IPFS/OriginTrail URI for full proposal.
            stake_lovelace: AP3X to stake in lovelace (default 25 AP3X).
            review_window: Review window in POSIX ms (default ~7 days).
            priority: ProposalPriority (default Standard).

        Returns:
            Dict with tx_hash, script_address, stake, proposal_token_name.
        """
        if len(proposal_hash) != 32:
            raise ValueError("proposal_hash must be 32 bytes (blake2b_256)")
        if not self.proposal_mint_cbor:
            raise ValueError("proposal_mint_cbor is required for validated submit")

        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())
        proposal_address = self._script_address(self.proposal_cbor)
        proposal_mint_hash = self._script_hashes.get("proposal_mint", "")

        # Get current time as POSIX ms (on-chain uses POSIX time, not slot numbers).
        # Query genesis for slot-to-POSIX conversion.
        tip = await self.agent.context._ogmios.query_network_tip()
        current_slot = tip.get("slot", 0)
        try:
            genesis = await self.agent.context._ogmios._rpc(
                "queryNetwork/genesisConfiguration", {"era": "shelley"}
            )
            _sl_ms = genesis.get("slotLength", {}).get("milliseconds", 1000)
            _st_str = genesis.get("startTime", "2025-07-09T10:38:04Z")
            from datetime import datetime, timezone
            _st_dt = datetime.fromisoformat(_st_str.replace("Z", "+00:00"))
            _sys_start_ms = int(_st_dt.timestamp() * 1000)
        except Exception:
            _sl_ms = 1000
            _sys_start_ms = 1752055084000
        current_posix_ms = current_slot * _sl_ms + _sys_start_ms

        # Build the ProposalDatum
        # submitted_at and review_window are both in POSIX ms
        # (matches on-chain current_slot from validity range lower bound)
        datum = build_proposal_datum(
            proposer_did=proposer_did,
            proposer_vkey_hash=vkey_hash,
            proposal_hash=proposal_hash,
            proposal_type=proposal_type,
            storage_uri=storage_uri,
            stake_amount=stake_lovelace,
            submitted_at=current_posix_ms,
            review_window=review_window,
            priority=priority,
        )

        # Step 1: Lock ProposalDatum at script address
        lock_result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="lock",
            datum=cbor2.dumps(datum.data),
            lovelace=stake_lovelace + 2_000_000,
        )
        lock_tx = lock_result.tx_hash
        lock_idx = 0  # First output is the script output
        print(f"[DEBUG] lock_tx={lock_tx}, lock_idx={lock_idx}")

        # Wait for lock tx to confirm (poll until UTxO appears)
        import asyncio
        for _attempt in range(6):
            await asyncio.sleep(5)
            try:
                utxos = await self.agent.context.async_utxos(proposal_address)
                if any(
                    str(u.input.transaction_id) == lock_tx
                    and u.input.index == lock_idx
                    for u in utxos
                ):
                    break
            except Exception:
                pass

        # Step 2: Consume locked UTxO + mint proposal token + create activity
        # The on-chain current_slot is in POSIX time (ms), not slot numbers.
        # The ledger converts validity_start (slot) to POSIX time before passing
        # to Plutus scripts. We need the same POSIX time for the activity datum.
        #
        # Formula: posix_ms = slot * slot_length_ms + system_start_ms
        # Vector testnet: slot_length=1000ms, start=2025-07-09T10:38:04Z
        tip = await self.agent.context._ogmios.query_network_tip()
        tip_slot = tip.get("slot", 0)
        spend_slot = tip_slot - 60  # slot number for validity_start

        # Query genesis to get the slot-to-POSIX conversion params
        try:
            genesis = await self.agent.context._ogmios._rpc(
                "queryNetwork/genesisConfiguration", {"era": "shelley"}
            )
            slot_length_ms = genesis.get("slotLength", {}).get("milliseconds", 1000)
            start_time_str = genesis.get("startTime", "2025-07-09T10:38:04Z")
            from datetime import datetime, timezone
            start_dt = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            system_start_ms = int(start_dt.timestamp() * 1000)
        except Exception:
            # Fallback: Vector testnet defaults
            slot_length_ms = 1000
            system_start_ms = 1752055084000  # 2025-07-09T10:38:04Z in ms

        spend_posix_ms = spend_slot * slot_length_ms + system_start_ms

        # Derive the proposal token name from the locked UTxO ref
        prop_token = self._proposal_token_name(lock_tx, lock_idx)
        act_token = self._activity_token_name(proposer_did)
        print(f"[DEBUG] prop_token={prop_token.hex()}, act_token={act_token.hex()}")

        # Build activity datum — last_proposal_slot must equal validity_start
        activity_datum = RawPlutusData(
            cbor2.CBORTag(
                121,
                [
                    proposer_did if isinstance(proposer_did, bytes) else proposer_did.encode("utf-8"),
                    cbor2.CBORTag(121, [vkey_hash]),  # credential
                    1,  # active_proposal_count
                    spend_posix_ms,  # last_proposal_slot in POSIX ms (matches on-chain current_slot)
                ],
            )
        )

        # Build outputs: proposal datum + activity datum, both at proposal_spend
        proposal_script_hash = ScriptHash.from_primitive(
            bytes.fromhex(self._script_hashes["proposal"])
        )
        proposal_addr = Address(
            payment_part=proposal_script_hash, network=Network.MAINNET
        )

        # Proposal output: stake + proposal token
        prop_ma = MultiAsset()
        mint_policy_hash = ScriptHash.from_primitive(
            bytes.fromhex(proposal_mint_hash)
        )
        prop_ma[mint_policy_hash] = Asset()
        prop_ma[mint_policy_hash][AssetName(prop_token)] = 1
        proposal_output = TransactionOutput(
            proposal_addr,
            Value(stake_lovelace + 2_000_000, prop_ma),
            datum=RawPlutusData(datum.data),
        )

        # Activity output: activity token
        act_ma = MultiAsset()
        act_ma[mint_policy_hash] = Asset()
        act_ma[mint_policy_hash][AssetName(act_token)] = 1
        activity_output = TransactionOutput(
            proposal_addr,
            Value(2_000_000, act_ma),
            datum=RawPlutusData(activity_datum.data),
        )

        # Mint both tokens
        mint_assets = {
            prop_token.hex(): 1,
            act_token.hex(): 1,
        }

        # Include governance reference inputs
        ref_inputs = self._governance_ref_inputs or None

        result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="spend",
            redeemer=cbor2.dumps(ProposalAction.SUBMIT.data),
            utxo_ref={"tx_hash": lock_tx, "output_index": lock_idx},
            reference_inputs=ref_inputs,
            mint_assets=mint_assets,
            mint_script_cbor=self.proposal_mint_cbor,
            mint_redeemer=cbor2.dumps(ProposalAction.SUBMIT.data),
            additional_outputs=[proposal_output, activity_output],
            validity_start=spend_slot,
        )

        return {
            "tx_hash": result.tx_hash,
            "lock_tx_hash": lock_tx,
            "script_address": proposal_address,
            "stake": stake_lovelace,
            "proposal_token_name": prop_token.hex(),
        }

    async def withdraw_proposal(self, utxo_ref: dict) -> dict:
        """Withdraw a proposal (proposer only). Stake is returned.

        Simple version — does not burn proposal token or update activity.
        Use :meth:`validated_withdraw_proposal` for full on-chain flow.
        """
        return await self._spend_at(
            self.proposal_cbor, ProposalAction.WITHDRAW, utxo_ref
        )

    async def validated_withdraw_proposal(
        self,
        utxo_ref: dict,
        activity_utxo_ref: dict,
        proposer_did: str,
    ) -> dict:
        """Withdraw a proposal with full validator compliance.

        Burns the proposal token, decrements the activity counter,
        and returns the stake to the wallet.

        Args:
            utxo_ref: The proposal UTxO to withdraw (tx_hash + output_index).
            activity_utxo_ref: The activity UTxO (tx_hash + output_index).
            proposer_did: Proposer's DID (for activity token lookup).
        """
        if not self.proposal_mint_cbor:
            raise ValueError("proposal_mint_cbor is required for validated withdraw")

        proposal_address = self._script_address(self.proposal_cbor)
        proposal_mint_hash = self._script_hashes.get("proposal_mint", "")

        # Fetch the proposal UTxO to find the proposal token name
        proposal_utxos = await self.agent.context.async_utxos(proposal_address)
        target_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == utxo_ref["tx_hash"]
                and u.input.index == utxo_ref["output_index"]
            ):
                target_utxo = u
                break
        if target_utxo is None:
            raise ValueError(f"Proposal UTxO not found: {utxo_ref}")

        # Find the proposal token name from the UTxO's multi-asset
        prop_token_name = None
        mint_policy = ScriptHash.from_primitive(bytes.fromhex(proposal_mint_hash))
        if hasattr(target_utxo.output.amount, 'multi_asset') and target_utxo.output.amount.multi_asset:
            for pid, assets in target_utxo.output.amount.multi_asset.items():
                if pid.payload.hex() == proposal_mint_hash:
                    for aname in assets:
                        if aname.payload[:5] == b"prop_":
                            prop_token_name = aname.payload
                            break

        if prop_token_name is None:
            raise ValueError("No proposal token (prop_*) found in UTxO")

        # Fetch the activity UTxO
        activity_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == activity_utxo_ref["tx_hash"]
                and u.input.index == activity_utxo_ref["output_index"]
            ):
                activity_utxo = u
                break
        if activity_utxo is None:
            raise ValueError(f"Activity UTxO not found: {activity_utxo_ref}")

        # Decode current activity datum to get count
        import cbor2 as cbor2_mod
        act_datum_raw = activity_utxo.output.datum.data  # RawPlutusData
        old_count = act_datum_raw.value[2]  # active_proposal_count

        # Build decremented activity datum
        act_token = self._activity_token_name(proposer_did)
        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())
        new_activity_datum = RawPlutusData(
            cbor2.CBORTag(
                121,
                [
                    proposer_did if isinstance(proposer_did, bytes) else proposer_did.encode("utf-8"),
                    cbor2.CBORTag(121, [vkey_hash]),
                    old_count - 1,
                    act_datum_raw.value[3],  # last_proposal_slot unchanged
                ],
            )
        )

        # Build activity output
        proposal_script_hash = ScriptHash.from_primitive(
            bytes.fromhex(self._script_hashes["proposal"])
        )
        proposal_addr = Address(
            payment_part=proposal_script_hash, network=Network.MAINNET
        )

        act_ma = MultiAsset()
        act_ma[mint_policy] = Asset()
        act_ma[mint_policy][AssetName(act_token)] = 1
        activity_output = TransactionOutput(
            proposal_addr,
            Value(2_000_000, act_ma),
            datum=RawPlutusData(new_activity_datum.data),
        )

        # Burn proposal token: -1
        mint_assets = {prop_token_name.hex(): -1}

        # Build activity UTxO as additional script input
        # Activity input uses SpendActivity redeemer (not WithdrawProposal),
        # because the validator would crash trying to parse ProposerActivityDatum
        # as ProposalDatum. SpendActivity just guards that a proposal spend
        # is also happening in the same tx.
        activity_redeemer = RawPlutusData(ProposalAction.SPEND_ACTIVITY.data)
        additional_inputs = [{
            "utxo": activity_utxo,
            "redeemer": activity_redeemer,
        }]

        ref_inputs = self._governance_ref_inputs or None

        result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="spend",
            redeemer=cbor2.dumps(ProposalAction.WITHDRAW.data),
            utxo_ref=utxo_ref,
            reference_inputs=ref_inputs,
            mint_assets=mint_assets,
            mint_script_cbor=self.proposal_mint_cbor,
            mint_redeemer=cbor2.dumps(ProposalAction.WITHDRAW.data),
            additional_outputs=[activity_output],
            additional_script_inputs=additional_inputs,
        )

        return {"tx_hash": result.tx_hash}

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
        """Expire a proposal after review window (simple, no token burn).

        For full on-chain compliance, use :meth:`validated_expire_proposal`.
        """
        return await self._spend_at(
            self.proposal_cbor, ProposalAction.EXPIRE, utxo_ref
        )

    async def validated_expire_proposal(
        self,
        utxo_ref: dict,
        activity_utxo_ref: dict,
        proposer_did: str | bytes,
    ) -> dict:
        """Expire a proposal with full on-chain validation.

        Burns the proposal token, decrements activity, and returns
        the proposer's stake. Callable by anyone after review window.

        Args:
            utxo_ref: The proposal UTxO to expire (tx_hash + output_index).
            activity_utxo_ref: The proposer's activity UTxO (tx_hash + output_index).
            proposer_did: Proposer's DID (for activity token lookup).
        """
        if not self.proposal_mint_cbor:
            raise ValueError("proposal_mint_cbor is required for validated expire")

        proposal_address = self._script_address(self.proposal_cbor)
        proposal_mint_hash = self._script_hashes.get("proposal_mint", "")

        # Fetch the proposal UTxO to find the proposal token
        proposal_utxos = await self.agent.context.async_utxos(proposal_address)
        target_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == utxo_ref["tx_hash"]
                and u.input.index == utxo_ref["output_index"]
            ):
                target_utxo = u
                break
        if target_utxo is None:
            raise ValueError(f"Proposal UTxO not found: {utxo_ref}")

        # Find the proposal token name
        prop_token_name = None
        mint_policy = ScriptHash.from_primitive(bytes.fromhex(proposal_mint_hash))
        if hasattr(target_utxo.output.amount, 'multi_asset') and target_utxo.output.amount.multi_asset:
            for pid, assets_map in target_utxo.output.amount.multi_asset.items():
                if pid.payload.hex() == proposal_mint_hash:
                    for aname in assets_map:
                        if aname.payload[:5] == b"prop_":
                            prop_token_name = aname.payload
                            break
        if prop_token_name is None:
            raise ValueError("No proposal token (prop_*) found in UTxO")

        # Fetch the activity UTxO
        activity_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == activity_utxo_ref["tx_hash"]
                and u.input.index == activity_utxo_ref["output_index"]
            ):
                activity_utxo = u
                break
        if activity_utxo is None:
            raise ValueError(f"Activity UTxO not found: {activity_utxo_ref}")

        # Decode current activity datum to get count
        act_datum_raw = activity_utxo.output.datum.data
        old_count = act_datum_raw.value[2]

        # Build decremented activity datum
        act_token = self._activity_token_name(proposer_did)
        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())
        new_activity_datum = RawPlutusData(
            cbor2.CBORTag(
                121,
                [
                    proposer_did if isinstance(proposer_did, bytes) else proposer_did.encode("utf-8"),
                    cbor2.CBORTag(121, [vkey_hash]),
                    old_count - 1,
                    act_datum_raw.value[3],
                ],
            )
        )

        # Build activity output
        proposal_script_hash = ScriptHash.from_primitive(
            bytes.fromhex(self._script_hashes["proposal"])
        )
        proposal_addr = Address(
            payment_part=proposal_script_hash, network=Network.MAINNET
        )

        act_ma = MultiAsset()
        act_ma[mint_policy] = Asset()
        act_ma[mint_policy][AssetName(act_token)] = 1
        activity_output = TransactionOutput(
            proposal_addr,
            Value(2_000_000, act_ma),
            datum=RawPlutusData(new_activity_datum.data),
        )

        # Burn proposal token
        mint_assets = {prop_token_name.hex(): -1}

        # Activity input uses SpendActivity redeemer
        activity_redeemer = RawPlutusData(ProposalAction.SPEND_ACTIVITY.data)
        additional_inputs = [{
            "utxo": activity_utxo,
            "redeemer": activity_redeemer,
        }]

        ref_inputs = self._governance_ref_inputs or None

        # Get current tip for validity_start
        tip = await self.agent.context._ogmios.query_network_tip()
        tip_slot = tip.get("slot", 0)
        spend_slot = tip_slot - 60

        result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="spend",
            redeemer=cbor2.dumps(ProposalAction.EXPIRE.data),
            utxo_ref=utxo_ref,
            reference_inputs=ref_inputs,
            mint_assets=mint_assets,
            mint_script_cbor=self.proposal_mint_cbor,
            mint_redeemer=cbor2.dumps(ProposalAction.EXPIRE.data),
            additional_outputs=[activity_output],
            additional_script_inputs=additional_inputs,
            validity_start=spend_slot,
        )

        return {"tx_hash": result.tx_hash}

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
        """Foundation adopts a proposal (simple oracle action, no token burn).

        For full on-chain compliance, use :meth:`validated_adopt_proposal`.

        Args:
            utxo_ref: Proposal UTxO reference.
            reasoning_hash: blake2b_256 hash of adoption reasoning.
            reward_amount: AP3X reward in lovelace.
        """
        redeemer = ProposalAction.adopt(reasoning_hash, reward_amount)
        result = await self._spend_at(self.proposal_cbor, redeemer, utxo_ref)
        result["reward"] = reward_amount
        return result

    async def validated_adopt_proposal(
        self,
        utxo_ref: dict,
        activity_utxo_ref: dict,
        proposer_did: str | bytes,
        reasoning_hash: bytes,
        reward_amount: int,
    ) -> dict:
        """Foundation adopts a proposal with full on-chain validation.

        Burns the proposal token, decrements activity, and returns
        the proposer's stake. The wallet must be the oracle signer.

        Args:
            utxo_ref: The proposal UTxO to adopt (tx_hash + output_index).
            activity_utxo_ref: The proposer's activity UTxO (tx_hash + output_index).
            proposer_did: Proposer's DID (for activity token lookup).
            reasoning_hash: blake2b_256 hash of adoption reasoning (32 bytes).
            reward_amount: AP3X reward in lovelace.
        """
        if not self.proposal_mint_cbor:
            raise ValueError("proposal_mint_cbor is required for validated adopt")
        if len(reasoning_hash) != 32:
            raise ValueError("reasoning_hash must be 32 bytes")

        proposal_address = self._script_address(self.proposal_cbor)
        proposal_mint_hash = self._script_hashes.get("proposal_mint", "")

        # Fetch the proposal UTxO to find the proposal token and datum
        proposal_utxos = await self.agent.context.async_utxos(proposal_address)
        target_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == utxo_ref["tx_hash"]
                and u.input.index == utxo_ref["output_index"]
            ):
                target_utxo = u
                break
        if target_utxo is None:
            raise ValueError(f"Proposal UTxO not found: {utxo_ref}")

        # Find the proposal token name
        prop_token_name = None
        mint_policy = ScriptHash.from_primitive(bytes.fromhex(proposal_mint_hash))
        if hasattr(target_utxo.output.amount, 'multi_asset') and target_utxo.output.amount.multi_asset:
            for pid, assets_map in target_utxo.output.amount.multi_asset.items():
                if pid.payload.hex() == proposal_mint_hash:
                    for aname in assets_map:
                        if aname.payload[:5] == b"prop_":
                            prop_token_name = aname.payload
                            break
        if prop_token_name is None:
            raise ValueError("No proposal token (prop_*) found in UTxO")

        # Fetch the activity UTxO
        activity_utxo = None
        for u in proposal_utxos:
            if (
                str(u.input.transaction_id) == activity_utxo_ref["tx_hash"]
                and u.input.index == activity_utxo_ref["output_index"]
            ):
                activity_utxo = u
                break
        if activity_utxo is None:
            raise ValueError(f"Activity UTxO not found: {activity_utxo_ref}")

        # Decode current activity datum to get count
        act_datum_raw = activity_utxo.output.datum.data
        old_count = act_datum_raw.value[2]

        # Build decremented activity datum
        act_token = self._activity_token_name(proposer_did)
        vkey_hash = bytes(self.agent._wallet.payment_verification_key.hash())
        new_activity_datum = RawPlutusData(
            cbor2.CBORTag(
                121,
                [
                    proposer_did if isinstance(proposer_did, bytes) else proposer_did.encode("utf-8"),
                    cbor2.CBORTag(121, [vkey_hash]),
                    old_count - 1,
                    act_datum_raw.value[3],
                ],
            )
        )

        # Build activity output
        proposal_script_hash = ScriptHash.from_primitive(
            bytes.fromhex(self._script_hashes["proposal"])
        )
        proposal_addr = Address(
            payment_part=proposal_script_hash, network=Network.MAINNET
        )

        act_ma = MultiAsset()
        act_ma[mint_policy] = Asset()
        act_ma[mint_policy][AssetName(act_token)] = 1
        activity_output = TransactionOutput(
            proposal_addr,
            Value(2_000_000, act_ma),
            datum=RawPlutusData(new_activity_datum.data),
        )

        # Burn proposal token
        mint_assets = {prop_token_name.hex(): -1}

        # Activity input uses SpendActivity redeemer
        activity_redeemer = RawPlutusData(ProposalAction.SPEND_ACTIVITY.data)
        additional_inputs = [{
            "utxo": activity_utxo,
            "redeemer": activity_redeemer,
        }]

        ref_inputs = self._governance_ref_inputs or None

        # Get current tip for validity_start
        tip = await self.agent.context._ogmios.query_network_tip()
        tip_slot = tip.get("slot", 0)
        spend_slot = tip_slot - 60

        redeemer = ProposalAction.adopt(reasoning_hash, reward_amount)
        result = await self.agent.interact_contract(
            script_cbor=self.proposal_cbor,
            script_type="PlutusV3",
            action="spend",
            redeemer=cbor2.dumps(redeemer.data),
            utxo_ref=utxo_ref,
            reference_inputs=ref_inputs,
            mint_assets=mint_assets,
            mint_script_cbor=self.proposal_mint_cbor,
            mint_redeemer=cbor2.dumps(redeemer.data),
            additional_outputs=[activity_output],
            additional_script_inputs=additional_inputs,
            validity_start=spend_slot,
        )

        return {
            "tx_hash": result.tx_hash,
            "reward": reward_amount,
        }

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

        # Include governance reference inputs (params, oracle, etc.)
        ref_inputs = self._governance_ref_inputs or None

        if ref_utxo and script_name:
            result = await self.agent.interact_contract(
                script_hash=self._script_hashes[script_name],
                script_type="PlutusV3",
                action="spend",
                redeemer=cbor2.dumps(redeemer.data),
                utxo_ref=utxo_ref,
                reference_utxo=ref_utxo,
                reference_inputs=ref_inputs,
            )
        else:
            result = await self.agent.interact_contract(
                script_cbor=script_cbor,
                script_type="PlutusV3",
                action="spend",
                redeemer=cbor2.dumps(redeemer.data),
                utxo_ref=utxo_ref,
                reference_inputs=ref_inputs,
            )
        return {"tx_hash": result.tx_hash}
