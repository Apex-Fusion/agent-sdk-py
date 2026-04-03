"""GovernanceIndexer — on-demand query layer for governance UTxOs.

Queries proposal, critique, and endorsement UTxOs from the chain,
decodes inline datums, and provides filtered/sorted views.

Phase 1.0: All queries are live UTxO scans via Ogmios.
No separate database required.
"""

import cbor2
from typing import Optional

from pycardano import Address, Network
from pycardano.hash import ScriptHash
from pycardano.plutus import RawPlutusData


# CBOR constructor tag offsets for Plutus sum types
_PROPOSAL_STATE_NAMES = {
    121: "Open",
    122: "Amended",
    123: "Adopted",
    124: "Rejected",
    125: "Expired",
    126: "Withdrawn",
}

_PROPOSAL_TYPE_NAMES = {
    121: "ParameterChange",
    122: "TreasurySpend",
    123: "ProtocolUpgrade",
    124: "GameActivation",
    125: "GeneralSuggestion",
}

_PRIORITY_NAMES = {
    121: "Standard",
    122: "Emergency",
}

_CRITIQUE_TYPE_NAMES = {
    121: "Supportive",
    122: "Opposing",
    123: "Amendment",
}


def _decode_datum(raw_datum) -> Optional[dict]:
    """Decode a PyCardano inline datum into a Python dict via CBOR."""
    if raw_datum is None:
        return None
    try:
        if isinstance(raw_datum, RawPlutusData):
            data = raw_datum.data
        elif isinstance(raw_datum, bytes):
            data = cbor2.loads(raw_datum)
        else:
            data = raw_datum
        if hasattr(data, "tag") and hasattr(data, "value"):
            return {"tag": data.tag, "value": data.value}
        return None
    except Exception:
        return None


def _decode_proposal(datum_dict: dict) -> Optional[dict]:
    """Parse a ProposalDatum from a decoded CBOR constructor."""
    if datum_dict is None:
        return None
    fields = datum_dict.get("value", [])
    if len(fields) < 12:
        return None
    try:
        state_tag = fields[11]
        state_name = "Unknown"
        if hasattr(state_tag, "tag"):
            state_name = _PROPOSAL_STATE_NAMES.get(state_tag.tag, "Unknown")

        type_tag = fields[3]
        type_name = "Unknown"
        if hasattr(type_tag, "tag"):
            type_name = _PROPOSAL_TYPE_NAMES.get(type_tag.tag, "Unknown")

        priority_tag = fields[8]
        priority_name = "Unknown"
        if hasattr(priority_tag, "tag"):
            priority_name = _PRIORITY_NAMES.get(priority_tag.tag, "Unknown")

        return {
            "proposer_did": fields[0].hex() if isinstance(fields[0], bytes) else str(fields[0]),
            "proposal_hash": fields[2].hex() if isinstance(fields[2], bytes) else str(fields[2]),
            "proposal_type": type_name,
            "storage_uri": fields[4].decode("utf-8") if isinstance(fields[4], bytes) else str(fields[4]),
            "stake_amount": fields[5],
            "submitted_at": fields[6],
            "review_window": fields[7],
            "priority": priority_name,
            "amendment_count": fields[9],
            "incorporated_critiques": len(fields[10]) if isinstance(fields[10], list) else 0,
            "state": state_name,
        }
    except Exception:
        return None


def _decode_critique(datum_dict: dict) -> Optional[dict]:
    """Parse a CritiqueDatum from a decoded CBOR constructor."""
    if datum_dict is None:
        return None
    fields = datum_dict.get("value", [])
    if len(fields) < 9:
        return None
    try:
        critique_type_tag = fields[5]
        type_name = "Unknown"
        if hasattr(critique_type_tag, "tag"):
            type_name = _CRITIQUE_TYPE_NAMES.get(critique_type_tag.tag, "Unknown")

        # Decode incorporated bool (CBORTag 121=False, 122=True)
        incorporated = False
        if hasattr(fields[8], "tag"):
            incorporated = fields[8].tag == 122

        # Decode proposal_ref
        proposal_ref = None
        if hasattr(fields[2], "tag") and hasattr(fields[2], "value"):
            ref_fields = fields[2].value
            if len(ref_fields) >= 2:
                proposal_ref = {
                    "tx_hash": ref_fields[0].hex() if isinstance(ref_fields[0], bytes) else str(ref_fields[0]),
                    "output_index": ref_fields[1],
                }

        return {
            "critic_did": fields[0].hex() if isinstance(fields[0], bytes) else str(fields[0]),
            "proposal_ref": proposal_ref,
            "critique_hash": fields[3].hex() if isinstance(fields[3], bytes) else str(fields[3]),
            "storage_uri": fields[4].decode("utf-8") if isinstance(fields[4], bytes) else str(fields[4]),
            "critique_type": type_name,
            "stake_amount": fields[6],
            "submitted_at": fields[7],
            "incorporated": incorporated,
        }
    except Exception:
        return None


def _decode_endorsement(datum_dict: dict) -> Optional[dict]:
    """Parse a GovernanceEndorsementDatum from a decoded CBOR constructor."""
    if datum_dict is None:
        return None
    fields = datum_dict.get("value", [])
    if len(fields) < 5:
        return None
    try:
        proposal_ref = None
        if hasattr(fields[2], "tag") and hasattr(fields[2], "value"):
            ref_fields = fields[2].value
            if len(ref_fields) >= 2:
                proposal_ref = {
                    "tx_hash": ref_fields[0].hex() if isinstance(ref_fields[0], bytes) else str(ref_fields[0]),
                    "output_index": ref_fields[1],
                }

        return {
            "endorser_did": fields[0].hex() if isinstance(fields[0], bytes) else str(fields[0]),
            "proposal_ref": proposal_ref,
            "stake_amount": fields[3],
            "created_at": fields[4],
        }
    except Exception:
        return None


class GovernanceIndexer:
    """On-demand query layer for governance UTxOs.

    Queries UTxOs at validator script addresses, decodes inline datums,
    and returns structured Python dicts.

    Parameters
    ----------
    context : VectorChainContext
        Chain context with async_utxos support.
    proposal_spend_hash : str
        Script hash of the proposal_spend validator.
    critique_spend_hash : str
        Script hash of the critique_spend validator.
    endorsement_spend_hash : str
        Script hash of the endorsement_spend validator.
    treasury_address : str
        Address of the treasury holder script.
    """

    def __init__(
        self,
        context,
        proposal_spend_hash: str,
        critique_spend_hash: str = "",
        endorsement_spend_hash: str = "",
        treasury_address: str = "",
    ):
        self._context = context
        self._proposal_addr = self._script_address(proposal_spend_hash) if proposal_spend_hash else ""
        self._critique_addr = self._script_address(critique_spend_hash) if critique_spend_hash else ""
        self._endorsement_addr = self._script_address(endorsement_spend_hash) if endorsement_spend_hash else ""
        self._treasury_addr = treasury_address

    @staticmethod
    def _script_address(script_hash_hex: str) -> str:
        sh = ScriptHash.from_primitive(bytes.fromhex(script_hash_hex))
        return str(Address(payment_part=sh, network=Network.MAINNET))

    async def get_proposals(
        self,
        state: Optional[str] = None,
        proposal_type: Optional[str] = None,
        proposer_did: Optional[str] = None,
        sort_by: str = "submitted_at",
        descending: bool = True,
    ) -> list[dict]:
        """Query proposals, optionally filtered by state/type/proposer.

        Returns a list of dicts with decoded proposal fields plus
        ``utxo_ref`` (tx_hash, output_index) and ``lovelace``.
        """
        if not self._proposal_addr:
            return []

        utxos = await self._context.async_utxos(self._proposal_addr)
        proposals = []

        for u in utxos:
            datum_dict = _decode_datum(u.output.datum)
            proposal = _decode_proposal(datum_dict)
            if proposal is None:
                continue

            # Filters
            if state and proposal["state"] != state:
                continue
            if proposal_type and proposal["proposal_type"] != proposal_type:
                continue
            if proposer_did and proposal["proposer_did"] != proposer_did:
                continue

            proposal["utxo_ref"] = {
                "tx_hash": str(u.input.transaction_id),
                "output_index": u.input.index,
            }
            lovelace = u.output.amount
            if hasattr(lovelace, "coin"):
                proposal["lovelace"] = lovelace.coin
            elif isinstance(lovelace, int):
                proposal["lovelace"] = lovelace
            else:
                proposal["lovelace"] = 0

            proposals.append(proposal)

        # Sort
        if sort_by in ("submitted_at", "stake_amount"):
            proposals.sort(key=lambda p: p.get(sort_by, 0), reverse=descending)

        return proposals

    async def get_critiques(
        self,
        proposal_tx_hash: Optional[str] = None,
        proposal_output_index: Optional[int] = None,
    ) -> list[dict]:
        """Query critiques, optionally filtered by the proposal they reference."""
        if not self._critique_addr:
            return []

        utxos = await self._context.async_utxos(self._critique_addr)
        critiques = []

        for u in utxos:
            datum_dict = _decode_datum(u.output.datum)
            critique = _decode_critique(datum_dict)
            if critique is None:
                continue

            # Filter by proposal ref
            if proposal_tx_hash and critique.get("proposal_ref"):
                ref = critique["proposal_ref"]
                if ref["tx_hash"] != proposal_tx_hash:
                    continue
                if proposal_output_index is not None and ref["output_index"] != proposal_output_index:
                    continue

            critique["utxo_ref"] = {
                "tx_hash": str(u.input.transaction_id),
                "output_index": u.input.index,
            }
            critiques.append(critique)

        return critiques

    async def get_endorsements(
        self,
        proposal_tx_hash: Optional[str] = None,
        proposal_output_index: Optional[int] = None,
    ) -> list[dict]:
        """Query endorsements, optionally filtered by the proposal they reference."""
        if not self._endorsement_addr:
            return []

        utxos = await self._context.async_utxos(self._endorsement_addr)
        endorsements = []

        for u in utxos:
            datum_dict = _decode_datum(u.output.datum)
            endorsement = _decode_endorsement(datum_dict)
            if endorsement is None:
                continue

            if proposal_tx_hash and endorsement.get("proposal_ref"):
                ref = endorsement["proposal_ref"]
                if ref["tx_hash"] != proposal_tx_hash:
                    continue
                if proposal_output_index is not None and ref["output_index"] != proposal_output_index:
                    continue

            endorsement["utxo_ref"] = {
                "tx_hash": str(u.input.transaction_id),
                "output_index": u.input.index,
            }
            endorsements.append(endorsement)

        return endorsements

    async def get_quality_signal(self, proposal_tx_hash: str, proposal_output_index: int = 0) -> dict:
        """Compute quality signal for a proposal: endorsement stake + critique count."""
        endorsements = await self.get_endorsements(proposal_tx_hash, proposal_output_index)
        critiques = await self.get_critiques(proposal_tx_hash, proposal_output_index)

        total_endorsement_stake = sum(e.get("stake_amount", 0) for e in endorsements)
        supporting = sum(1 for c in critiques if c.get("critique_type") == "Supportive")
        opposing = sum(1 for c in critiques if c.get("critique_type") == "Opposing")
        amendments = sum(1 for c in critiques if c.get("critique_type") == "Amendment")

        return {
            "endorsement_count": len(endorsements),
            "total_endorsement_stake": total_endorsement_stake,
            "critique_count": len(critiques),
            "supporting_critiques": supporting,
            "opposing_critiques": opposing,
            "amendment_critiques": amendments,
        }

    async def get_agent_track_record(self, agent_did: str) -> dict:
        """Get an agent's governance track record by scanning proposals."""
        proposals = await self.get_proposals(proposer_did=agent_did)

        by_state = {}
        total_stake = 0
        for p in proposals:
            s = p.get("state", "Unknown")
            by_state[s] = by_state.get(s, 0) + 1
            total_stake += p.get("stake_amount", 0)

        return {
            "agent_did": agent_did,
            "total_proposals": len(proposals),
            "by_state": by_state,
            "total_stake_committed": total_stake,
            "adopted_count": by_state.get("Adopted", 0),
            "adoption_rate": (
                by_state.get("Adopted", 0) / len(proposals) if proposals else 0.0
            ),
        }

    async def get_treasury_balance(self) -> dict:
        """Sum lovelace at the treasury holder address."""
        if not self._treasury_addr:
            return {"total_lovelace": 0, "utxo_count": 0}

        utxos = await self._context.async_utxos(self._treasury_addr)
        total = 0
        for u in utxos:
            amount = u.output.amount
            if hasattr(amount, "coin"):
                total += amount.coin
            elif isinstance(amount, int):
                total += amount

        return {
            "total_lovelace": total,
            "utxo_count": len(utxos),
            "total_apex": total / 1_000_000,
        }
