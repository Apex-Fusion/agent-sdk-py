"""On-chain type encodings for Game 6: Governance Suggestion Engine.

CBOR constructor tags matching the Aiken on-chain types in types.ak.
"""

import cbor2
from pycardano.plutus import PlutusData, RawPlutusData


class ProposalType:
    """Proposal type variants (§4.1 ProposalType)."""

    @staticmethod
    def parameter_change(
        param_name: str, current_value: int, proposed_value: int
    ) -> RawPlutusData:
        return RawPlutusData(
            cbor2.CBORTag(
                121, [param_name.encode("utf-8"), current_value, proposed_value]
            )
        )

    @staticmethod
    def treasury_spend(amount: int, recipient_description: str) -> RawPlutusData:
        return RawPlutusData(
            cbor2.CBORTag(122, [amount, recipient_description.encode("utf-8")])
        )

    @staticmethod
    def protocol_upgrade(upgrade_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(123, [upgrade_hash]))

    @staticmethod
    def game_activation(game_id: int) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(124, [game_id]))

    @staticmethod
    def general_suggestion() -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(125, []))


class ProposalPriority:
    """Proposal priority (§4.1 ProposalPriority)."""

    STANDARD = RawPlutusData(cbor2.CBORTag(121, []))
    EMERGENCY = RawPlutusData(cbor2.CBORTag(122, []))


class ProposalState:
    """Proposal lifecycle state (§4.1 ProposalState)."""

    OPEN = RawPlutusData(cbor2.CBORTag(121, []))

    @staticmethod
    def amended(previous_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(122, [previous_hash]))

    @staticmethod
    def adopted(reasoning_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(123, [reasoning_hash]))

    @staticmethod
    def rejected(reasoning_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(124, [reasoning_hash]))

    EXPIRED = RawPlutusData(cbor2.CBORTag(125, []))
    WITHDRAWN = RawPlutusData(cbor2.CBORTag(126, []))


class ProposalAction:
    """Redeemers for the proposal validator (§4.1 ProposalAction)."""

    SUBMIT = RawPlutusData(cbor2.CBORTag(121, []))
    WITHDRAW = RawPlutusData(cbor2.CBORTag(122, []))

    @staticmethod
    def amend(
        new_hash: bytes, new_uri: str, incorporated_refs: list
    ) -> RawPlutusData:
        return RawPlutusData(
            cbor2.CBORTag(
                123, [new_hash, new_uri.encode("utf-8"), incorporated_refs]
            )
        )

    @staticmethod
    def adopt(reasoning_hash: bytes, reward_amount: int) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(124, [reasoning_hash, reward_amount]))

    @staticmethod
    def reject(reasoning_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(125, [reasoning_hash]))

    EXPIRE = RawPlutusData(cbor2.CBORTag(126, []))
    EXPIRE_STALE = RawPlutusData(cbor2.CBORTag(127, []))

    @staticmethod
    def extend_review(additional_slots: int) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(128, [additional_slots]))


class CritiqueType:
    """Critique type variants (§4.2 CritiqueType)."""

    SUPPORTIVE = RawPlutusData(cbor2.CBORTag(121, []))
    OPPOSING = RawPlutusData(cbor2.CBORTag(122, []))

    @staticmethod
    def amendment(suggested_change_hash: bytes) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(123, [suggested_change_hash]))


class CritiqueAction:
    """Redeemers for the critique validator (§4.2 CritiqueAction)."""

    MINT = RawPlutusData(cbor2.CBORTag(121, []))
    WITHDRAW = RawPlutusData(cbor2.CBORTag(122, []))
    INCORPORATE = RawPlutusData(cbor2.CBORTag(123, []))

    @staticmethod
    def reward(share: int) -> RawPlutusData:
        return RawPlutusData(cbor2.CBORTag(124, [share]))

    BURN = RawPlutusData(cbor2.CBORTag(125, []))


class EndorsementAction:
    """Redeemers for the endorsement validator (§4.3)."""

    MINT = RawPlutusData(cbor2.CBORTag(121, []))
    WITHDRAW = RawPlutusData(cbor2.CBORTag(122, []))
    BURN = RawPlutusData(cbor2.CBORTag(123, []))
