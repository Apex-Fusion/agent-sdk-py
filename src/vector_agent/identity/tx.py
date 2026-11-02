"""Transaction assembly for the identity clients.

A client fills a :class:`TxPlan` (validity window, script spends, mints,
withdrawals, reference inputs, outputs and required signers). :func:`build`
balances it with the PyCardano ``TransactionBuilder``: the funding address
pays the fee, the collateral and any deposit, and gets the change. The result
is an unsigned :class:`BuiltTx` with every key hash that must sign. Signing
stays with the caller: each key holder adds a witness in turn
(:func:`add_signatures`).

Every identity, attestation, delegation and vault transaction has a finite
validity range with ``hi - lo <= 3,600,000`` ms (Part 2 §3.2). The window
starts 60 s before the tip, so that a node with a slightly older tip accepts
the transaction, and ends ``valid_for`` seconds after the tip.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    Network,
    Redeemer,
    ScriptHash,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    VerificationKeyHash,
    VerificationKeyWitness,
    Withdrawals,
)
from pycardano.key import ExtendedSigningKey, SigningKey
from pycardano.serialization import RawCBOR
from pycardano.utils import min_lovelace_post_alonzo

from vector_agent.exceptions import TransactionError
from vector_agent.identity.constants import MAX_RANGE_MS
from vector_agent.identity.context import IdentityContext, ScriptSource, utxo_ref
from vector_agent.identity.plutus_data import PlutusData, encode_data

#: A redeemer: a value with ``to_data()``, Plutus Data, or CBOR bytes.
RedeemerValue = Any

__all__ = [
    "DEFAULT_VALID_FOR_S",
    "BuiltTx",
    "TxPlan",
    "Window",
    "add_signatures",
    "build",
    "make_window",
    "min_lovelace",
]

#: Default seconds between the tip and the end of the validity range.
DEFAULT_VALID_FOR_S = 900
#: The validity range starts this many milliseconds before the tip.
BACKPAD_MS = 60_000


@dataclass(frozen=True)
class Window:
    """A validity range: slots for the ledger, POSIX milliseconds for the scripts."""

    lo_slot: int
    hi_slot: int
    lo: int
    hi: int


def make_window(
    ctx: IdentityContext,
    *,
    valid_for: int = DEFAULT_VALID_FOR_S,
    tip_slot: int | None = None,
) -> Window:
    """``[tip - 60 s, tip + valid_for]``; ``hi - lo`` must stay within one hour."""
    clock = ctx.clock
    tip = ctx.ledger.tip_slot() if tip_slot is None else tip_slot
    lo_slot = clock.slot_at_or_before(clock.posix_ms(tip) - BACKPAD_MS)
    hi_slot = clock.slot_at_or_before(clock.posix_ms(tip) + valid_for * 1000)
    lo, hi = clock.posix_ms(lo_slot), clock.posix_ms(hi_slot)
    if valid_for <= 0 or hi - lo > MAX_RANGE_MS:
        raise ValueError(
            f"valid_for must be 1..{(MAX_RANGE_MS - BACKPAD_MS) // 1000} seconds (the range is at most one hour)"
        )
    return Window(lo_slot, hi_slot, lo, hi)


@dataclass
class _ScriptSpend:
    utxo: UTxO
    source: ScriptSource
    redeemer: bytes
    datum: object | None = None


@dataclass
class TxPlan:
    """What a client wants in a transaction. ``build`` adds funding and change."""

    window: Window
    inputs: list[UTxO] = field(default_factory=list)
    spends: list[_ScriptSpend] = field(default_factory=list)
    mints: list[tuple[ScriptSource, dict[bytes, int], bytes]] = field(default_factory=list)
    withdrawals: list[tuple[ScriptSource, bytes]] = field(default_factory=list)
    reference_inputs: list[UTxO] = field(default_factory=list)
    outputs: list[TransactionOutput] = field(default_factory=list)
    signers: list[bytes] = field(default_factory=list)
    created_id: bytes | None = None

    def add_input(self, utxo: UTxO) -> None:
        self.inputs.append(utxo)

    def spend(self, utxo: UTxO, source: ScriptSource, redeemer: RedeemerValue, datum=None) -> None:
        self.spends.append(_ScriptSpend(utxo, source, _cbor(redeemer), datum))

    def mint(self, source: ScriptSource, assets: dict[bytes, int], redeemer: RedeemerValue) -> None:
        self.mints.append((source, dict(assets), _cbor(redeemer)))

    def withdraw_zero(self, source: ScriptSource, redeemer: RedeemerValue) -> None:
        """A withdrawal of 0 from the script's reward account (approval by a stake script)."""
        self.withdrawals.append((source, _cbor(redeemer)))

    def reference(self, *utxos: UTxO) -> None:
        known = {utxo_ref(u) for u in self.reference_inputs}
        for utxo in utxos:
            if utxo_ref(utxo) not in known:
                self.reference_inputs.append(utxo)
                known.add(utxo_ref(utxo))

    def output(self, output: TransactionOutput) -> None:
        self.outputs.append(output)

    def require(self, *key_hashes: bytes) -> None:
        for key_hash in key_hashes:
            if len(key_hash) != 28:
                raise ValueError("a required signer is a 28-byte key hash")
            if key_hash not in self.signers:
                self.signers.append(key_hash)


def _cbor(value: RedeemerValue) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if hasattr(value, "to_data"):
        return encode_data(value.to_data())
    data: PlutusData = value
    return encode_data(data)


def min_lovelace(ctx: IdentityContext, output: TransactionOutput) -> int:
    """The ledger minimum of ``output`` (protocol parameter ``coins_per_utxo_byte``)."""
    return min_lovelace_post_alonzo(output, ctx.ledger.context)


@dataclass(frozen=True)
class BuiltTx:
    """An unsigned transaction and every key hash that must sign it."""

    transaction: Transaction
    required_signers: tuple[str, ...]
    valid_from: int
    valid_to: int
    created_id: str | None = None

    @property
    def tx_id(self) -> str:
        return str(self.transaction.id)

    @property
    def cbor_hex(self) -> str:
        return self.transaction.to_cbor_hex()

    def sign(self, *signing_keys: SigningKey | ExtendedSigningKey) -> Transaction:
        """The transaction with a witness of each key (the caller's keys)."""
        return add_signatures(self.transaction, signing_keys)


def add_signatures(
    transaction: Transaction | str, signing_keys: Iterable[SigningKey | ExtendedSigningKey]
) -> Transaction:
    """Add a vkey witness of each key; existing witnesses of other keys stay."""
    tx = Transaction.from_cbor(transaction) if isinstance(transaction, str) else transaction
    tx = Transaction.from_cbor(tx.to_cbor())  # a copy
    body_hash = tx.transaction_body.hash()
    witnesses = {bytes(w.vkey.hash().payload): w for w in tx.transaction_witness_set.vkey_witnesses or []}
    for key in signing_keys:
        vkey = key.to_verification_key()
        if isinstance(key, ExtendedSigningKey):
            vkey = vkey.to_non_extended()
        witnesses[bytes(vkey.hash().payload)] = VerificationKeyWitness(vkey, key.sign(body_hash))
    tx.transaction_witness_set.vkey_witnesses = list(witnesses.values()) or None
    return tx


def build(
    ctx: IdentityContext,
    plan: TxPlan,
    funding_address: str | Address,
    *,
    change_address: str | Address | None = None,
) -> BuiltTx:
    """Balance ``plan`` with the funds of ``funding_address`` and return it unsigned."""
    funding = ctx.address_of(funding_address)
    change = ctx.address_of(change_address) if change_address is not None else funding
    builder = TransactionBuilder(ctx.ledger.context)
    builder.add_input_address(funding)
    for utxo in plan.inputs:
        builder.add_input(utxo)
    for spend in plan.spends:
        builder.add_script_input(
            spend.utxo,
            script=spend.source.argument,
            datum=spend.datum,
            redeemer=Redeemer(RawCBOR(spend.redeemer)),
        )
    if plan.mints:
        mint = MultiAsset()
        for source, assets, redeemer in plan.mints:
            policy = ScriptHash(source.script_hash)
            if policy not in mint:
                mint[policy] = Asset()
            for name, quantity in assets.items():
                mint[policy][AssetName(name)] = quantity
            builder.add_minting_script(source.argument, Redeemer(RawCBOR(redeemer)))
        builder.mint = mint
    if plan.withdrawals:
        rewards = {}
        for source, redeemer in plan.withdrawals:
            reward = Address(staking_part=ScriptHash(bytes(source.script_hash)), network=Network.MAINNET)
            rewards[reward.to_primitive()] = 0
            builder.add_withdrawal_script(source.argument, Redeemer(RawCBOR(redeemer)))
        builder.withdrawals = Withdrawals(rewards)
    for utxo in plan.reference_inputs:
        builder.reference_inputs.add(utxo)
    for output in plan.outputs:
        builder.add_output(output)
    builder.required_signers = [VerificationKeyHash(h) for h in sorted(plan.signers)] or None
    builder.validity_start = plan.window.lo_slot
    builder.ttl = plan.window.hi_slot
    try:
        body = builder.build(change_address=change)
    except Exception as exc:
        raise TransactionError(f"cannot build the transaction: {exc}") from exc
    witness_set = builder.build_witness_set(remove_dup_script=True)
    transaction = Transaction(body, witness_set)
    size = len(transaction.to_cbor())
    max_size = ctx.ledger.context.protocol_param.max_tx_size
    if size > max_size:
        raise TransactionError(
            f"the transaction has {size} bytes, more than the limit of {max_size}; "
            "configure the reference-script UTxOs (VECTOR_*_REF_UTXO)"
        )
    witnesses = {bytes(h.payload) for h in builder.required_signers or []}
    for utxo in list(builder.inputs) + list(builder.collaterals):
        payment = utxo.output.address.payment_part
        if isinstance(payment, VerificationKeyHash):
            witnesses.add(bytes(payment.payload))
    return BuiltTx(
        transaction=transaction,
        required_signers=tuple(sorted(h.hex() for h in witnesses)),
        valid_from=plan.window.lo,
        valid_to=plan.window.hi,
        created_id=plan.created_id.hex() if plan.created_id is not None else None,
    )
