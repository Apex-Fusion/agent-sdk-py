"""Delegation client (Part 2 §5.1–§5.2): delegate and undelegate.

A delegation names a delegate agent and one of its Ed25519 keys with the
delegation purpose. The SDK refuses a ``delegate_key`` that another live
delegation uses (§5.2 "Fresh keys").
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from pycardano import Address, Asset, AssetName, MultiAsset, ScriptHash, TransactionOutput, Value
from pycardano.serialization import RawCBOR

from vector_agent.identity.constants import PURPOSE_DELEGATION
from vector_agent.identity.context import AuthenticOutput, IdentityContext
from vector_agent.identity.errors import IdentityLookupError, IdentityRuleError
from vector_agent.identity.ids import blake2b_224, vector_id_from_seed
from vector_agent.identity.rules import (
    Effective,
    active_key,
    covered,
    effective,
    narrower,
    validate_delegation,
)
from vector_agent.identity.tx import (
    DEFAULT_VALID_FOR_S,
    BuiltTx,
    TxPlan,
    Window,
    build,
    make_window,
    min_lovelace,
)
from vector_agent.identity.types import (
    AgentDelegator,
    Delegate,
    DelegationDatum,
    Delegator,
    IdentityDatum,
    OutputReference,
    PrincipalKey,
    Undelegate,
    ValueLimit,
)

__all__ = ["Delegations", "escrow_resource"]


def escrow_resource(escrow_hash: bytes) -> bytes:
    """``script:<escrow_hash>`` in lowercase hex: the resource of vault payments (§5.1)."""
    return b"script:" + escrow_hash.hex().encode()


def _pattern(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _bytes(value: str | bytes, size: int, name: str) -> bytes:
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != size:
        raise IdentityRuleError(f"{name}: expected {size} bytes")
    return raw


class Delegations:
    """Builders for the delegation contract, and delegation reads."""

    def __init__(self, ctx: IdentityContext) -> None:
        self.ctx = ctx

    def get(self, delegation_id: str | bytes) -> AuthenticOutput[DelegationDatum]:
        return self.ctx.delegation(delegation_id)

    def _active_record(
        self, plan: TxPlan, agent_id: bytes, window: Window, what: str
    ) -> AuthenticOutput[IdentityDatum]:
        """The record of ``agent_id`` and its ancestors as reference inputs; Active over the window."""
        rec = self.ctx.record(agent_id)
        ancestors = self.ctx.ancestors(rec.datum)
        plan.reference(rec.utxo, *(a.utxo for a in ancestors))
        find = {a.id: a.datum for a in ancestors}.get
        if effective(rec.datum, find, window.lo, window.hi) != Effective.ACTIVE:
            raise IdentityRuleError(f"the {what}'s effective status must be Active")
        return rec

    def _agent_signs(self, plan: TxPlan, record: IdentityDatum, key_hash: bytes | None, what: str) -> None:
        """The agent's controller (default) or a listed key with the delegation purpose signs."""
        if key_hash is None:
            plan.require(blake2b_224(record.controller))
        elif key_hash == blake2b_224(record.controller) or active_key(record, key_hash, PURPOSE_DELEGATION):
            plan.require(key_hash)
        else:
            raise IdentityRuleError(f"the {what} key is neither the controller nor a listed delegation key")

    def delegate(
        self,
        funding_address: str | Address,
        *,
        delegator: Delegator,
        delegate: str | bytes,
        delegate_key: str | bytes,
        actions: Sequence[str | bytes],
        not_after: int,
        resources: Sequence[str | bytes] = (),
        not_before: int | None = None,
        remaining: int = 0,
        purpose: bytes | None = None,
        value: ValueLimit | None = None,
        parent: str | bytes | None = None,
        delegator_key_hash: bytes | None = None,
        seed: OutputReference | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Create a delegation; the new token name is ``BuiltTx.created_id``.

        ``delegate_key`` is the key hash of the delegate's Ed25519 key with the
        delegation purpose; it signs. ``not_before`` defaults to the lower bound
        of the validity range. Without ``parent``: a ``PrincipalKey`` signs, or
        the ``AgentDelegator``'s controller (or the listed delegation key
        ``delegator_key_hash``). With ``parent``: the parent's delegate key signs.
        """
        ctx = self.ctx
        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        delegate_id = _bytes(delegate, 32, "delegate")
        key = _bytes(delegate_key, 28, "delegate_key")

        delegate_rec = self._active_record(plan, delegate_id, window, "delegate")
        if not active_key(delegate_rec.datum, key, PURPOSE_DELEGATION):
            raise IdentityRuleError("the delegate record does not list delegate_key with the delegation purpose")
        plan.require(key)
        for live in ctx.delegations():
            if live.datum.delegate_key == key:
                raise IdentityRuleError(f"delegate_key is in use by the live delegation {live.id.hex()}")

        datum = DelegationDatum(
            delegator=delegator,
            parent=None,
            delegate=delegate_id,
            delegate_key=key,
            actions=tuple(_pattern(a) for a in actions),
            resources=tuple(_pattern(r) for r in resources),
            not_before=window.lo if not_before is None else not_before,
            not_after=not_after,
            depth=1,
            remaining=remaining,
            purpose=purpose,
            value=value,
        )
        if parent is None:
            if isinstance(delegator, PrincipalKey):
                plan.require(delegator.hash)
            else:
                record = self._active_record(plan, delegator.id, window, "delegator")
                self._agent_signs(plan, record.datum, delegator_key_hash, "delegator")
        else:
            parent_out = ctx.delegation(parent)
            p = parent_out.datum
            if not isinstance(delegator, AgentDelegator) or delegator.id != p.delegate:
                raise IdentityRuleError("a sub-delegation's delegator is the parent's delegate agent")
            if p.remaining < 1:
                raise IdentityRuleError("the parent allows no further delegation (remaining is 0)")
            record = self._active_record(plan, delegator.id, window, "delegator")
            if not active_key(record.datum, p.delegate_key, PURPOSE_DELEGATION):
                raise IdentityRuleError("the parent's delegate key is no longer a delegation key of its agent")
            plan.reference(parent_out.utxo)
            plan.require(p.delegate_key)
            datum = replace(datum, parent=parent_out.id, depth=p.depth + 1)
            if not narrower(datum.actions, p.actions) or not narrower(datum.resources, p.resources):
                raise IdentityRuleError("the actions and resources must be inside the parent's")
            if not (p.not_before <= datum.not_before and datum.not_after <= p.not_after):
                raise IdentityRuleError("the period must be inside the parent's period")
            if datum.remaining > p.remaining - 1:
                raise IdentityRuleError("remaining must be below the parent's remaining")
            if p.value is not None and (
                datum.value is None
                or datum.value.per_tx > p.value.per_tx
                or datum.value.total > p.value.total
                or datum.value.period_ms < p.value.period_ms
            ):
                raise IdentityRuleError("the value limit must be inside the parent's value limit")
        validate_delegation(datum)

        if seed is None:
            utxos = ctx.ledger.context.utxos(ctx.address_of(funding_address))
            if not utxos:
                raise IdentityLookupError("the funding address has no output to use as a seed")
            seed_utxo = min(utxos, key=lambda u: (str(u.input.transaction_id), u.input.index))
        else:
            seed_utxo = ctx.ledger.utxo(seed)
            if seed_utxo is None:
                raise IdentityLookupError(f"the seed {seed} is spent or unknown")
        plan.add_input(seed_utxo)
        seed_ref = OutputReference(bytes(seed_utxo.input.transaction_id.payload), seed_utxo.input.index)
        delegation_id = bytes.fromhex(vector_id_from_seed(seed_ref.tx_id, seed_ref.index))
        plan.created_id = delegation_id

        script = ctx.scripts.delegation
        plan.mint(ctx.script_source("delegation"), {delegation_id: 1}, Delegate(seed_ref))
        bundle = MultiAsset({ScriptHash(script.hash): Asset({AssetName(delegation_id): 1})})
        output = TransactionOutput(script.address, Value(0, bundle), datum=RawCBOR(datum.to_cbor()))
        output.amount = Value(min_lovelace(ctx, output), bundle)
        plan.output(output)
        return build(ctx, plan, funding_address)

    def undelegate(
        self,
        funding_address: str | Address,
        delegation_id: str | bytes,
        *,
        level: int = 0,
        signer_key_hash: bytes | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Burn a delegation. Its delegator signs (``level=0``), or the delegator of
        the ancestor ``level`` links up (the ancestors are reference inputs).

        For an agent delegator, the controller signs, or the listed delegation
        key ``signer_key_hash``.
        """
        ctx = self.ctx
        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        leaf = ctx.delegation(delegation_id)
        current = leaf.datum
        for _ in range(level):
            if current.parent is None:
                raise IdentityRuleError(f"the delegation has fewer than {level} ancestors")
            ancestor = ctx.delegation(current.parent)
            plan.reference(ancestor.utxo)
            current = ancestor.datum
        delegator = current.delegator
        if isinstance(delegator, PrincipalKey):
            plan.require(delegator.hash)
        else:
            record = ctx.record(delegator.id)
            plan.reference(record.utxo)
            self._agent_signs(plan, record.datum, signer_key_hash, "delegator")
        source = ctx.script_source("delegation")
        plan.spend(leaf.utxo, source, Undelegate())
        plan.mint(source, {leaf.id: -1}, Undelegate())
        return build(ctx, plan, funding_address)

    def check_use(
        self, delegation_id: str | bytes, action: str | bytes, resource: str | bytes, window: Window
    ) -> tuple[AuthenticOutput[DelegationDatum], list]:
        """The §5.2 use checks; returns the delegation and every output to reference.

        Raises ``ValueError`` with the failed check.
        """
        ctx = self.ctx
        leaf = ctx.delegation(delegation_id)
        d = leaf.datum
        refs: list = [leaf.utxo]
        if not covered(d.actions, _pattern(action)):
            raise IdentityRuleError("the delegation does not cover the action")
        if not covered(d.resources, _pattern(resource)):
            raise IdentityRuleError("the delegation does not cover the resource")
        if not (d.not_before <= window.lo and window.hi <= d.not_after):
            raise IdentityRuleError("the validity range is outside the delegation's period")
        current = d
        for _ in range(4):
            delegate_rec = ctx.record(current.delegate)
            ancestors = ctx.ancestors(delegate_rec.datum)
            refs += [delegate_rec.utxo, *(a.utxo for a in ancestors)]
            find = {a.id: a.datum for a in ancestors}.get
            if effective(delegate_rec.datum, find, window.lo, window.hi) != Effective.ACTIVE:
                raise IdentityRuleError(f"the delegate {current.delegate.hex()} is not Active")
            if not active_key(delegate_rec.datum, current.delegate_key, PURPOSE_DELEGATION):
                raise IdentityRuleError(f"the delegate key of {current.delegate.hex()} is no longer listed")
            if current.parent is None:
                if isinstance(current.delegator, AgentDelegator):
                    root = ctx.record(current.delegator.id)
                    root_ancestors = ctx.ancestors(root.datum)
                    refs += [root.utxo, *(a.utxo for a in root_ancestors)]
                    find = {a.id: a.datum for a in root_ancestors}.get
                    if effective(root.datum, find, window.lo, window.hi) != Effective.ACTIVE:
                        raise IdentityRuleError("the root delegator agent is not Active")
                return leaf, refs
            parent = ctx.delegation(current.parent)
            refs.append(parent.utxo)
            current = parent.datum
        raise IdentityRuleError("the delegation chain is longer than 4 links")
