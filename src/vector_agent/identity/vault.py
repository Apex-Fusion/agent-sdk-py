"""Vault client (Part 2 §5.3): open, pay and close.

A vault holds AP3X of an owner (a principal key or an agent) for one
delegation. ``pay`` lets the delegation's delegate post new escrows (§6.1)
from the vault, within the delegation's value limit; escrow refunds return
to the vault as ``Returned`` outputs, which only the owner can close.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

import httpx
from pycardano import Address, TransactionOutput, UTxO
from pycardano.serialization import RawCBOR

from vector_agent.exceptions import ConnectionError as VectorConnectionError
from vector_agent.identity.constants import (
    DAYS_7_MS,
    HIRE_ACTION,
    MAX_ESCROW_LOVELACE,
    PURPOSE_TRANSACTION,
)
from vector_agent.identity.context import IdentityContext, datum_bytes
from vector_agent.identity.delegation import Delegations, escrow_resource
from vector_agent.identity.errors import IdentityLookupError, IdentityRuleError
from vector_agent.identity.ids import blake2b_224
from vector_agent.identity.plutus_data import decode_data
from vector_agent.identity.rules import (
    Effective,
    active_key,
    covered,
    effective,
    has_capability,
    independent,
)
from vector_agent.identity.tx import (
    BACKPAD_MS,
    DEFAULT_VALID_FOR_S,
    BuiltTx,
    TxPlan,
    build,
    make_window,
    min_lovelace,
)
from vector_agent.identity.types import (
    AdvertDatum,
    AdvertStatus,
    AgentDelegator,
    Delegator,
    EscrowDatum,
    EscrowState,
    OutputReference,
    PlutusAddress,
    PrincipalKey,
    Refund,
    ScriptCredential,
    VaultDatum,
    VaultLive,
    VaultReturned,
    VaultSpend,
    vault_datum_from_data,
)

__all__ = ["NETWORK_BUFFER_MS", "VaultJob", "Vaults", "request_spec_hash"]

#: ``deliver_by = posted_at + max_processing_ms + NETWORK_BUFFER_MS`` (as the marketplace Post builders).
NETWORK_BUFFER_MS = 30_000


def request_spec_hash(advert: AdvertDatum) -> bytes:
    """SHA-256 of the JCS (RFC 8785) object ``{capability_id, max_output_tokens, model}``."""
    spec = {
        "capability_id": advert.capability_id.decode("utf-8"),
        "max_output_tokens": advert.max_output_tokens,
        "model": advert.model.decode("utf-8"),
    }
    text = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).digest()


@dataclass(frozen=True)
class VaultJob:
    """One escrow that a vault payment posts: the advert to hire and the prompt commitment."""

    advert_ref: OutputReference
    prompt_hash: bytes


AdvertListed = Callable[[OutputReference, AdvertDatum], bool]


class Vaults:
    """Builders for the vault contract, and vault reads."""

    def __init__(self, ctx: IdentityContext, *, advert_listed: AdvertListed | None = None) -> None:
        self.ctx = ctx
        self._advert_listed = advert_listed

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(self, vault_ref: OutputReference) -> tuple[UTxO, VaultDatum]:
        utxo = self.ctx.ledger.utxo(vault_ref)
        if utxo is None or utxo.output.address != self.ctx.scripts.vault.address:
            raise IdentityLookupError(f"no vault output {vault_ref}")
        raw = datum_bytes(utxo)
        if raw is None:
            raise IdentityLookupError(f"the vault output {vault_ref} has no inline datum")
        return utxo, vault_datum_from_data(decode_data(raw))

    def list(self, owner: Delegator | None = None) -> list[tuple[UTxO, VaultDatum]]:
        """The vault outputs, all or those of ``owner``."""
        out = []
        for utxo in self.ctx.ledger.utxos_at(str(self.ctx.scripts.vault.address)):
            raw = datum_bytes(utxo)
            if raw is None:
                continue
            try:
                datum = vault_datum_from_data(decode_data(raw))
            except ValueError:
                continue
            if owner is None or datum.owner == owner:
                out.append((utxo, datum))
        return out

    # ------------------------------------------------------------------
    # Open
    # ------------------------------------------------------------------

    def open(
        self,
        funding_address: str | Address,
        *,
        owner: Delegator,
        delegation_id: str | bytes,
        amount: int,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Lock ``amount`` base units for the delegation ``delegation_id`` of ``owner``.

        The delegation must name ``owner`` as delegator, have a value limit, and
        cover the action ``marketplace.hire.v1`` and the escrow resource;
        else no payment could ever pass.
        """
        ctx = self.ctx
        delegation = ctx.delegation(delegation_id)
        d = delegation.datum
        if d.delegator != owner:
            raise IdentityRuleError("the delegation's delegator is not the vault owner")
        if d.value is None:
            raise IdentityRuleError("a vault needs a delegation with a value limit")
        resource = escrow_resource(ctx.scripts.escrow.hash)
        if not covered(d.actions, HIRE_ACTION.encode()) or not covered(d.resources, resource):
            raise IdentityRuleError(f"the delegation must cover {HIRE_ACTION} and {resource.decode()}")
        plan = TxPlan(make_window(ctx, valid_for=valid_for))
        datum = VaultLive(owner, delegation.id, 0, 0)
        output = TransactionOutput(ctx.scripts.vault.address, amount, datum=RawCBOR(datum.to_cbor()))
        if amount < min_lovelace(ctx, output):
            raise IdentityRuleError("the vault amount is below the ledger minimum")
        plan.output(output)
        return build(ctx, plan, funding_address)

    # ------------------------------------------------------------------
    # Pay
    # ------------------------------------------------------------------

    def _listed_by_indexer(self, advert_ref: OutputReference, advert: AdvertDatum) -> bool:
        base = self.ctx.config.indexer_url
        if not base:
            raise IdentityRuleError("the listing rule (Part 2 §6.2) needs the creating transaction's signers: "
            "set VECTOR_MARKETPLACE_INDEXER_URL or pass advert_listed to Vaults")
        try:
            response = httpx.get(f"{base}/suppliers/{advert.supplier_pkh.hex()}", timeout=15.0)
        except httpx.HTTPError as exc:
            raise VectorConnectionError(f"indexer request failed: {exc}") from exc
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
            rows = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise VectorConnectionError(f"indexer answer is not usable: {exc}") from exc
        rows = rows if isinstance(rows, list) else [rows]
        return any(
            str(row.get("utxo_ref", "")).lower() == str(advert_ref) and row.get("agent_id") == advert.agent_id.hex()
            for row in rows
            if isinstance(row, dict)
        )

    def _advert(self, ref: OutputReference, lo: int, hi: int) -> tuple[UTxO, AdvertDatum]:
        """A listed new advert (Part 2 §6.2) with its agent able to work."""
        ctx = self.ctx
        utxo = ctx.ledger.utxo(ref)
        if utxo is None or utxo.output.address != ctx.scripts.advert.address:
            raise IdentityRuleError(f"no new advert at {ref}")
        raw = datum_bytes(utxo)
        if raw is None:
            raise IdentityRuleError(f"the advert {ref} has no inline datum")
        advert = AdvertDatum.from_cbor(raw)
        if advert.status != AdvertStatus.ACTIVE:
            raise IdentityRuleError(f"the advert {ref} is retired")
        record = ctx.record(advert.agent_id)
        if not independent(record.datum):
            raise IdentityRuleError("the advert's agent is a subagent")
        if effective(record.datum, lambda _: None, lo, hi) != Effective.ACTIVE:
            raise IdentityRuleError("the advert's agent is not Active")
        if not active_key(record.datum, advert.supplier_pkh, PURPOSE_TRANSACTION):
            raise IdentityRuleError("the agent record does not list the supplier key with the transaction purpose")
        if not has_capability(record.datum, advert.capability_id):
            raise IdentityRuleError("the agent record does not list the advert's capability")
        listed = self._advert_listed or self._listed_by_indexer
        if not listed(ref, advert):
            raise IdentityRuleError(f"the advert {ref} is not listed (Part 2 §6.2)")
        return utxo, advert

    def pay(
        self,
        funding_address: str | Address,
        vault_ref: OutputReference,
        jobs: Sequence[VaultJob],
        *,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Post one new escrow per job from the vault (the delegate key signs).

        Each escrow copies the advert (supplier, capability, price, bonds,
        ``agent_id``), names the delegate key as buyer and the vault as refund
        address. The funding address pays only the fee.
        """
        ctx = self.ctx
        if not jobs:
            raise IdentityRuleError("a payment posts at least one escrow")
        utxo, vault = self.get(vault_ref)
        if not isinstance(vault, VaultLive):
            raise IdentityRuleError("only a Live vault output pays")
        amount_in = utxo.output.amount
        if not isinstance(amount_in, int) and amount_in.multi_asset:
            raise IdentityRuleError("a paying vault holds AP3X only")
        vault_lovelace = amount_in if isinstance(amount_in, int) else amount_in.coin
        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        scripts = ctx.scripts
        leaf, refs = Delegations(ctx).check_use(
            vault.delegation, HIRE_ACTION, escrow_resource(scripts.escrow.hash), window
        )
        d = leaf.datum
        if d.delegator != vault.owner:
            raise IdentityRuleError("the delegation's delegator is not the vault owner")
        if d.value is None:
            raise IdentityRuleError("the delegation has no value limit")
        plan.reference(*refs)
        plan.require(d.delegate_key)

        refund = Refund(
            PlutusAddress(ScriptCredential(scripts.vault.hash)), VaultReturned(vault.owner).to_data()
        )
        posted_at = window.lo + BACKPAD_MS
        total = 0
        for job in jobs:
            _, advert = self._advert(job.advert_ref, window.lo, window.hi)
            if len(job.prompt_hash) != 32:
                raise IdentityRuleError("prompt_hash is a 32-byte hash")
            job_total = advert.price_lovelace + advert.buyer_bond_lovelace + advert.supplier_bond_lovelace
            deliver_by = posted_at + advert.max_processing_ms + NETWORK_BUFFER_MS
            if deliver_by > window.hi + DAYS_7_MS:
                raise IdentityRuleError("deliver_by must be at most 7 days after hi")
            escrow = EscrowDatum(
                buyer_pkh=d.delegate_key,
                supplier_pkh=advert.supplier_pkh,
                advert_ref=job.advert_ref,
                capability_id=advert.capability_id,
                request_spec_hash=request_spec_hash(advert),
                prompt_hash=bytes(job.prompt_hash),
                payment_lovelace=advert.price_lovelace,
                buyer_bond_lovelace=advert.buyer_bond_lovelace,
                supplier_bond_lovelace=advert.supplier_bond_lovelace,
                deliver_by=deliver_by,
                posted_at=posted_at,
                submitted_at=None,
                result_receipt_hash=None,
                state=EscrowState.OPEN,
                agent_id=advert.agent_id,
                refund=refund,
            )
            # The escrow output's AP3X must equal payment + both bonds; a ledger-minimum top-up
            # goes into the buyer bond, which returns to the buyer (contract fix W4-CFIX).
            for _ in range(3):
                output = TransactionOutput(scripts.escrow.address, job_total, datum=RawCBOR(escrow.to_cbor()))
                top_up = min_lovelace(ctx, output) - job_total
                if top_up <= 0:
                    break
                escrow = replace(escrow, buyer_bond_lovelace=escrow.buyer_bond_lovelace + top_up)
                job_total += top_up
            else:
                raise IdentityRuleError("cannot size the escrow output to the ledger minimum")
            if job_total > MAX_ESCROW_LOVELACE:
                raise IdentityRuleError("payment + bonds exceed 10,000 AP3X (F-29)")
            total += job_total
            plan.output(output)

        limit = d.value
        if total > limit.per_tx:
            raise IdentityRuleError(f"the payment of {total} exceeds per_tx {limit.per_tx}")
        if window.lo >= vault.period_start + limit.period_ms:
            spent, period_start = total, window.hi
        else:
            spent, period_start = vault.spent + total, vault.period_start
        if spent > limit.total:
            raise IdentityRuleError(f"the period total {spent} would exceed {limit.total}")
        rest = VaultLive(vault.owner, vault.delegation, spent, period_start)
        continuing = TransactionOutput(scripts.vault.address, vault_lovelace - total, datum=RawCBOR(rest.to_cbor()))
        if vault_lovelace - total < min_lovelace(ctx, continuing):
            raise IdentityRuleError("the vault would fall below the ledger minimum; it cannot pay this much")
        plan.output(continuing)
        plan.spend(utxo, ctx.script_source("vault"), VaultSpend.PAY)
        return build(ctx, plan, funding_address)

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(
        self,
        funding_address: str | Address,
        vault_refs: Sequence[OutputReference],
        *,
        to_address: str | Address | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Close ``Live`` or ``Returned`` vault outputs of one owner; the funds go to
        ``to_address`` (default: the funding address)."""
        ctx = self.ctx
        if not vault_refs:
            raise IdentityRuleError("give at least one vault output")
        plan = TxPlan(make_window(ctx, valid_for=valid_for))
        owner = None
        source = ctx.script_source("vault")
        for ref in vault_refs:
            utxo, datum = self.get(ref)
            if owner is None:
                owner = datum.owner
            elif datum.owner != owner:
                raise IdentityRuleError("close vault outputs of one owner at a time")
            plan.spend(utxo, source, VaultSpend.CLOSE)
        if isinstance(owner, PrincipalKey):
            plan.require(owner.hash)
        elif isinstance(owner, AgentDelegator):
            record = ctx.record(owner.id)
            plan.reference(record.utxo)
            plan.require(blake2b_224(record.datum.controller))
        return build(ctx, plan, funding_address, change_address=to_address)
