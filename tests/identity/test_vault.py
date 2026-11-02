"""Vault builders (Part 2 §5.3) and the escrows that a payment posts (§6.1)."""

from __future__ import annotations

import hashlib

import httpx
import pytest
from pycardano import Address, TransactionOutput
from pycardano.serialization import RawCBOR

from vector_agent.identity import (
    Delegations,
    IdentityRegistry,
    IdentityRuleError,
    OutputReference,
    PrincipalKey,
    ValueLimit,
    VaultJob,
    VaultLive,
    VaultReturned,
    Vaults,
    escrow_resource,
)
from vector_agent.identity.constants import DAY_MS, HIRE_ACTION
from vector_agent.identity.types import AdvertDatum, AdvertStatus, EscrowDatum, EscrowState, ScriptCredential
from vector_agent.identity.vault import request_spec_hash

from .conftest import Agent, register_agent, scripts_pass
from .world import World, key_hash, signing_key, utxo_ref

PRINCIPAL = signing_key("vault-principal")
OWNER = PrincipalKey(key_hash(PRINCIPAL))
PROMPT = hashlib.sha256(b"the prompt").digest()


def h(key) -> str:
    return key_hash(key).hex()


def delegation(world: World, payer: Address, agent: Agent, limit: ValueLimit) -> str:
    built = Delegations(world.ctx).delegate(
        payer,
        delegator=OWNER,
        delegate=agent.id,
        delegate_key=key_hash(agent.delegation_key),
        actions=[HIRE_ACTION],
        resources=[escrow_resource(world.scripts.escrow.hash)],
        not_after=world.ctx.clock.posix_ms(world.tip) + 30 * DAY_MS,
        value=limit,
    )
    world.apply(built)
    return built.created_id


def advert(world: World, supplier: Agent, *, price: int = 5_000_000) -> OutputReference:
    datum = AdvertDatum(
        supplier_pkh=key_hash(supplier.transaction_key),
        capability_id=b"llm.chat",
        model=b"qwen3.5:0.5b",
        max_output_tokens=4096,
        max_processing_ms=60_000,
        price_lovelace=price,
        supplier_bond_lovelace=1_000_000,
        buyer_bond_lovelace=1_000_000,
        endpoint_url=b"https://supplier.example.org/v1",
        detail_uri=b"ipfs://detail",
        detail_hash=bytes(32),
        advertised_at=world.ctx.clock.posix_ms(world.tip),
        status=AdvertStatus.ACTIVE,
        agent_id=bytes.fromhex(supplier.id),
    )
    utxo = world.put(TransactionOutput(world.scripts.advert.address, 3_000_000, datum=RawCBOR(datum.to_cbor())))
    return utxo_ref(utxo)


def open_vault(world: World, payer: Address, delegation_id: str, amount: int = 120_000_000) -> OutputReference:
    built = Vaults(world.ctx).open(payer, owner=OWNER, delegation_id=delegation_id, amount=amount)
    scripts_pass(world, built)
    created = world.apply(built)
    vault = next(u for u in created if u.output.address == world.scripts.vault.address)
    return utxo_ref(vault)


def test_open_pay_and_close(world: World, payer: Address, agent: Agent) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(30_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    _, datum = Vaults(world.ctx).get(vault_ref)
    assert datum == VaultLive(OWNER, bytes.fromhex(delegation_id), 0, 0)

    advert_ref = advert(world, supplier)
    vaults = Vaults(world.ctx, advert_listed=lambda ref, ad: ref == advert_ref)
    pay = vaults.pay(payer, vault_ref, [VaultJob(advert_ref, PROMPT)])
    scripts_pass(world, pay)
    assert h(agent.delegation_key) in pay.required_signers
    outputs = pay.transaction.transaction_body.outputs
    escrows = [o for o in outputs if o.address == world.scripts.escrow.address]
    assert len(escrows) == 1 and escrows[0].amount == 7_000_000
    escrow = EscrowDatum.from_cbor(escrows[0].datum.cbor)
    assert escrow.buyer_pkh == key_hash(agent.delegation_key) and escrow.state == EscrowState.OPEN
    assert escrow.agent_id == bytes.fromhex(supplier.id) and escrow.payment_lovelace == 5_000_000
    assert escrow.refund.address.payment == ScriptCredential(world.scripts.vault.hash)
    assert escrow.refund.datum == VaultReturned(OWNER).to_data()
    assert escrow.deliver_by == escrow.posted_at + 60_000 + 30_000
    created = world.apply(pay)
    continuing = next(u for u in created if u.output.address == world.scripts.vault.address)
    _, rest = Vaults(world.ctx).get(utxo_ref(continuing))
    assert rest.spent == 7_000_000 and rest.period_start == pay.valid_to
    assert continuing.output.amount == 113_000_000

    # An escrow refund arrives as a Returned output; the owner closes both.
    returned = world.put(
        TransactionOutput(world.scripts.vault.address, 7_000_000, datum=RawCBOR(VaultReturned(OWNER).to_cbor()))
    )
    close = Vaults(world.ctx).close(payer, [utxo_ref(continuing), utxo_ref(returned)])
    scripts_pass(world, close)
    assert h(PRINCIPAL) in close.required_signers


def test_pay_respects_the_value_limit(world: World, payer: Address, agent: Agent) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(6_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    advert_ref = advert(world, supplier)
    vaults = Vaults(world.ctx, advert_listed=lambda ref, ad: True)
    with pytest.raises(IdentityRuleError, match="per_tx"):
        vaults.pay(payer, vault_ref, [VaultJob(advert_ref, PROMPT)])


def test_pay_checks_the_listing_with_the_indexer(
    world: World, payer: Address, agent: Agent, monkeypatch: pytest.MonkeyPatch
) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(30_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    advert_ref = advert(world, supplier)
    world.ctx.config = world.ctx.config.with_values(indexer_url="https://indexer.example.org")
    seen = []

    def fake_get(url: str, timeout: float) -> httpx.Response:
        seen.append(url)
        rows = [{"utxo_ref": str(advert_ref), "agent_id": supplier.id}]
        return httpx.Response(200, json=rows, request=httpx.Request("GET", url))

    monkeypatch.setattr("vector_agent.identity.vault.httpx.get", fake_get)
    pay = Vaults(world.ctx).pay(payer, vault_ref, [VaultJob(advert_ref, PROMPT)])
    scripts_pass(world, pay)
    assert seen == [f"https://indexer.example.org/suppliers/{h(supplier.transaction_key)}"]

    def unlisted(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(404, json={"error": "supplier not found"}, request=httpx.Request("GET", url))

    monkeypatch.setattr("vector_agent.identity.vault.httpx.get", unlisted)
    with pytest.raises(IdentityRuleError, match="not listed"):
        Vaults(world.ctx).pay(payer, vault_ref, [VaultJob(advert_ref, PROMPT)])


def test_pay_needs_a_listing_check(world: World, payer: Address, agent: Agent) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(30_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    with pytest.raises(IdentityRuleError, match="VECTOR_MARKETPLACE_INDEXER_URL"):
        Vaults(world.ctx).pay(payer, vault_ref, [VaultJob(advert(world, supplier), PROMPT)])


def test_pay_refuses_an_advert_whose_agent_lacks_the_capability(world: World, payer: Address, agent: Agent) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(30_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    ref = advert(world, supplier)
    world.apply(IdentityRegistry(world.ctx).update(payer, supplier.id, capabilities=["ocr.extract"]))
    with pytest.raises(IdentityRuleError, match="capability"):
        Vaults(world.ctx, advert_listed=lambda r, a: True).pay(payer, vault_ref, [VaultJob(ref, PROMPT)])


def test_open_refuses_a_delegation_without_hire(world: World, payer: Address, agent: Agent) -> None:
    built = Delegations(world.ctx).delegate(
        payer,
        delegator=OWNER,
        delegate=agent.id,
        delegate_key=key_hash(agent.delegation_key),
        actions=["ocr.*"],
        not_after=world.ctx.clock.posix_ms(world.tip) + DAY_MS,
        value=ValueLimit(1, 1, DAY_MS),
    )
    world.apply(built)
    with pytest.raises(IdentityRuleError, match=HIRE_ACTION):
        Vaults(world.ctx).open(payer, owner=OWNER, delegation_id=built.created_id, amount=10_000_000)
    with pytest.raises(IdentityRuleError, match="vault owner"):
        Vaults(world.ctx).open(
            payer, owner=PrincipalKey(bytes(28)), delegation_id=built.created_id, amount=10_000_000
        )


def test_request_spec_hash_is_jcs_sha256() -> None:
    datum = AdvertDatum(
        supplier_pkh=bytes(28), capability_id=b"llm.chat", model=b"m", max_output_tokens=7,
        max_processing_ms=1, price_lovelace=1, supplier_bond_lovelace=0, buyer_bond_lovelace=0,
        endpoint_url=b"", detail_uri=b"", detail_hash=bytes(32), advertised_at=0,
        status=AdvertStatus.ACTIVE, agent_id=bytes(32),
    )
    expected = hashlib.sha256(b'{"capability_id":"llm.chat","max_output_tokens":7,"model":"m"}').digest()
    assert request_spec_hash(datum) == expected
