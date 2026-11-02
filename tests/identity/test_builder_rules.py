"""Builder rules of the composition review R5 and the contract fixes W4-CFIX.

- A Module-1 withdrawal takes the whole current reward balance of Script(M1).
- Every spend of a record with a Module-1 party reads the configuration record.
- A live record output holds max(10 AP3X, the ledger minimum of the output).
- A vault escrow output holds exactly payment + both bonds; a top-up goes into the buyer bond.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pycardano import Address, TransactionOutput

from vector_agent.identity import (
    IdentityLookupError,
    IdentityRegistry,
    KeyHashSigner,
    OgmiosKoiosLedger,
    PartySpec,
    Role,
    ScriptSigner,
    ValueLimit,
    VaultJob,
    Vaults,
    ed25519_key,
    p256_key,
)
from vector_agent.identity.constants import DAY_MS, MIN_RECORD_LOVELACE, PURPOSE_ASSERTION, PURPOSE_AUTHENTICATION
from vector_agent.identity.tx import min_lovelace
from vector_agent.identity.types import EscrowDatum

from .conftest import Agent, register_agent, scripts_pass
from .test_vault import PROMPT, advert, delegation, open_vault
from .world import World, key_hash, public_key, signing_key


def references(built) -> set[tuple[bytes, int]]:
    return {(bytes(r.transaction_id.payload), r.index) for r in built.transaction.transaction_body.reference_inputs}


def config_ref(world: World) -> tuple[bytes, int]:
    return (bytes(world.config_utxo.input.transaction_id.payload), world.config_utxo.input.index)


def module1_record(world: World, payer: Address) -> str:
    built = IdentityRegistry(world.ctx).register(
        payer,
        controller=public_key(signing_key("m1-controller")),
        name="Module-1 accountable",
        parties=[PartySpec(Role.ACCOUNTABLE, ScriptSigner(world.module1))],
    )
    scripts_pass(world, built)
    world.apply(built)
    return built.created_id


def test_module1_consent_withdraws_the_whole_reward_balance(world: World, payer: Address) -> None:
    world.rewards[world.module1] = 1_234_567
    built = IdentityRegistry(world.ctx).register(
        payer,
        controller=public_key(signing_key("m1-c")),
        name="Module-1 accountable",
        parties=[PartySpec(Role.ACCOUNTABLE, ScriptSigner(world.module1))],
    )
    scripts_pass(world, built)
    assert list(built.transaction.transaction_body.withdraws.values()) == [1_234_567]


def test_module1_consent_needs_a_registered_stake_credential(world: World, payer: Address) -> None:
    del world.rewards[world.module1]
    with pytest.raises(IdentityLookupError, match="not registered"):
        IdentityRegistry(world.ctx).register(
            payer,
            controller=public_key(signing_key("m1-c")),
            name="Module-1 accountable",
            parties=[PartySpec(Role.ACCOUNTABLE, ScriptSigner(world.module1))],
        )


def test_every_spend_of_a_module1_record_reads_the_configuration(world: World, payer: Address) -> None:
    vector_id = module1_record(world, payer)
    registry = IdentityRegistry(world.ctx)
    for built in (
        registry.suspend(payer, vector_id, reason=6, duration_ms=DAY_MS),
        registry.end_subagents(payer, vector_id),
        registry.retire(payer, vector_id),  # the tombstone has no party, but the spent record has one
    ):
        scripts_pass(world, built)
        assert config_ref(world) in references(built)
        assert not built.transaction.transaction_body.withdraws  # Module-1 approves nothing here


def test_a_large_record_holds_the_ledger_minimum(world: World, payer: Address) -> None:
    signers = [signing_key(f"big-{i}") for i in range(8)]
    keys = [ed25519_key(public_key(signers[0]), PURPOSE_AUTHENTICATION)] + [
        p256_key(bytes([2]) + bytes([i]) * 32, bytes(64), PURPOSE_ASSERTION) for i in range(1, 8)
    ]
    roles = [Role.ACCOUNTABLE, Role.RESPONSIBLE, Role.PROVIDER, Role.DISTRIBUTOR, Role.GUARDIAN]
    parties = [
        PartySpec(roles[i % 5], KeyHashSigner(key_hash(signers[i])), organisation="o" * 64) for i in range(8)
    ]
    registry = IdentityRegistry(world.ctx)
    built = registry.register(
        payer,
        controller=public_key(signing_key("big-controller")),
        name="n" * 64,
        description="d" * 256,
        framework="f" * 64,
        endpoint="https://" + "e" * 248,
        capabilities=[f"{i:02d}" + "c" * 62 for i in range(16)],
        keys=keys,
        parties=parties,
    )
    scripts_pass(world, built)
    world.apply(built)
    record = registry.record(built.created_id)
    floor = min_lovelace(world.ctx, record.utxo.output)
    assert record.lovelace == floor > MIN_RECORD_LOVELACE
    # A kept-value action raises the deposit to the new floor; an explicit deposit below it is refused.
    with pytest.raises(Exception, match="at least"):
        registry.update(payer, built.created_id, deposit=MIN_RECORD_LOVELACE)


def test_vault_tops_up_the_buyer_bond(world: World, payer: Address, agent: Agent) -> None:
    supplier = register_agent(world, payer, "supplier")
    delegation_id = delegation(world, payer, agent, ValueLimit(30_000_000, 60_000_000, DAY_MS))
    vault_ref = open_vault(world, payer, delegation_id)
    ref = advert(world, supplier, price=500_000, bonds=0)
    pay = Vaults(world.ctx, advert_listed=lambda r, a: True).pay(payer, vault_ref, [VaultJob(ref, PROMPT)])
    scripts_pass(world, pay)
    output = next(o for o in pay.transaction.transaction_body.outputs if o.address == world.scripts.escrow.address)
    escrow = EscrowDatum.from_cbor(output.datum.cbor)
    assert escrow.payment_lovelace == 500_000 and escrow.supplier_bond_lovelace == 0
    assert escrow.buyer_bond_lovelace > 0
    assert output.amount == escrow.payment_lovelace + escrow.buyer_bond_lovelace + escrow.supplier_bond_lovelace
    assert output.amount == min_lovelace(world.ctx, TransactionOutput(output.address, output.amount, datum=output.datum))


def test_ogmios_reward_balance(monkeypatch: pytest.MonkeyPatch) -> None:
    script = bytes([0xAB]) * 28

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "queryLedgerState/rewardAccountSummaries"
        assert body["params"] == {"scripts": [script.hex()]}
        entries = [{"from": "script", "credential": script.hex(), "rewards": {"ada": {"lovelace": 42}}}]
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": entries if body["id"] else []})

    transport = httpx.MockTransport(handler)

    def post(url, **kwargs):
        kwargs["json"] = {**kwargs["json"], "id": post.registered}
        return httpx.Client(transport=transport).post(url, **kwargs)

    monkeypatch.setattr("vector_agent.identity.chain.httpx.post", post)
    ledger = OgmiosKoiosLedger(ogmios_url="https://ogmios.example.org", koios_url="https://k.example.org", context=object())
    post.registered = 1
    assert ledger.reward_balance(script) == 42
    post.registered = 0
    assert ledger.reward_balance(script) is None
