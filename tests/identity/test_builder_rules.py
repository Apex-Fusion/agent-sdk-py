"""Builder rules that follow the contract rules of Part 2.

- A Module-1 withdrawal takes the whole current reward balance of Script(M1) (§3.8).
- Every spend of a record with a Module-1 party reads the configuration record (§3.8).
- A live record output holds max(10 AP3X, the ledger minimum of the output) (§3.2, §3.5).
- A vault escrow output holds exactly payment + both bonds; a top-up goes into the buyer bond (§5.3).
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


#: A script stake credential and the reward address that Koios lists for it (CIP-19 header 0xf1: script, network 1).
REWARD_SCRIPT = bytes.fromhex("a38f97f3d0228eae7df6785986d377e34034d43c2aa46aa9609aef89")
REWARD_ADDRESS = "stake17x3cl9ln6q3gatna7eu9npknwl35qdx58s42g64fvzdwlzg3fnwlc"


def reward_ledger(
    monkeypatch: pytest.MonkeyPatch, summaries: list[dict], accounts: list[dict] | None = None
) -> tuple[OgmiosKoiosLedger, list[httpx.Request]]:
    """A ledger whose Ogmios answers ``summaries`` and whose Koios answers ``accounts``; it keeps the requests."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "k.example.org":
            return httpx.Response(200, json=accounts)
        body = json.loads(request.content)
        assert body["method"] == "queryLedgerState/rewardAccountSummaries"
        assert body["params"] == {"scripts": [REWARD_SCRIPT.hex()]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": summaries})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr("vector_agent.identity.chain.httpx.post", client.post)
    ledger = OgmiosKoiosLedger(
        ogmios_url="https://ogmios.example.org",
        koios_url="https://k.example.org",
        koios_token="t0ken",
        context=object(),
    )
    return ledger, requests


def test_reward_balance_from_the_ogmios_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    summary = {"from": "script", "credential": REWARD_SCRIPT.hex(), "rewards": {"ada": {"lovelace": 42}}}
    ledger, requests = reward_ledger(monkeypatch, [summary])
    assert ledger.reward_balance(REWARD_SCRIPT) == 42
    assert [r.url.host for r in requests] == ["ogmios.example.org"]


def test_reward_balance_from_koios_without_an_ogmios_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ogmios gives no summary for a registered credential that is not delegated.
    account = {
        "stake_address": REWARD_ADDRESS,
        "status": "registered",
        "delegated_pool": None,
        "rewards_available": "1500000",
    }
    ledger, requests = reward_ledger(monkeypatch, [], [account])
    assert ledger.reward_balance(REWARD_SCRIPT) == 1_500_000
    koios = requests[1]
    assert str(koios.url) == "https://k.example.org/api/v1/account_info"
    assert json.loads(koios.content) == {"_stake_addresses": [REWARD_ADDRESS]}
    assert koios.headers["Authorization"] == "Bearer t0ken"


@pytest.mark.parametrize(
    "accounts",
    [[{"stake_address": REWARD_ADDRESS, "status": "not registered", "rewards_available": "7"}], []],
    ids=["not-registered", "unknown"],
)
def test_reward_balance_is_none_without_a_registration(monkeypatch: pytest.MonkeyPatch, accounts: list[dict]) -> None:
    ledger, requests = reward_ledger(monkeypatch, [], accounts)
    assert ledger.reward_balance(REWARD_SCRIPT) is None
    assert [r.url.host for r in requests] == ["ogmios.example.org", "k.example.org"]
