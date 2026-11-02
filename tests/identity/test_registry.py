"""Identity registry builders (Part 2 §3).

Each build runs the real identity validator through ``aiken tx simulate``
when ``aiken`` is on PATH (see ``world.py``); ``scripts_pass`` also checks the
final transaction with its execution units.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    Network,
    ScriptHash,
    TransactionOutput,
    Value,
    VerificationKeyHash,
)
from pycardano.serialization import RawCBOR

from vector_agent.identity import (
    CONTROLLER_SET,
    IdentityDatum,
    IdentityLookupError,
    IdentityRegistry,
    IdentityRuleError,
    KeyHashSigner,
    PartySpec,
    Role,
    ScriptSigner,
    ed25519_key,
    vector_id_from_seed,
)
from vector_agent.identity.constants import (
    DAYS_7_MS,
    DAYS_30_MS,
    LEGACY_REGISTRY_ADDRESS,
    MIN_RECORD_LOVELACE,
    PURPOSE_AUTHENTICATION,
    REASON_HOLD,
    REASON_KEY_COMPROMISE,
    REASON_SECURITY_INVESTIGATION,
    REASON_SUPERSEDED,
)
from vector_agent.identity.ids import allowlist_proof, blake2b_224
from vector_agent.identity.types import (
    ACTIVE,
    Hold,
    KeyCredential,
    LegacyDatum,
    PendingRecovery,
    Retired,
    Revoked,
    Subagent,
    Suspended,
)

from .conftest import Agent, register_agent, scripts_pass
from .world import World, key_address, key_hash, public_key, signing_key


def h(key) -> str:
    return key_hash(key).hex()


def registry(world: World) -> IdentityRegistry:
    return IdentityRegistry(world.ctx)


def new_record(world: World, built) -> IdentityDatum:
    world.apply(built)
    return registry(world).record(built.created_id or "").datum


def record_after(world: World, built, vector_id: str) -> IdentityDatum:
    scripts_pass(world, built)
    world.apply(built)
    return registry(world).record(vector_id).datum


# ---------------------------------------------------------------------------
# Register and adopt (§3.4)
# ---------------------------------------------------------------------------


def test_register_root_record(world: World, payer: Address) -> None:
    controller, accountable, listed = signing_key("c"), signing_key("a"), signing_key("k")
    reg = registry(world)
    seed, expected_id = reg.next_identifier(payer)
    built = reg.register(
        payer,
        controller=public_key(controller),
        name="Root agent",
        keys=[ed25519_key(public_key(listed), PURPOSE_AUTHENTICATION)],
        parties=[PartySpec(Role.ACCOUNTABLE, KeyHashSigner(key_hash(accountable)))],
        capabilities=["llm.chat"],
    )
    scripts_pass(world, built)
    assert built.created_id == expected_id == vector_id_from_seed(seed.tx_id, seed.index)
    payer_hash = bytes(Address.from_primitive(str(payer)).payment_part.payload).hex()
    assert set(built.required_signers) == {h(controller), h(accountable), h(listed), payer_hash}
    body = built.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.identity.hash)][AssetName(bytes.fromhex(expected_id))] == 1
    assert built.valid_to - built.valid_from <= 3_600_000
    record = new_record(world, built)
    assert record.created_at == built.valid_to
    assert record.status == ACTIVE and record.subagent_epoch == 0 and record.pending_recovery is None
    assert record.parties[0].not_before == built.valid_from
    assert record.parties[0].rights == 3


def test_register_full_record(world: World, payer: Address) -> None:
    agent = register_agent(world, payer, "full")
    record = registry(world).record(agent.id).datum
    assert len(record.keys) == 3 and len(record.parties) == 4 and record.guardian_threshold == 2


def test_register_subagent(world: World, payer: Address, agent: Agent) -> None:
    sub_controller, sub_accountable = signing_key("sub-c"), signing_key("sub-a")
    built = registry(world).register(
        payer,
        controller=public_key(sub_controller),
        name="Sub agent",
        parties=[PartySpec(Role.ACCOUNTABLE, KeyHashSigner(key_hash(sub_accountable)))],
        parent=agent.id,
    )
    scripts_pass(world, built)
    assert h(agent.controller) in built.required_signers
    parent_ref = registry(world).record(agent.id).ref
    refs = {(bytes(r.transaction_id.payload), r.index) for r in built.transaction.transaction_body.reference_inputs}
    assert (parent_ref.tx_id, parent_ref.index) in refs
    record = new_record(world, built)
    assert record.lineage == Subagent(bytes.fromhex(agent.id), 0, 1)
    # A subagent of the subagent: depth 2, with both ancestors as reference inputs.
    deeper = registry(world).register(
        payer,
        controller=public_key(signing_key("sub2-c")),
        name="Sub sub agent",
        parties=[PartySpec(Role.ACCOUNTABLE, KeyHashSigner(key_hash(sub_accountable)))],
        parent=built.created_id,
    )
    scripts_pass(world, deeper)
    assert new_record(world, deeper).lineage.depth == 2


def test_register_subagent_refuses_an_endpoint(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="empty endpoint"):
        registry(world).register(
            payer,
            controller=public_key(signing_key("s")),
            name="Sub",
            endpoint="https://sub.example.org",
            parties=[PartySpec(Role.ACCOUNTABLE, CONTROLLER_SET)],
            parent=agent.id,
        )


def test_register_with_module1_consent(world: World, payer: Address) -> None:
    built = registry(world).register(
        payer,
        controller=public_key(signing_key("m1-c")),
        name="Module-1 accountable",
        parties=[PartySpec(Role.ACCOUNTABLE, ScriptSigner(world.module1))],
    )
    scripts_pass(world, built)
    body = built.transaction.transaction_body
    assert len(body.withdraws) == 1
    refs = {(bytes(r.transaction_id.payload), r.index) for r in body.reference_inputs}
    config = world.config_utxo.input
    assert (bytes(config.transaction_id.payload), config.index) in refs
    assert new_record(world, built).parties[0].signer == ScriptSigner(world.module1)


def test_register_refuses_without_accountable_party(world: World, payer: Address) -> None:
    with pytest.raises(IdentityRuleError, match="Accountable Party"):
        registry(world).register(
            payer,
            controller=public_key(signing_key("c")),
            name="No party",
            parties=[PartySpec(Role.RESPONSIBLE, CONTROLLER_SET)],
        )


def test_register_refuses_a_foreign_script_party(world: World, payer: Address) -> None:
    with pytest.raises(IdentityRuleError, match="Module-1"):
        registry(world).register(
            payer,
            controller=public_key(signing_key("c")),
            name="Wrong script",
            parties=[PartySpec(Role.ACCOUNTABLE, ScriptSigner(bytes(28)))],
        )


def test_register_refuses_guardian_threshold_above_guardians(world: World, payer: Address) -> None:
    with pytest.raises(IdentityRuleError, match="guardian_threshold"):
        registry(world).register(
            payer,
            controller=public_key(signing_key("c")),
            name="Threshold",
            parties=[PartySpec(Role.ACCOUNTABLE, CONTROLLER_SET)],
            guardian_threshold=1,
        )


def _legacy_world(owner) -> tuple[World, str]:
    seed_tx = bytes([0x4C]) * 32
    legacy_id = vector_id_from_seed(seed_tx, 0)
    allowlist = (legacy_id, bytes(32).hex(), (bytes([1]) * 32).hex())
    world = World(allowlist=allowlist)
    legacy = LegacyDatum(
        owner=KeyCredential(key_hash(owner)),
        name=b"Legacy agent",
        description=b"A record of the legacy registry.",
        capabilities=(b"document-extraction",),
        framework=b"custom",
        endpoint=b"https://legacy.example.org/agent",
        registered_at=1_756_000_000_000,
    )
    value = Value(
        10_000_000,
        MultiAsset({ScriptHash(world.scripts.legacy_hash): Asset({AssetName(bytes.fromhex(legacy_id)): 1})}),
    )
    world.put(
        TransactionOutput(Address.from_primitive(LEGACY_REGISTRY_ADDRESS), value, datum=RawCBOR(legacy.to_cbor()))
    )
    return world, legacy_id


def test_adopt_legacy_record() -> None:
    owner = signing_key("legacy-owner")
    world, legacy_id = _legacy_world(owner)
    payer = world.fund(signing_key("payer"), 300_000_000, count=2)
    accountable = signing_key("adopt-a")
    built = registry(world).adopt(
        payer,
        legacy_id,
        controller=public_key(owner),
        parties=[PartySpec(Role.ACCOUNTABLE, KeyHashSigner(key_hash(accountable)))],
        allowlist=world.allowlist,
    )
    scripts_pass(world, built)
    assert built.created_id == legacy_id
    assert {h(owner), h(accountable)} <= set(built.required_signers)
    body = built.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.legacy_hash)][AssetName(bytes.fromhex(legacy_id))] == -1
    owner_outputs = [o for o in body.outputs if o.address == key_address(owner) and o.amount.coin >= 10_000_000]
    assert owner_outputs
    record = new_record(world, built)
    assert record.name == b"Legacy agent" and record.capabilities == (b"document-extraction",)


def test_adopt_refuses_an_identifier_off_the_allowlist() -> None:
    owner = signing_key("legacy-owner")
    world, legacy_id = _legacy_world(owner)
    payer = world.fund(signing_key("payer"))
    other = vector_id_from_seed(bytes([9]) * 32, 1)
    with pytest.raises(IdentityRuleError, match="allowlist"):
        registry(world).adopt(
            payer,
            legacy_id,
            controller=public_key(owner),
            parties=[PartySpec(Role.ACCOUNTABLE, CONTROLLER_SET)],
            proof=allowlist_proof((other, bytes(32).hex()), other),
        )


def test_adopt_refuses_a_missing_legacy_record() -> None:
    owner = signing_key("legacy-owner")
    world, _ = _legacy_world(owner)
    payer = world.fund(signing_key("payer"))
    with pytest.raises(IdentityLookupError, match="legacy record"):
        registry(world).adopt(
            payer,
            bytes(32).hex(),
            controller=public_key(owner),
            parties=[PartySpec(Role.ACCOUNTABLE, CONTROLLER_SET)],
            allowlist=world.allowlist,
        )


# ---------------------------------------------------------------------------
# Update (§3.6) and controller actions
# ---------------------------------------------------------------------------


def test_update_profile_and_keys(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    new_key = signing_key("alpha-new-key")
    built = reg.update(
        payer,
        agent.id,
        description="Updated description.",
        capabilities=["llm.chat"],
        keys=[old.keys[0], ed25519_key(public_key(new_key), PURPOSE_AUTHENTICATION)],
    )
    assert {h(agent.controller), h(new_key)} <= set(built.required_signers)
    assert h(agent.accountable) not in built.required_signers
    record = record_after(world, built, agent.id)
    assert record.description == b"Updated description."
    assert record.capabilities == (b"llm.chat",) and len(record.keys) == 2
    assert record.created_at == old.created_at


def test_update_appoints_a_party_and_gives_notice(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    provider = signing_key("alpha-provider")
    hi_guess = world.ctx.clock.posix_ms(world.tip) + 900_000
    notice = replace(old.parties[1], removal_after=hi_guess + DAYS_7_MS + 60_000)
    built = reg.update(
        payer,
        agent.id,
        parties=[old.parties[0], notice, old.parties[2], old.parties[3], PartySpec(Role.PROVIDER, KeyHashSigner(key_hash(provider)))],
    )
    assert h(provider) in built.required_signers
    assert h(agent.responsible) not in built.required_signers  # a notice of at least 7 days needs no signature
    record = record_after(world, built, agent.id)
    assert record.parties[4].role == Role.PROVIDER
    assert record.parties[1].removal_after == notice.removal_after


def test_update_refuses_a_short_notice(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    short = replace(old.parties[1], removal_after=world.ctx.clock.posix_ms(world.tip) + DAYS_7_MS)
    with pytest.raises(IdentityRuleError, match="7 days"):
        reg.update(payer, agent.id, parties=[old.parties[0], short, *old.parties[2:]])


def test_update_removes_a_party_after_its_notice(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    hi_guess = world.ctx.clock.posix_ms(world.tip) + 900_000
    noticed = replace(old.parties[1], removal_after=hi_guess + DAYS_7_MS + 120_000)
    world.apply(reg.update(payer, agent.id, parties=[old.parties[0], noticed, *old.parties[2:]]))
    world.advance(8 * 86_400)
    current = reg.record(agent.id).datum
    built = reg.update(payer, agent.id, parties=[current.parties[0], *current.parties[2:]])
    assert h(agent.responsible) not in built.required_signers
    assert len(record_after(world, built, agent.id).parties) == 3


def test_update_removal_without_notice_needs_the_party(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    built = reg.update(payer, agent.id, parties=[old.parties[0], *old.parties[2:]])
    assert h(agent.responsible) in built.required_signers
    scripts_pass(world, built)


def test_update_lowers_the_threshold_and_clears_recovery(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    old = reg.record(agent.id).datum
    built = reg.update(payer, agent.id, parties=list(old.parties[:2]), guardian_threshold=0)
    assert {h(agent.guardians[0]), h(agent.guardians[1])} <= set(built.required_signers)
    record = record_after(world, built, agent.id)
    assert record.guardian_threshold == 0 and record.pending_recovery is None


def test_update_refuses_reordered_parties(world: World, payer: Address, agent: Agent) -> None:
    old = registry(world).record(agent.id).datum
    with pytest.raises(IdentityRuleError, match="order"):
        registry(world).update(payer, agent.id, parties=[old.parties[1], old.parties[0], *old.parties[2:]])


def test_change_controller(world: World, payer: Address, agent: Agent) -> None:
    new_controller = signing_key("alpha-controller-2")
    built = registry(world).change_controller(payer, agent.id, public_key(new_controller))
    assert {h(agent.controller), h(new_controller)} <= set(built.required_signers)
    record = record_after(world, built, agent.id)
    assert record.controller == public_key(new_controller) and record.subagent_epoch == 1


def test_end_subagents(world: World, payer: Address, agent: Agent) -> None:
    built = registry(world).end_subagents(payer, agent.id)
    assert record_after(world, built, agent.id).subagent_epoch == 1


# ---------------------------------------------------------------------------
# Holds (§3.5)
# ---------------------------------------------------------------------------


def test_suspend_by_controller_and_unsuspend(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    built = reg.suspend(payer, agent.id, reason=REASON_HOLD, duration_ms=86_400_000)
    assert h(agent.controller) in built.required_signers
    record = record_after(world, built, agent.id)
    assert record.status == Suspended((Hold(CONTROLLER_SET, REASON_HOLD, built.valid_from, built.valid_from + 86_400_000),))
    lifted = reg.unsuspend(payer, agent.id)
    assert record_after(world, lifted, agent.id).status == ACTIVE


def test_two_authors_keep_their_own_holds(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    world.apply(reg.suspend(payer, agent.id, reason=REASON_HOLD, duration_ms=86_400_000))
    by_party = reg.suspend(payer, agent.id, reason=REASON_SECURITY_INVESTIGATION, duration_ms=DAYS_30_MS - 1_000_000, by_party=1)
    assert h(agent.responsible) in by_party.required_signers
    holds = record_after(world, by_party, agent.id).status.holds
    assert [hold.by for hold in holds] == [CONTROLLER_SET, KeyHashSigner(key_hash(agent.responsible))]
    lifted = reg.unsuspend(payer, agent.id, author=KeyHashSigner(key_hash(agent.responsible)))
    assert h(agent.responsible) in lifted.required_signers
    assert [hold.by for hold in record_after(world, lifted, agent.id).status.holds] == [CONTROLLER_SET]


def test_suspend_refuses_the_dispute_verdict_reason(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="reason 64"):
        registry(world).suspend(payer, agent.id, reason=64, duration_ms=86_400_000)


def test_suspend_refuses_a_party_without_the_right(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="suspend right"):
        registry(world).suspend(payer, agent.id, reason=REASON_HOLD, duration_ms=86_400_000, by_party=2)


def test_suspend_refuses_a_hold_over_30_days(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="until"):
        registry(world).suspend(payer, agent.id, reason=REASON_HOLD, duration_ms=DAYS_30_MS + 1)


# ---------------------------------------------------------------------------
# Final actions (§3.5, §3.7)
# ---------------------------------------------------------------------------


def test_revoke_by_controller_with_successor(world: World, payer: Address, agent: Agent) -> None:
    successor = register_agent(world, payer, "beta")
    built = registry(world).revoke(payer, agent.id, reason=REASON_SUPERSEDED, successor=successor.id)
    assert {h(agent.controller), h(successor.controller)} <= set(built.required_signers)
    record = record_after(world, built, agent.id)
    assert isinstance(record.status, Revoked)
    assert record.status.by == CONTROLLER_SET and record.status.successor == bytes.fromhex(successor.id)
    assert record.keys == () and record.parties == () and record.description == b""


def test_revoke_by_party_for_key_compromise(world: World, payer: Address, agent: Agent) -> None:
    created = registry(world).record(agent.id).datum.created_at
    world.advance(3_600)  # created_at is the upper bound of the creating range: wait until lo passes it
    built = registry(world).revoke(
        payer, agent.id, reason=REASON_KEY_COMPROMISE, invalid_from=created, by_party=0
    )
    assert h(agent.accountable) in built.required_signers and h(agent.controller) not in built.required_signers
    status = record_after(world, built, agent.id).status
    assert status.by == KeyHashSigner(key_hash(agent.accountable)) and status.invalid_from == created


def test_revoke_rules(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    with pytest.raises(IdentityRuleError, match="invalid_from"):
        reg.revoke(payer, agent.id, reason=REASON_KEY_COMPROMISE)
    with pytest.raises(IdentityRuleError, match="only the controller"):
        reg.revoke(payer, agent.id, reason=0, by_party=0, successor=agent.id)
    with pytest.raises(IdentityRuleError, match="revoke right"):
        reg.revoke(payer, agent.id, reason=0, by_party=1)


def test_retire_set_successor_and_reclaim(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    retired = reg.retire(payer, agent.id)
    record = record_after(world, retired, agent.id)
    assert record.status == Retired(retired.valid_from, None)
    with pytest.raises(IdentityRuleError, match="tombstone"):
        reg.update(payer, agent.id, name="again")
    successor = register_agent(world, payer, "gamma")
    named = reg.set_successor(payer, agent.id, successor.id)
    assert h(successor.controller) in named.required_signers
    assert record_after(world, named, agent.id).status.successor == bytes.fromhex(successor.id)
    with pytest.raises(IdentityRuleError, match="already names"):
        reg.set_successor(payer, agent.id, successor.id)
    reclaim = reg.reclaim(payer, agent.id)
    scripts_pass(world, reclaim)
    world.apply(reclaim)
    assert reg.record(agent.id).lovelace < MIN_RECORD_LOVELACE


def test_retire_releasing_the_deposit(world: World, payer: Address, agent: Agent) -> None:
    built = registry(world).retire(payer, agent.id, release_deposit=True)
    scripts_pass(world, built)
    world.apply(built)
    rec = registry(world).record(agent.id)
    assert rec.lovelace < MIN_RECORD_LOVELACE and isinstance(rec.datum.status, Retired)


def test_reclaim_needs_a_tombstone(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="live"):
        registry(world).reclaim(payer, agent.id)


# ---------------------------------------------------------------------------
# Recovery (§3.5)
# ---------------------------------------------------------------------------


def test_recovery_start_cancel_and_complete(world: World, payer: Address, agent: Agent) -> None:
    reg = registry(world)
    new_controller = signing_key("alpha-recovered")
    start = reg.start_recovery(payer, agent.id, public_key(new_controller))
    assert {h(agent.guardians[0]), h(agent.guardians[1]), h(new_controller)} <= set(start.required_signers)
    record = record_after(world, start, agent.id)
    assert record.pending_recovery == PendingRecovery(public_key(new_controller), start.valid_to + DAYS_7_MS)
    with pytest.raises(IdentityRuleError, match="already pending"):
        reg.start_recovery(payer, agent.id, public_key(new_controller))
    with pytest.raises(IdentityRuleError, match="completes at"):
        reg.complete_recovery(payer, agent.id)
    cancel = reg.cancel_recovery(payer, agent.id)
    assert record_after(world, cancel, agent.id).pending_recovery is None

    world.apply(reg.start_recovery(payer, agent.id, public_key(new_controller)))
    world.advance(7 * 86_400 + 1_000)
    complete = reg.complete_recovery(payer, agent.id)
    payer_hash = bytes(Address.from_primitive(str(payer)).payment_part.payload).hex()
    assert set(complete.required_signers) == {payer_hash}  # anybody can complete it
    record = record_after(world, complete, agent.id)
    assert record.controller == public_key(new_controller) and record.subagent_epoch == 1


def test_recovery_needs_enough_guardians(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="at least 2"):
        registry(world).start_recovery(payer, agent.id, public_key(signing_key("x")), guardians=[2])
    with pytest.raises(IdentityRuleError, match="eligible guardian"):
        registry(world).start_recovery(payer, agent.id, public_key(signing_key("x")), guardians=[0, 2])


def test_unknown_record(world: World, payer: Address) -> None:
    with pytest.raises(IdentityLookupError):
        registry(world).update(payer, bytes(32).hex(), name="x")


def test_owner_address_must_be_the_legacy_owner() -> None:
    owner = signing_key("legacy-owner")
    world, legacy_id = _legacy_world(owner)
    payer = world.fund(signing_key("payer"))
    stranger = Address(payment_part=VerificationKeyHash(blake2b_224(b"stranger")), network=Network.MAINNET)
    with pytest.raises(IdentityRuleError, match="owner_address"):
        registry(world).adopt(
            payer,
            legacy_id,
            controller=public_key(owner),
            parties=[PartySpec(Role.ACCOUNTABLE, CONTROLLER_SET)],
            allowlist=world.allowlist,
            owner_address=stranger,
        )
