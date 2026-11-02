"""Attestation builders (Part 2 §4) and the COSE_Sign1 envelope (§4.2)."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from pycardano import Address, AssetName, ScriptHash

from vector_agent.identity import (
    Attestations,
    IdentityLookupError,
    IdentityRuleError,
    Link,
    envelope_sig_structure,
    verify_envelope,
)
from vector_agent.identity.attestation import did_key, envelope_protected_header
from vector_agent.identity.constants import DAY_MS
from vector_agent.identity.types import Anchor, AttRevoked

from .conftest import Agent, register_agent, scripts_pass
from .world import World, key_hash, public_key, signing_key

DIGEST = hashlib.sha256(b"an attested document").digest()


def h(key) -> str:
    return key_hash(key).hex()


def attest(world: World, payer: Address, agent: Agent, **kwargs):
    issuer = kwargs.pop("issuer_key", signing_key("issuer"))
    built = Attestations(world.ctx).attest(
        payer, subject=agent.id, issuer=public_key(issuer), att_type=kwargs.pop("att_type", 0), digest=DIGEST, **kwargs
    )
    scripts_pass(world, built)
    world.apply(built)
    return built, issuer


def test_attest_with_an_unregistered_issuer_and_an_envelope(world: World, payer: Address, agent: Agent) -> None:
    issuer = signing_key("issuer")
    built, _ = attest(
        world,
        payer,
        agent,
        issuer_key=issuer,
        format=50,
        locator="https://attestations.example.org/doc.json",
        sign_envelope=issuer.sign,
    )
    assert h(issuer) in built.required_signers
    body = built.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.attestation.hash)][AssetName(bytes.fromhex(built.created_id))] == 1
    att = Attestations(world.ctx).get(built.created_id)
    assert att.datum.issued_at == built.valid_to and att.lovelace == 5_000_000
    assert att.datum.envelope_sig is not None and verify_envelope(att.datum)
    assert not verify_envelope(replace(att.datum, digest=bytes(32)))


def test_attest_by_a_registered_issuer_solicited(world: World, payer: Address, agent: Agent) -> None:
    issuer_agent = register_agent(world, payer, "issuer")
    built, _ = attest(
        world,
        payer,
        agent,
        issuer_key=issuer_agent.transaction_key,
        issuer_id=issuer_agent.id,
        att_type=2,
        valid_until=world.ctx.clock.posix_ms(world.tip) + 30 * DAY_MS,
        solicited=True,
        links=[Link(0, bytes(32))],
    )
    assert {h(issuer_agent.transaction_key), h(agent.controller)} <= set(built.required_signers)
    datum = Attestations(world.ctx).get(built.created_id).datum
    assert datum.issuer_id == bytes.fromhex(issuer_agent.id) and datum.solicited


def test_attest_refuses_an_unlisted_issuer_key(world: World, payer: Address, agent: Agent) -> None:
    issuer_agent = register_agent(world, payer, "issuer")
    with pytest.raises(IdentityRuleError, match="assertion purpose"):
        Attestations(world.ctx).attest(
            payer, subject=agent.id, issuer=public_key(signing_key("other")), issuer_id=issuer_agent.id,
            att_type=0, digest=DIGEST,
        )


def test_attest_content_rules(world: World, payer: Address, agent: Agent) -> None:
    attestations = Attestations(world.ctx)
    issuer = public_key(signing_key("issuer"))
    with pytest.raises(IdentityRuleError, match="att_type"):
        attestations.attest(payer, subject=agent.id, issuer=issuer, att_type=7, digest=DIGEST)
    with pytest.raises(IdentityRuleError, match="types 2 and 3"):
        attestations.attest(payer, subject=agent.id, issuer=issuer, att_type=3, digest=DIGEST)
    with pytest.raises(IdentityRuleError, match="366 days"):
        attestations.attest(
            payer, subject=agent.id, issuer=issuer, att_type=0, digest=DIGEST,
            valid_until=world.ctx.clock.posix_ms(world.tip) + 400 * DAY_MS,
        )
    with pytest.raises(IdentityLookupError):
        attestations.attest(payer, subject=bytes(32).hex(), issuer=issuer, att_type=0, digest=DIGEST)


def test_revoke_by_the_issuer_key(world: World, payer: Address, agent: Agent) -> None:
    built, issuer = attest(world, payer, agent)
    revoke = Attestations(world.ctx).revoke(payer, built.created_id, reason=3)
    scripts_pass(world, revoke)
    assert h(issuer) in revoke.required_signers
    world.apply(revoke)
    assert Attestations(world.ctx).get(built.created_id).datum.status == AttRevoked(revoke.valid_from, 3)
    with pytest.raises(IdentityRuleError, match="already revoked"):
        Attestations(world.ctx).revoke(payer, built.created_id, reason=3)


def test_revoke_by_the_issuer_controller(world: World, payer: Address, agent: Agent) -> None:
    issuer_agent = register_agent(world, payer, "issuer")
    built, _ = attest(world, payer, agent, issuer_key=issuer_agent.transaction_key, issuer_id=issuer_agent.id)
    revoke = Attestations(world.ctx).revoke(payer, built.created_id, reason=0, by="controller")
    scripts_pass(world, revoke)
    assert h(issuer_agent.controller) in revoke.required_signers
    assert h(issuer_agent.transaction_key) not in revoke.required_signers


def test_contest_by_the_subject(world: World, payer: Address, agent: Agent) -> None:
    built, _ = attest(world, payer, agent)
    reply = hashlib.sha256(b"our reply").digest()
    contest = Attestations(world.ctx).contest(payer, built.created_id, uri="https://alpha.example.org/reply", sha256=reply)
    scripts_pass(world, contest)
    assert h(agent.controller) in contest.required_signers
    world.apply(contest)
    datum = Attestations(world.ctx).get(built.created_id).datum
    assert datum.contested == Anchor(b"https://alpha.example.org/reply", reply)


def test_withdraw_after_90_days(world: World, payer: Address, agent: Agent) -> None:
    built, issuer = attest(world, payer, agent)
    world.apply(Attestations(world.ctx).revoke(payer, built.created_id, reason=0))
    with pytest.raises(IdentityRuleError, match="90 days"):
        Attestations(world.ctx).withdraw(payer, built.created_id)
    world.advance(91 * 86_400)
    withdraw = Attestations(world.ctx).withdraw(payer, built.created_id)
    scripts_pass(world, withdraw)
    assert h(issuer) in withdraw.required_signers
    body = withdraw.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.attestation.hash)][AssetName(bytes.fromhex(built.created_id))] == -1
    world.apply(withdraw)
    with pytest.raises(IdentityLookupError):
        Attestations(world.ctx).get(built.created_id)


def test_envelope_protected_header_is_deterministic() -> None:
    from vector_agent.identity.types import ATT_ACTIVE, AttestationDatum

    key = signing_key("issuer")
    datum = AttestationDatum(
        subject=bytes(32), issuer=public_key(key), issuer_id=None, att_type=0, format=None, profile=None,
        digest=DIGEST, locator=None, envelope_sig=None, issued_at=1_793_577_600_999, valid_from=None,
        valid_until=None, solicited=False, status=ATT_ACTIVE, contested=None, links=(),
    )
    header = envelope_protected_header(datum)
    did = did_key(public_key(key))
    assert did.startswith("did:key:z6Mk")
    # Map of 4 entries: 1 (alg) = -19, 4 (kid), 15 (CWT claims), 258 = -16; keys in bytewise order.
    assert header[:3] == bytes.fromhex("a40132")
    assert bytes.fromhex("1901022f") in header
    assert (1_793_577_600).to_bytes(4, "big") in header
    structure = envelope_sig_structure(datum)
    assert structure.startswith(bytes.fromhex("846a5369676e617475726531"))
    assert structure.endswith(bytes.fromhex("40") + bytes.fromhex("5820") + DIGEST)
    with_format = envelope_protected_header(replace(datum, format=50))
    assert with_format[0] == 0xA5 and with_format.endswith(bytes.fromhex("1901031832"))
