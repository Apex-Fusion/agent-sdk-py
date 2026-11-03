"""Delegation builders (Part 2 §5.1–§5.2)."""

from __future__ import annotations

import pytest
from pycardano import Address, AssetName, ScriptHash

from vector_agent.identity import (
    AgentDelegator,
    Delegations,
    IdentityLookupError,
    IdentityRuleError,
    PrincipalKey,
    ValueLimit,
    escrow_resource,
)
from vector_agent.identity.constants import DAY_MS, HIRE_ACTION
from vector_agent.identity.rules import covers_pattern, narrower, valid_action_pattern, valid_resource_pattern

from .conftest import Agent, register_agent, scripts_pass
from .world import World, key_hash, signing_key

LIMIT = ValueLimit(per_tx=50_000_000, total=200_000_000, period_ms=DAY_MS)


def h(key) -> str:
    return key_hash(key).hex()


def delegate_from_principal(world: World, payer: Address, agent: Agent, **kwargs):
    principal = kwargs.pop("principal", signing_key("principal"))
    built = Delegations(world.ctx).delegate(
        payer,
        delegator=PrincipalKey(key_hash(principal), b"example.org"),
        delegate=agent.id,
        delegate_key=key_hash(agent.delegation_key),
        actions=kwargs.pop("actions", [HIRE_ACTION]),
        resources=kwargs.pop("resources", [escrow_resource(world.scripts.escrow.hash)]),
        not_after=world.ctx.clock.posix_ms(world.tip) + 30 * DAY_MS,
        value=kwargs.pop("value", LIMIT),
        **kwargs,
    )
    scripts_pass(world, built)
    return built, principal


def test_delegate_from_a_principal_key(world: World, payer: Address, agent: Agent) -> None:
    built, principal = delegate_from_principal(world, payer, agent, remaining=1)
    assert {h(principal), h(agent.delegation_key)} <= set(built.required_signers)
    body = built.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.delegation.hash)][AssetName(bytes.fromhex(built.created_id))] == 1
    world.apply(built)
    datum = Delegations(world.ctx).get(built.created_id).datum
    assert datum.depth == 1 and datum.remaining == 1 and datum.not_before == built.valid_from


def test_delegate_from_an_agent_and_a_sub_delegation(world: World, payer: Address, agent: Agent) -> None:
    beta = register_agent(world, payer, "beta")
    root = Delegations(world.ctx).delegate(
        payer,
        delegator=AgentDelegator(bytes.fromhex(agent.id)),
        delegate=beta.id,
        delegate_key=key_hash(beta.delegation_key),
        actions=["ocr.*", "llm.chat"],
        resources=["*"],
        not_after=world.ctx.clock.posix_ms(world.tip) + 30 * DAY_MS,
        remaining=1,
        value=LIMIT,
    )
    scripts_pass(world, root)
    assert {h(agent.controller), h(beta.delegation_key)} <= set(root.required_signers)
    world.apply(root)

    gamma = register_agent(world, payer, "gamma")
    child = Delegations(world.ctx).delegate(
        payer,
        delegator=AgentDelegator(bytes.fromhex(beta.id)),
        delegate=gamma.id,
        delegate_key=key_hash(gamma.delegation_key),
        actions=["ocr.extract.v1"],
        resources=[escrow_resource(world.scripts.escrow.hash)],
        not_after=world.ctx.clock.posix_ms(world.tip) + 20 * DAY_MS,
        value=ValueLimit(10_000_000, 100_000_000, DAY_MS),
        parent=root.created_id,
    )
    scripts_pass(world, child)
    assert {h(beta.delegation_key), h(gamma.delegation_key)} <= set(child.required_signers)
    world.apply(child)
    datum = Delegations(world.ctx).get(child.created_id).datum
    assert datum.depth == 2 and datum.parent == bytes.fromhex(root.created_id)

    # The root delegator ends the child through its ancestor (level 1).
    undelegate = Delegations(world.ctx).undelegate(payer, child.created_id, level=1)
    scripts_pass(world, undelegate)
    assert h(agent.controller) in undelegate.required_signers
    world.apply(undelegate)
    # The delegate key is free again; a child must stay inside its parent ("oc.*" is not inside "ocr.*").
    with pytest.raises(IdentityRuleError, match="inside the parent"):
        Delegations(world.ctx).delegate(
            payer,
            delegator=AgentDelegator(bytes.fromhex(beta.id)),
            delegate=gamma.id,
            delegate_key=key_hash(gamma.delegation_key),
            actions=["oc.*"],
            not_after=world.ctx.clock.posix_ms(world.tip) + DAY_MS,
            parent=root.created_id,
        )


def test_undelegate_by_the_principal(world: World, payer: Address, agent: Agent) -> None:
    built, principal = delegate_from_principal(world, payer, agent)
    world.apply(built)
    undelegate = Delegations(world.ctx).undelegate(payer, built.created_id)
    scripts_pass(world, undelegate)
    assert h(principal) in undelegate.required_signers
    body = undelegate.transaction.transaction_body
    assert body.mint[ScriptHash(world.scripts.delegation.hash)][AssetName(bytes.fromhex(built.created_id))] == -1
    world.apply(undelegate)
    with pytest.raises(IdentityLookupError):
        Delegations(world.ctx).get(built.created_id)


def test_a_delegate_key_serves_one_live_delegation(world: World, payer: Address, agent: Agent) -> None:
    built, _ = delegate_from_principal(world, payer, agent)
    world.apply(built)
    with pytest.raises(IdentityRuleError, match="in use"):
        delegate_from_principal(world, payer, agent, principal=signing_key("other-principal"))


def test_delegate_rules(world: World, payer: Address, agent: Agent) -> None:
    with pytest.raises(IdentityRuleError, match="delegation purpose"):
        Delegations(world.ctx).delegate(
            payer,
            delegator=PrincipalKey(key_hash(signing_key("p"))),
            delegate=agent.id,
            delegate_key=key_hash(agent.transaction_key),
            actions=[HIRE_ACTION],
            not_after=world.ctx.clock.posix_ms(world.tip) + DAY_MS,
        )
    with pytest.raises(IdentityRuleError, match="action pattern"):
        delegate_from_principal(world, payer, agent, actions=["Bad.Pattern"])
    with pytest.raises(IdentityRuleError, match="value limit"):
        delegate_from_principal(world, payer, agent, value=ValueLimit(2, 1, DAY_MS))


def test_patterns() -> None:
    assert valid_action_pattern(b"*") and valid_action_pattern(b"ocr.*") and valid_action_pattern(b"mcp:tool/x")
    assert not valid_action_pattern(b"ocr.") and not valid_action_pattern(b".*") and not valid_action_pattern(b"A")
    assert valid_resource_pattern(b"script:" + b"0" * 56) and not valid_resource_pattern(b"script:" + b"0" * 55)
    assert not valid_resource_pattern(b"ocr.*")
    assert covers_pattern(b"ocr.*", b"ocr.extract") and covers_pattern(b"ocr.*", b"ocr.extract.*")
    assert not covers_pattern(b"oc.*", b"ocr.extract")
    assert not covers_pattern(b"https://a.*", b"https://a.b")
    assert narrower([b"ocr.extract"], [b"ocr.*"]) and not narrower([b"*"], [b"ocr.*"])
