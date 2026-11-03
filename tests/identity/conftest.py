"""Fixtures of the identity client tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from pycardano import Address, PaymentSigningKey

from vector_agent.identity import (
    BuiltTx,
    IdentityRegistry,
    KeyHashSigner,
    PartySpec,
    Role,
    ed25519_key,
    p256_key,
)
from vector_agent.identity.constants import (
    PURPOSE_ASSERTION,
    PURPOSE_AUTHENTICATION,
    PURPOSE_DELEGATION,
    PURPOSE_TRANSACTION,
)

from .world import AIKEN, World, key_hash, public_key, signing_key

requires_aiken = pytest.mark.skipif(AIKEN is None, reason="aiken is not on PATH")


def scripts_pass(world: World, built: BuiltTx) -> None:
    """The final transaction passes every script (when aiken is on PATH)."""
    if world.simulate_scripts:
        world.simulate(built)


@dataclass
class Agent:
    """A registered root agent and its throwaway keys."""

    id: str
    controller: PaymentSigningKey
    accountable: PaymentSigningKey
    responsible: PaymentSigningKey
    guardians: tuple[PaymentSigningKey, PaymentSigningKey]
    transaction_key: PaymentSigningKey
    delegation_key: PaymentSigningKey


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def payer(world: World) -> Address:
    return world.fund(signing_key("payer"), 900_000_000, count=3)


def register_agent(world: World, payer: Address, label: str, *, threshold: int = 2) -> Agent:
    keys = {name: signing_key(f"{label}-{name}") for name in (
        "controller", "accountable", "responsible", "guardian1", "guardian2", "tx", "delegation",
    )}
    built = IdentityRegistry(world.ctx).register(
        payer,
        controller=public_key(keys["controller"]),
        name=f"{label} agent",
        description="An agent of the identity tests.",
        framework="custom",
        endpoint=f"https://{label}.example.org/mcp",
        capabilities=["llm.chat", "document-extraction"],
        keys=[
            ed25519_key(public_key(keys["tx"]), PURPOSE_AUTHENTICATION | PURPOSE_ASSERTION | PURPOSE_TRANSACTION),
            ed25519_key(public_key(keys["delegation"]), PURPOSE_DELEGATION),
            p256_key(b"\x02" + bytes([7]) * 32, bytes(64), PURPOSE_ASSERTION),
        ],
        parties=[
            PartySpec(Role.ACCOUNTABLE, KeyHashSigner(key_hash(keys["accountable"])), organisation="example.org"),
            PartySpec(Role.RESPONSIBLE, KeyHashSigner(key_hash(keys["responsible"]))),
            PartySpec(Role.GUARDIAN, KeyHashSigner(key_hash(keys["guardian1"]))),
            PartySpec(Role.GUARDIAN, KeyHashSigner(key_hash(keys["guardian2"]))),
        ],
        guardian_threshold=threshold,
    )
    world.apply(built)
    return Agent(
        id=built.created_id,
        controller=keys["controller"],
        accountable=keys["accountable"],
        responsible=keys["responsible"],
        guardians=(keys["guardian1"], keys["guardian2"]),
        transaction_key=keys["tx"],
        delegation_key=keys["delegation"],
    )


@pytest.fixture
def agent(world: World, payer: Address) -> Agent:
    return register_agent(world, payer, "alpha")
