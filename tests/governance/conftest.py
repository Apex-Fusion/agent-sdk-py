"""Fixtures of the Module-6 client tests."""

from __future__ import annotations

import pytest

from vector_agent.identity.ids import blake2b_256
from vector_agent.identity.tx import BuiltTx
from vector_agent.identity.types import OutputReference

from .world import AIKEN, GovAgent, GovWorld

requires_aiken = pytest.mark.skipif(AIKEN is None, reason="aiken is not on PATH")


@pytest.fixture
def gw() -> GovWorld:
    return GovWorld()


@pytest.fixture
def alice(gw: GovWorld) -> GovAgent:
    return gw.agent("alice")


@pytest.fixture
def bob(gw: GovWorld) -> GovAgent:
    return gw.agent("bob")


@pytest.fixture
def carol(gw: GovWorld) -> GovAgent:
    return gw.agent("carol")


def run(gw: GovWorld, built: BuiltTx) -> list[OutputReference]:
    """Run every script of the final transaction (when aiken is on PATH), then apply it."""
    if gw.simulate_scripts:
        gw.simulate(built)
    return [OutputReference(bytes(u.input.transaction_id.payload), u.input.index) for u in gw.apply(built)]


def propose(gw: GovWorld, agent: GovAgent, label: str = "proposal", **terms) -> tuple[OutputReference, OutputReference]:
    """Lock and submit a proposal of ``agent``; returns (seed, proposal output)."""
    lock = gw.gov.lock_proposal(
        agent.address,
        proposer=agent.did,
        proposal_hash=blake2b_256(label.encode()),
        storage_uri=f"ipfs://{label}",
        **terms,
    )
    seed = run(gw, lock)[0]
    created = gw.gov.submit_proposal(agent.address, seed)
    return seed, run(gw, created)[0]


def critique(gw: GovWorld, agent: GovAgent, seed: OutputReference, label: str = "critique", **terms) -> OutputReference:
    lock = gw.gov.lock_critique(
        agent.address,
        critic=agent.did,
        proposal_seed=seed,
        critique_hash=blake2b_256(label.encode()),
        storage_uri=f"ipfs://{label}",
        **terms,
    )
    locked = run(gw, lock)[0]
    return run(gw, gw.gov.submit_critique(agent.address, locked))[0]


def endorse(gw: GovWorld, agent: GovAgent, seed: OutputReference, **terms) -> OutputReference:
    lock = gw.gov.lock_endorsement(agent.address, endorser=agent.did, proposal_seed=seed, **terms)
    locked = run(gw, lock)[0]
    return run(gw, gw.gov.submit_endorsement(agent.address, locked))[0]
