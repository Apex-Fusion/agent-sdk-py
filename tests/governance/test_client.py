"""GovernanceClient flows with a stand-in agent on the offline ledger.

The stand-in agent has a wallet key and a chain context whose submission checks
every required signature, runs the scripts (``aiken tx simulate``) and applies
the transaction to the ledger.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nacl.signing import VerifyKey
from pycardano import Transaction

from vector_agent.exceptions import SpendLimitExceededError
from vector_agent.governance import (
    GovernanceClient,
    GovernanceRuleError,
    ProposalDatum,
    ProposalType,
    proposal_token_name,
)
from vector_agent.identity.ids import blake2b_256
from vector_agent.identity.types import KeyCredential, OutputReference
from vector_agent.safety import SafetyLayer

from .world import GovAgent, GovWorld, key_hash, signing_key


class StandInContext:
    def __init__(self, gw: GovWorld) -> None:
        self.gw = gw
        self.submitted: list[Transaction] = []

    async def async_submit_tx_cbor(self, cbor) -> str:
        tx = Transaction.from_cbor(cbor)
        body_hash = tx.transaction_body.hash()
        signed = set()
        for witness in tx.transaction_witness_set.vkey_witnesses or []:
            VerifyKey(bytes(witness.vkey.payload)).verify(body_hash, witness.signature)
            signed.add(bytes(witness.vkey.hash().payload))
        required = {bytes(h.payload) for h in tx.transaction_body.required_signers or []}
        assert required <= signed, "a required signer did not sign"
        if self.gw.simulate_scripts and tx.transaction_witness_set.redeemer:
            self.gw.simulate(tx)
        self.gw.apply(tx)
        self.submitted.append(tx)
        return str(tx.id)


class StandInAgent:
    """What GovernanceClient reads from a VectorAgent."""

    def __init__(self, gw: GovWorld, agent: GovAgent, per_tx_limit: int = 100_000_000) -> None:
        self._wallet = SimpleNamespace(payment_signing_key=agent.key, payment_address=agent.address)
        self._ogmios_url = "http://ogmios.invalid"
        self.context = StandInContext(gw)
        self.safety = SafetyLayer(per_tx_limit=per_tx_limit)


def client(gw: GovWorld, agent: GovAgent, **kwargs) -> GovernanceClient:
    return GovernanceClient(
        StandInAgent(gw, agent, **kwargs), gw.deployment, ledger=gw, clock=gw.gov_ctx.clock, attempts=2, delay=0
    )


def ref(text: str) -> OutputReference:
    return OutputReference.parse(text)


async def test_proposal_endorsement_and_critique_flows(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    gov = client(gw, alice)
    result = await gov.submit_proposal(alice.did, blake2b_256(b"proposal"), "ipfs://proposal")
    seed = ref(result["seed"])
    assert result["seed"] == f"{result['lock_tx_hash']}#0"
    assert result["proposal_token_name"] == proposal_token_name(seed).hex()
    assert result["stake"] == 25_000_000 and result["script_address"].startswith("addr1w")
    proposal = gw.gov_ctx.proposal(ref(result["proposal"]))
    assert proposal.datum.proposer_did == alice.id and proposal.token == proposal_token_name(seed)
    node = gw.gov_ctx.activity_list().node(alice.id)
    assert node.ref == ref(result["activity"]) and node.datum.active_proposal_count == 1
    status = gov.agent.safety.get_spend_status()
    assert status.daily_spent >= 27_000_000

    bob_gov = client(gw, bob)
    endorsed = await bob_gov.endorse_proposal(bob.did, result["seed"])
    assert gw.gov_ctx.endorsement(ref(endorsed["endorsement"])).datum.endorser_did == bob.id
    reviewed = await bob_gov.submit_critique(bob.did, seed, blake2b_256(b"critique"), "ipfs://critique")
    assert gw.gov_ctx.critique(ref(reviewed["critique"])).datum.proposal_ref == seed

    assert (await bob_gov.withdraw_critique(reviewed["critique"]))["tx_hash"]
    assert (await bob_gov.withdraw_endorsement(endorsed["endorsement"]))["tx_hash"]
    proposals = await gov.get_proposals()
    assert [p.ref for p in proposals] == [ref(result["proposal"])]
    assert (await gov.withdraw_proposal(result["proposal"]))["tx_hash"]
    assert gw.gov_ctx.proposal_by_seed(seed) is None


async def test_oracle_actions_need_the_oracle_key(gw: GovWorld, alice: GovAgent) -> None:
    gov = client(gw, alice)
    result = await gov.submit_proposal(alice.did, blake2b_256(b"proposal"), "ipfs://proposal")
    with pytest.raises(GovernanceRuleError, match=key_hash(gw.oracle_key).hex()):
        await gov.adopt_proposal(result["proposal"], blake2b_256(b"why"), 50_000_000)
    adopted = await gov.adopt_proposal(
        result["proposal"], blake2b_256(b"why"), 50_000_000, signing_keys=[gw.oracle_key]
    )
    assert adopted["reward"] == 50_000_000


async def test_a_listed_transaction_key_signs_as_the_credential(gw: GovWorld) -> None:
    tx_key = signing_key("dana-transaction-key")
    dana = gw.agent("dana", transaction_keys=(tx_key,))
    gov = client(gw, dana)
    result = await gov.submit_proposal(
        dana.did,
        blake2b_256(b"proposal"),
        "ipfs://proposal",
        ProposalType.general_suggestion(),
        credential_key=tx_key,
    )
    datum: ProposalDatum = gw.gov_ctx.proposal(ref(result["proposal"])).datum
    assert datum.proposer_credential == KeyCredential(key_hash(tx_key))
    amended = await gov.amend_proposal(result["proposal"], blake2b_256(b"v2"), "ipfs://v2", credential_key=tx_key)
    assert gw.gov_ctx.proposal(ref(amended["proposal"])).datum.amendment_count == 1


async def test_the_spend_limit_applies_to_locks(gw: GovWorld, alice: GovAgent) -> None:
    gov = client(gw, alice, per_tx_limit=10_000_000)
    with pytest.raises(SpendLimitExceededError):
        await gov.submit_proposal(alice.did, blake2b_256(b"proposal"), "ipfs://proposal")
    assert gov.agent.context.submitted == []


@pytest.mark.parametrize(
    "koios_url",
    ["https://v2.koios.vector.testnet.apexfusion.org/", "https://v2.koios.vector.testnet.apexfusion.org/api/v1"],
)
def test_the_koios_url_of_the_agent_in_both_forms(gw: GovWorld, alice: GovAgent, koios_url: str) -> None:
    agent = StandInAgent(gw, alice)
    agent._koios_url = koios_url
    gov = GovernanceClient(agent, gw.deployment)
    assert gov.ctx.ledger._koios_url == "https://v2.koios.vector.testnet.apexfusion.org/api/v1"
