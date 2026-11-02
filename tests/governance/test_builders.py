"""Module-6 builders against the compiled validators.

``GovWorld`` holds a Module-6 deployment of the embedded blueprint. Every build
evaluates its redeemers with ``aiken tx simulate`` (when ``aiken`` is on PATH),
so a transaction that a validator rejects fails the build, and ``run`` runs the
final transaction once more. The tests marked ``requires_aiken`` remove one
client check and show that the validators then reject the transaction.
"""

from __future__ import annotations

import pytest
from pycardano import AssetName, ScriptHash

from vector_agent.exceptions import TransactionError
from vector_agent.governance import (
    ActivityDatum,
    ActivityList,
    CritiqueDatum,
    CritiqueType,
    EndorsementDatum,
    GovernanceLookupError,
    GovernanceRuleError,
    ProposalDatum,
    ProposalKind,
    ProposalPriority,
    ProposalType,
    StateKind,
    activity_token_name,
    critique_token_name,
    endorsement_token_name,
    proposal_token_name,
)
from vector_agent.governance import builders as builders_module
from vector_agent.governance.context import Position
from vector_agent.identity.ids import blake2b_256
from vector_agent.identity.tx import BuiltTx, Window
from vector_agent.identity.types import KeyCredential, OutputReference

from .conftest import critique, endorse, propose, requires_aiken, run
from .world import PARAMS, GovAgent, GovWorld, key_hash, revoked, signing_key, suspended

DAY_S = 86_400


def body(built: BuiltTx):
    return built.transaction.transaction_body


def output_datum(built: BuiltTx, index: int, decode):
    return decode(bytes(body(built).outputs[index].datum.cbor))


def references(built: BuiltTx) -> set[OutputReference]:
    return {OutputReference(bytes(i.transaction_id.payload), i.index) for i in body(built).reference_inputs or []}


def ref(utxo) -> OutputReference:
    return OutputReference(bytes(utxo.input.transaction_id.payload), utxo.input.index)


def minted(built: BuiltTx, policy: bytes) -> dict[bytes, int]:
    bundle = (body(built).mint or {}).get(ScriptHash(policy), {})
    return {bytes(name.payload): quantity for name, quantity in bundle.items()}


def lock_proposal(gw: GovWorld, agent: GovAgent, label: str = "proposal", **terms) -> BuiltTx:
    terms.setdefault("storage_uri", f"ipfs://{label}")
    return gw.gov.lock_proposal(agent.address, proposer=agent.did, proposal_hash=blake2b_256(label.encode()), **terms)


# ---------------------------------------------------------------------------
# SubmitProposal and the activity list
# ---------------------------------------------------------------------------


def test_first_submission_inserts_the_node_after_the_head(gw: GovWorld, alice: GovAgent) -> None:
    scripts = gw.gov_scripts
    lock = lock_proposal(gw, alice, storage_uri="ipfs://" + "Q" * 90)
    datum = output_datum(lock, 0, ProposalDatum.from_cbor)
    assert datum.proposer_did == alice.id and datum.proposer_credential == KeyCredential(alice.key_hash)
    assert datum.submitted_at == lock.valid_from and len(datum.storage_uri) == 97
    assert body(lock).outputs[0].address == scripts.proposal_spend.address
    assert body(lock).outputs[0].amount.coin >= PARAMS.min_proposal_stake + 2_000_000
    seed = run(gw, lock)[0]

    created = gw.gov.submit_proposal(alice.address, seed)
    token = proposal_token_name(seed)
    assert created.created_id == token.hex()
    assert created.required_signers == (alice.key_hash.hex(),)
    assert minted(created, scripts.proposal_mint.hash) == {token: 1, activity_token_name(alice.id): 1}
    assert {ref(alice.record), ref(gw.params_utxo), ref(gw.cross_refs_utxo)} <= references(created)
    proposal = output_datum(created, 0, ProposalDatum.from_cbor)
    assert proposal.submitted_at == created.valid_from and created.valid_to - created.valid_from <= 3_600_000
    node = output_datum(created, 1, ActivityDatum.from_cbor)
    assert node == ActivityDatum(alice.id, KeyCredential(alice.key_hash), 1, created.valid_from, b"")
    head = output_datum(created, 2, ActivityDatum.from_cbor)
    assert head.agent_did == b"" and head.next_did == alice.id
    run(gw, created)

    activity = gw.gov_ctx.activity_list()
    assert activity.head.datum.next_did == alice.id
    assert [n.datum.agent_did for n in activity.nodes] == [alice.id]


def test_first_submission_inserts_between_two_nodes(gw: GovWorld) -> None:
    agents = sorted((gw.agent(label) for label in ("alice", "bob", "carol")), key=lambda a: a.id)
    first, middle, last = agents
    propose(gw, first, "first")
    propose(gw, last, "last")
    lock = run(gw, lock_proposal(gw, middle, "middle"))[0]
    created = gw.gov.submit_proposal(middle.address, lock)
    assert output_datum(created, 1, ActivityDatum.from_cbor).next_did == last.id
    predecessor = output_datum(created, 2, ActivityDatum.from_cbor)
    assert predecessor.agent_did == first.id and predecessor.next_did == middle.id
    run(gw, created)
    assert [n.datum.agent_did for n in gw.gov_ctx.activity_list().nodes] == [first.id, middle.id, last.id]


def test_next_submission_continues_the_node(gw: GovWorld, alice: GovAgent) -> None:
    propose(gw, alice, "one")
    with pytest.raises(GovernanceRuleError, match="cooldown"):
        lock_proposal(gw, alice, "two")
    gw.advance(DAY_S + 120)
    lock = run(gw, lock_proposal(gw, alice, "two"))[0]
    created = gw.gov.submit_proposal(alice.address, lock)
    assert minted(created, gw.gov_scripts.proposal_mint.hash) == {proposal_token_name(lock): 1}
    node = output_datum(created, 1, ActivityDatum.from_cbor)
    assert node.active_proposal_count == 2 and node.last_proposal_slot == created.valid_from
    run(gw, created)


def test_active_proposal_limit(gw: GovWorld, alice: GovAgent) -> None:
    for label in ("one", "two", "three"):
        propose(gw, alice, label)
        gw.advance(DAY_S + 120)
    with pytest.raises(GovernanceRuleError, match="3 active proposals"):
        lock_proposal(gw, alice, "four")


def test_subagent_proposal_reads_the_parent_record(gw: GovWorld) -> None:
    parent = gw.agent("parent")
    child = gw.agent("child", parent=parent.id)
    lock = run(gw, lock_proposal(gw, child))[0]
    created = gw.gov.submit_proposal(child.address, lock)
    assert {ref(child.record), ref(parent.record)} <= references(created)
    run(gw, created)


def test_inactive_parent_suspends_the_subagent(gw: GovWorld) -> None:
    parent = gw.agent("parent")
    child = gw.agent("child", parent=parent.id)
    gw.replace_record(parent, suspended(gw.record_datum(parent.key)))
    with pytest.raises(GovernanceRuleError, match="suspended"):
        lock_proposal(gw, child)


def test_listed_transaction_key_as_the_credential(gw: GovWorld) -> None:
    tx_key = signing_key("dana-transaction-key")
    dana = gw.agent("dana", transaction_keys=(tx_key,))
    lock_built = lock_proposal(gw, dana, credential_key_hash=key_hash(tx_key))
    assert output_datum(lock_built, 0, ProposalDatum.from_cbor).proposer_credential == KeyCredential(key_hash(tx_key))
    created = gw.gov.submit_proposal(dana.address, run(gw, lock_built)[0])
    assert set(created.required_signers) == {key_hash(tx_key).hex(), dana.key_hash.hex()}
    run(gw, created)


def test_undeclared_credential_is_refused(gw: GovWorld, alice: GovAgent) -> None:
    with pytest.raises(GovernanceRuleError, match="not the controller"):
        lock_proposal(gw, alice, credential_key_hash=key_hash(signing_key("stranger")))


@pytest.mark.parametrize(
    ("change", "status"),
    [
        (suspended, "suspended"),
        (revoked, "revoked"),
    ],
)
def test_inactive_agent_is_refused(gw: GovWorld, alice: GovAgent, change, status: str) -> None:
    gw.replace_record(alice, change(gw.record_datum(alice.key)))
    with pytest.raises(GovernanceRuleError, match=status):
        lock_proposal(gw, alice)


def test_agent_without_an_accountable_party_is_suspended(gw: GovWorld) -> None:
    erin = gw.agent("erin", parties=())
    with pytest.raises(GovernanceRuleError, match="suspended"):
        lock_proposal(gw, erin)


def test_missing_record_and_missing_ancestor(gw: GovWorld) -> None:
    ghost = GovAgent(blake2b_256(b"ghost"), signing_key("ghost"), None)
    gw.fund(ghost.key)
    with pytest.raises(GovernanceLookupError, match="no identity record"):
        lock_proposal(gw, ghost)
    orphan = gw.agent("orphan", parent=blake2b_256(b"missing parent"))
    with pytest.raises(GovernanceLookupError, match="no identity record"):
        lock_proposal(gw, orphan)


@pytest.mark.parametrize(
    ("terms", "message"),
    [
        ({"stake": 24_000_000}, "stake is below"),
        ({"review_window": 1_000}, "review window"),
        ({"proposal_type": ProposalType.parameter_change("NOT_A_PARAM", 1, 2)}, "not a governable parameter"),
        ({"proposal_type": ProposalType.treasury_spend(0, "nothing")}, "treasury amount"),
        ({"proposal_type": ProposalType.protocol_upgrade(bytes(31))}, "not 32 bytes"),
        ({"priority": ProposalPriority.EMERGENCY}, "emergency proposal is a ParameterChange"),
    ],
)
def test_proposal_rules(gw: GovWorld, alice: GovAgent, terms: dict, message: str) -> None:
    with pytest.raises(GovernanceRuleError, match=message):
        lock_proposal(gw, alice, **terms)


def test_emergency_proposal(gw: GovWorld, alice: GovAgent) -> None:
    lock_built = lock_proposal(
        gw,
        alice,
        proposal_type=ProposalType.parameter_change("MAX_AMENDMENTS", 5, 6),
        priority=ProposalPriority.EMERGENCY,
    )
    datum = output_datum(lock_built, 0, ProposalDatum.from_cbor)
    assert datum.stake_amount == 125_000_000 and datum.review_window == PARAMS.emergency_review_window
    run(gw, gw.gov.submit_proposal(alice.address, run(gw, lock_built)[0]))


def test_a_submitted_proposal_is_not_a_lock(gw: GovWorld, alice: GovAgent) -> None:
    _, proposal = propose(gw, alice)
    with pytest.raises(GovernanceRuleError, match="holds tokens"):
        gw.gov.submit_proposal(alice.address, proposal)


# ---------------------------------------------------------------------------
# Critiques and endorsements name the proposal by its seed
# ---------------------------------------------------------------------------


def test_critique_names_the_seed_and_reads_the_proposer_record(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    lock = gw.gov.lock_critique(
        bob.address,
        critic=bob.did,
        proposal_seed=seed,
        critique_hash=blake2b_256(b"critique"),
        storage_uri="ipfs://critique",
    )
    locked = output_datum(lock, 0, CritiqueDatum.from_cbor)
    assert locked.proposal_ref == seed and locked.stake_amount == PARAMS.min_critique_stake
    lock_ref = run(gw, lock)[0]
    created = gw.gov.submit_critique(bob.address, lock_ref)
    assert created.created_id == critique_token_name(lock_ref).hex()
    assert minted(created, gw.gov_scripts.critique_mint.hash) == {critique_token_name(lock_ref): 1}
    assert {ref(bob.record), ref(alice.record), proposal} <= references(created)
    assert output_datum(created, 0, CritiqueDatum.from_cbor).submitted_at == created.valid_from
    assert created.required_signers == (bob.key_hash.hex(),)
    run(gw, created)


def test_amendment_critique_of_the_proposer(gw: GovWorld, alice: GovAgent) -> None:
    seed, _ = propose(gw, alice)
    position = critique(gw, alice, seed, critique_type=CritiqueType.amendment(blake2b_256(b"change")))
    assert gw.gov_ctx.critique(position).datum.critique_type.kind.name == "AMENDMENT"


def test_critique_refusals(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, _ = propose(gw, alice)
    terms = {"critique_hash": blake2b_256(b"c"), "storage_uri": "ipfs://c", "proposal_seed": seed}
    with pytest.raises(GovernanceRuleError, match="only an Amendment critique"):
        gw.gov.lock_critique(alice.address, critic=alice.did, **terms)
    with pytest.raises(GovernanceRuleError, match="stake is below"):
        gw.gov.lock_critique(bob.address, critic=bob.did, stake=1_000_000, **terms)
    twin = gw.agent("twin", fund=False)
    twin = gw.replace_record(twin, gw.record_datum(alice.key))
    with pytest.raises(GovernanceRuleError, match="same controller key"):
        gw.gov.lock_critique(alice.address, critic=twin.did, **terms)
    child = gw.agent("child-of-alice", parent=alice.id)
    with pytest.raises(GovernanceRuleError, match="subagent of the proposer"):
        gw.gov.lock_critique(child.address, critic=child.did, **terms)
    with pytest.raises(GovernanceLookupError, match="no proposal holds the token"):
        gw.gov.lock_critique(bob.address, critic=bob.did, **{**terms, "proposal_seed": f"{'ab' * 32}#0"})


def test_endorsement_mints_the_endorsement_token(gw: GovWorld, alice: GovAgent, carol: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    lock = gw.gov.lock_endorsement(carol.address, endorser=carol.did, proposal_seed=seed)
    assert output_datum(lock, 0, EndorsementDatum.from_cbor).proposal_ref == seed
    created = gw.gov.submit_endorsement(carol.address, run(gw, lock)[0])
    token = endorsement_token_name(carol.id, seed)
    assert minted(created, gw.gov_scripts.critique_mint.hash) == {token: 1}
    assert {ref(carol.record), ref(alice.record), proposal} <= references(created)
    datum = output_datum(created, 0, EndorsementDatum.from_cbor)
    assert datum.created_at == created.valid_from and datum.stake_amount == PARAMS.min_governance_endorsement
    run(gw, created)


def test_endorsement_refusals(gw: GovWorld, alice: GovAgent, carol: GovAgent) -> None:
    seed, _ = propose(gw, alice)
    with pytest.raises(GovernanceRuleError, match="cannot endorse its own proposal"):
        gw.gov.lock_endorsement(alice.address, endorser=alice.did, proposal_seed=seed)
    with pytest.raises(GovernanceRuleError, match="stake is below"):
        gw.gov.lock_endorsement(carol.address, endorser=carol.did, proposal_seed=seed, stake=1)


# ---------------------------------------------------------------------------
# AmendProposal
# ---------------------------------------------------------------------------


def test_amend_with_incorporated_critiques(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    first = critique(gw, bob, seed, "by-bob")
    second = critique(gw, alice, seed, "by-alice", critique_type=CritiqueType.amendment(blake2b_256(b"x")))
    before = gw.gov_ctx.proposal(proposal).datum
    built = gw.gov.amend_proposal(
        alice.address, proposal, new_hash=blake2b_256(b"v2"), new_uri="ipfs://v2", incorporate=[first, second]
    )
    amended = output_datum(built, 0, ProposalDatum.from_cbor)
    assert amended.state.kind == StateKind.AMENDED and amended.state.hash == before.proposal_hash
    assert amended.amendment_count == 1 and amended.incorporated_critiques == (first, second)
    assert amended.submitted_at == before.submitted_at
    for index, position in ((1, first), (2, second)):
        datum = output_datum(built, index, CritiqueDatum.from_cbor)
        assert datum.incorporated and body(built).outputs[index].amount == gw.utxo(position).output.amount
    outputs = run(gw, built)
    assert gw.gov_ctx.proposal(outputs[0]).token == proposal_token_name(seed)


def test_amend_refusals(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    other_seed, _ = propose(gw, bob, "other")
    foreign = critique(gw, alice, other_seed, "foreign")
    current = gw.gov_ctx.proposal(proposal).datum.proposal_hash
    with pytest.raises(GovernanceRuleError, match="differs from the current hash"):
        gw.gov.amend_proposal(alice.address, proposal, new_hash=current, new_uri="ipfs://v2")
    with pytest.raises(GovernanceRuleError, match="names another proposal"):
        gw.gov.amend_proposal(alice.address, proposal, new_hash=blake2b_256(b"v2"), new_uri="ipfs://v2", incorporate=[foreign])
    own = critique(gw, bob, seed, "own")
    with pytest.raises(GovernanceRuleError, match="listed twice"):
        gw.gov.amend_proposal(alice.address, proposal, new_hash=blake2b_256(b"v2"), new_uri="ipfs://v2", incorporate=[own, own])


# ---------------------------------------------------------------------------
# Exits and settlements
# ---------------------------------------------------------------------------


def test_withdraw_critique_burns_the_token_and_pays_the_critic(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    position = critique(gw, bob, seed)
    held = gw.gov_ctx.critique(position)
    built = gw.gov.withdraw_critique(bob.address, position)
    assert minted(built, gw.gov_scripts.critique_mint.hash) == {held.token: -1}
    assert proposal in references(built) and built.required_signers == (bob.key_hash.hex(),)
    payout = body(built).outputs[0]
    assert payout.address == bob.address and payout.amount.coin == held.lovelace
    run(gw, built)


def test_incorporated_critique_settles_with_the_finalisation(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    position = critique(gw, bob, seed)
    outputs = run(
        gw,
        gw.gov.amend_proposal(alice.address, proposal, new_hash=blake2b_256(b"v2"), new_uri="ipfs://v2", incorporate=[position]),
    )
    with pytest.raises(GovernanceRuleError, match="incorporated"):
        gw.gov.withdraw_critique(bob.address, outputs[1])
    built = gw.gov.withdraw_proposal(alice.address, outputs[0], settle=[outputs[1]])
    payouts = {str(o.address): o.amount.coin for o in body(built).outputs}
    assert payouts[str(bob.address)] == gw.gov_ctx.critique(outputs[1]).lovelace
    run(gw, built)


def test_critique_withdrawal_reads_another_active_proposal(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    position = critique(gw, bob, seed)
    run(gw, gw.gov.withdraw_proposal(alice.address, proposal))
    with pytest.raises(GovernanceLookupError, match="no proposal is Open or Amended"):
        gw.gov.withdraw_critique(bob.address, position)
    _, other = propose(gw, bob, "other")
    built = gw.gov.withdraw_critique(bob.address, position)
    assert other in references(built)
    run(gw, built)


def test_withdraw_endorsement(gw: GovWorld, alice: GovAgent, carol: GovAgent) -> None:
    seed, _ = propose(gw, alice)
    position = endorse(gw, carol, seed)
    built = gw.gov.withdraw_endorsement(carol.address, position)
    assert minted(built, gw.gov_scripts.critique_mint.hash) == {endorsement_token_name(carol.id, seed): -1}
    assert built.required_signers == (carol.key_hash.hex(),)
    run(gw, built)


def test_withdraw_proposal_returns_the_stake(gw: GovWorld, alice: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    position = gw.gov_ctx.proposal(proposal)
    built = gw.gov.withdraw_proposal(alice.address, proposal)
    assert minted(built, gw.gov_scripts.proposal_mint.hash) == {proposal_token_name(seed): -1}
    assert built.required_signers == (alice.key_hash.hex(),)
    node = output_datum(built, 0, ActivityDatum.from_cbor)
    assert node.agent_did == alice.id and node.active_proposal_count == 0
    payout = body(built).outputs[1]
    assert payout.address == alice.address and payout.amount.coin == position.lovelace
    run(gw, built)
    assert gw.gov_ctx.proposal_by_seed(seed) is None


def test_settling_a_position_of_another_proposal_needs_its_owner(
    gw: GovWorld, alice: GovAgent, bob: GovAgent, carol: GovAgent
) -> None:
    _, proposal = propose(gw, alice)
    other_seed, _ = propose(gw, bob, "other")
    position = endorse(gw, carol, other_seed)
    built = gw.gov.withdraw_proposal(alice.address, proposal, settle=[position])
    assert carol.key_hash.hex() in built.required_signers
    run(gw, built)


def test_expire_after_the_review_window(gw: GovWorld, alice: GovAgent, carol: GovAgent) -> None:
    _, proposal = propose(gw, alice)
    with pytest.raises(GovernanceRuleError, match="review window"):
        gw.gov.expire_proposal(carol.address, proposal)
    gw.advance(8 * DAY_S)
    built = gw.gov.expire_proposal(carol.address, proposal)
    assert built.required_signers == (carol.key_hash.hex(),)
    assert body(built).outputs[1].address == alice.address
    run(gw, built)


def test_expire_stale_proposal(gw: GovWorld, alice: GovAgent, carol: GovAgent) -> None:
    _, stale = propose(gw, alice, "stale", proposal_type=ProposalType.parameter_change("MIN_PROPOSAL_STAKE", 20_000_000, 1))
    gw.advance(DAY_S + 120)
    _, current = propose(gw, alice, "current", proposal_type=ProposalType.parameter_change("MAX_AMENDMENTS", 5, 6))
    gw.advance(DAY_S + 120)
    _, module1 = propose(gw, alice, "module1", proposal_type=ProposalType.parameter_change("JURY_SIZE", 1, 2))
    with pytest.raises(GovernanceRuleError, match="not stale"):
        gw.gov.expire_stale_proposal(carol.address, current)
    with pytest.raises(GovernanceRuleError, match="not a Module-6 parameter"):
        gw.gov.expire_stale_proposal(carol.address, module1)
    run(gw, gw.gov.expire_stale_proposal(carol.address, stale))


def test_adopt_needs_the_oracle_and_settles_positions(
    gw: GovWorld, alice: GovAgent, bob: GovAgent, carol: GovAgent
) -> None:
    seed, proposal = propose(gw, alice)
    review = critique(gw, bob, seed)
    support = endorse(gw, carol, seed)
    with pytest.raises(GovernanceRuleError, match="reward must be in"):
        gw.gov.adopt_proposal(alice.address, proposal, reasoning_hash=blake2b_256(b"why"), reward_amount=1)
    built = gw.gov.adopt_proposal(
        alice.address, proposal, reasoning_hash=blake2b_256(b"why"), reward_amount=50_000_000, settle=[review, support]
    )
    assert key_hash(gw.oracle_key).hex() in built.required_signers
    assert ref(gw.oracle_utxo) in references(built)
    burns = minted(built, gw.gov_scripts.critique_mint.hash)
    assert burns == {gw.gov_ctx.critique(review).token: -1, endorsement_token_name(carol.id, seed): -1}
    addresses = {str(o.address) for o in body(built).outputs}
    assert {str(alice.address), str(bob.address), str(carol.address)} <= addresses
    run(gw, built)


def test_reject_and_extend_review(gw: GovWorld, alice: GovAgent) -> None:
    _, proposal = propose(gw, alice)
    with pytest.raises(GovernanceRuleError, match="exceed"):
        gw.gov.extend_review(alice.address, proposal, additional_ms=PARAMS.max_review_window)
    extended = gw.gov.extend_review(alice.address, proposal, additional_ms=DAY_S * 1000)
    assert output_datum(extended, 0, ProposalDatum.from_cbor).review_window == 604_800_000 + DAY_S * 1000
    assert key_hash(gw.oracle_key).hex() in extended.required_signers
    proposal = run(gw, extended)[0]
    rejected = gw.gov.reject_proposal(alice.address, proposal, reasoning_hash=blake2b_256(b"no"))
    assert key_hash(gw.oracle_key).hex() in rejected.required_signers
    run(gw, rejected)


def test_inactive_oracle_is_refused(gw: GovWorld, alice: GovAgent) -> None:
    from pycardano import TransactionOutput
    from pycardano.serialization import RawCBOR

    from vector_agent.governance import GovernanceOracleDatum

    _, proposal = propose(gw, alice)
    output = gw.oracle_utxo.output
    datum = GovernanceOracleDatum(KeyCredential(key_hash(gw.oracle_key)), bytes(28), False)
    del gw.ledger_state[gw.oracle_utxo.input]
    gw.oracle_utxo = gw.put(TransactionOutput(output.address, output.amount, datum=RawCBOR(datum.to_cbor())))
    with pytest.raises(GovernanceRuleError, match="not active"):
        gw.gov.reject_proposal(alice.address, proposal, reasoning_hash=blake2b_256(b"no"))


def test_without_reference_scripts_a_submission_is_too_large() -> None:
    gw = GovWorld(reference_scripts=False)
    alice = gw.agent("alice")
    lock = run(gw, lock_proposal(gw, alice))[0]
    with pytest.raises(TransactionError, match="REF_UTXO"):
        gw.gov.submit_proposal(alice.address, lock)


def test_proposal_types_round_trip_through_the_ledger(gw: GovWorld, alice: GovAgent) -> None:
    kinds = [
        ProposalType.treasury_spend(1_000_000, "a recipient"),
        ProposalType.protocol_upgrade(blake2b_256(b"upgrade")),
        ProposalType.game_activation(3),
    ]
    for index, proposal_type in enumerate(kinds):
        _, proposal = propose(gw, alice, f"kind-{index}", proposal_type=proposal_type)
        assert gw.gov_ctx.proposal(proposal).datum.proposal_type == proposal_type
        gw.advance(DAY_S + 120)
        run(gw, gw.gov.withdraw_proposal(alice.address, proposal))
    assert {k.kind for k in kinds} == {ProposalKind.TREASURY_SPEND, ProposalKind.PROTOCOL_UPGRADE, ProposalKind.GAME_ACTIVATION}


# ---------------------------------------------------------------------------
# The validators reject what the client refuses
# ---------------------------------------------------------------------------


@requires_aiken
def test_validators_reject_a_range_over_one_hour(gw: GovWorld, alice: GovAgent) -> None:
    lock = run(gw, lock_proposal(gw, alice))[0]
    window = gw.gov.window()
    long = Window(window.lo_slot, window.lo_slot + 3_601, window.lo, window.lo + 3_601_000)
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_proposal(alice.address, lock, window=long)


@requires_aiken
def test_validators_reject_a_second_node_of_an_agent(gw: GovWorld, alice: GovAgent, monkeypatch) -> None:
    propose(gw, alice, "one")
    gw.advance(DAY_S + 120)
    lock = run(gw, lock_proposal(gw, alice, "two"))[0]
    real = gw.gov_ctx.activity_list()
    stale = ActivityList(Position(real.head.utxo, ActivityDatum(b"", real.head.datum.agent_credential, 0, 0, b"")))
    monkeypatch.setattr(gw.gov_ctx, "activity_list", lambda: stale)
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_proposal(alice.address, lock)


@requires_aiken
def test_validators_reject_a_missing_ancestor(gw: GovWorld, monkeypatch) -> None:
    parent = gw.agent("parent")
    child = gw.agent("child", parent=parent.id)
    lock = run(gw, lock_proposal(gw, child))[0]
    chain = gw.gov_ctx.record_chain(child.id)
    monkeypatch.setattr(gw.gov_ctx, "record_chain", lambda agent: chain[:1])
    monkeypatch.setattr(builders_module, "require_active", lambda *args: None)
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_proposal(child.address, lock)


@requires_aiken
def test_validators_reject_an_inactive_agent(gw: GovWorld, alice: GovAgent, monkeypatch) -> None:
    lock = run(gw, lock_proposal(gw, alice))[0]
    gw.replace_record(alice, suspended(gw.record_datum(alice.key)))
    monkeypatch.setattr(builders_module, "require_active", lambda *args: None)
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_proposal(alice.address, lock)


@requires_aiken
def test_validators_reject_an_endorsement_without_the_proposer_record(
    gw: GovWorld, alice: GovAgent, carol: GovAgent, monkeypatch
) -> None:
    seed, _ = propose(gw, alice)
    lock = run(gw, gw.gov.lock_endorsement(carol.address, endorser=carol.did, proposal_seed=seed))[0]
    own = gw.gov_ctx.record(carol.id)
    monkeypatch.setattr(gw.gov_ctx, "record", lambda agent: own)
    monkeypatch.setattr(builders_module, "check_distinct_parties", lambda *args: None)
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_endorsement(carol.address, lock)


@requires_aiken
def test_validators_reject_a_supportive_critique_of_the_proposer(gw: GovWorld, alice: GovAgent, monkeypatch) -> None:
    seed, _ = propose(gw, alice)
    monkeypatch.setattr(builders_module, "check_critique", lambda *args: None)
    monkeypatch.setattr(builders_module, "check_distinct_parties", lambda *args: None)
    lock = gw.gov.lock_critique(
        alice.address, critic=alice.did, proposal_seed=seed, critique_hash=blake2b_256(b"c"), storage_uri="ipfs://c"
    )
    locked = run(gw, lock)[0]
    with pytest.raises(TransactionError, match="failed script execution"):
        gw.gov.submit_critique(alice.address, locked)


def test_token_names_of_created_positions(gw: GovWorld, alice: GovAgent, bob: GovAgent) -> None:
    seed, proposal = propose(gw, alice)
    position = gw.gov_ctx.proposal(proposal)
    assert position.token == proposal_token_name(seed)
    tokens = gw.utxo(proposal).output.amount.multi_asset[ScriptHash(gw.gov_scripts.proposal_mint.hash)]
    assert dict(tokens) == {AssetName(proposal_token_name(seed)): 1}
    node = gw.gov_ctx.activity_list().node(alice.id)
    assert node.token == activity_token_name(alice.id)
    review = critique(gw, bob, seed)
    assert gw.gov_ctx.critique(review).token is not None
