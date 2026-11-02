"""Module-6 deployment values from the environment and from a deploy state."""

from __future__ import annotations

import json

import pytest

from vector_agent.governance import ENV_VARS, GovernanceConfigError, GovernanceDeployment
from vector_agent.governance.scripts import VALIDATOR_TITLES
from vector_agent.identity.constants import LEGACY_REGISTRY_HASH
from vector_agent.identity.types import OutputReference

from .test_scripts import APPLIED, CONFIG

REQUIRED_ENV = {
    "VECTOR_MODULE6_IDENTITY_HASH": "1d" * 28,
    "VECTOR_MODULE6_RECORD_TOKEN_POLICY": "7a" * 28,
    "VECTOR_MODULE6_REFS_TOKEN_POLICY": "7b" * 28,
    "VECTOR_MODULE6_ORACLE_HOLDER_HASH": "4b" * 28,
    "VECTOR_MODULE6_PARAMS_HOLDER_HASH": "4a" * 28,
    "VECTOR_MODULE6_TREASURY_HOLDER_HASH": "4c" * 28,
}


def deploy_state(**changes) -> dict:
    """A deploy state as Module-6/scripts/deploy.py writes it."""
    state = {
        "network": "vector-mainnet",
        "identity_hash": "1d" * 28,
        "record_token_policy": "7a" * 28,
        "refs_token_policy": "7b" * 28,
        "holders": {name: {"hash": value * 28} for name, value in (("params", "4a"), ("oracle", "4b"), ("treasury", "4c"))},
        "validators": {title: {"hash": APPLIED[name][0], "compiled_code": ""} for name, title in VALIDATOR_TITLES.items()},
        "tx_hashes": {f"{name}_ref": f"{i:02x}" * 32 for i, name in enumerate(VALIDATOR_TITLES, 0xE1)},
    }
    state.update(changes)
    return state


def test_deploy_state_gives_the_configuration_and_the_reference_scripts() -> None:
    deployment = GovernanceDeployment.from_deploy_state(deploy_state())
    assert deployment.config() == CONFIG
    assert deployment.scripts().proposal_spend.hash_hex == APPLIED["proposal_spend"][0]
    assert deployment.reference("proposal_spend") == OutputReference(bytes([0xE1]) * 32, 0)
    assert deployment.reference("endorsement_spend") == OutputReference(bytes([0xE5]) * 32, 0)


def test_deploy_state_file(tmp_path) -> None:
    path = tmp_path / "deploy_state.json"
    path.write_text(json.dumps(deploy_state()))
    assert GovernanceDeployment.from_deploy_state(path).config() == CONFIG
    env = {"VECTOR_MODULE6_DEPLOY_STATE": str(path), "VECTOR_MODULE6_PARAMS_UTXO": f"{'aa' * 32}#2"}
    deployment = GovernanceDeployment.from_env(env)
    assert deployment.config() == CONFIG and deployment.params_utxo == OutputReference(bytes([0xAA]) * 32, 2)


def test_a_state_of_the_old_deployment_is_refused() -> None:
    state = deploy_state()
    del state["identity_hash"]
    with pytest.raises(GovernanceConfigError, match="legacy agent registry"):
        GovernanceDeployment.from_deploy_state(state)


def test_validator_hashes_of_another_blueprint_are_refused() -> None:
    state = deploy_state()
    state["validators"][VALIDATOR_TITLES["critique_mint"]]["hash"] = "00" * 28
    deployment = GovernanceDeployment.from_deploy_state(state)
    with pytest.raises(GovernanceConfigError, match="critique_mint"):
        deployment.scripts()


def test_environment_values() -> None:
    env = {
        **REQUIRED_ENV,
        "VECTOR_MODULE6_PROPOSAL_SPEND_HASH": APPLIED["proposal_spend"][0],
        "VECTOR_MODULE6_PROPOSAL_MINT_REF_UTXO": f"{'0c' * 32}#1",
        "VECTOR_MODULE6_CROSSREFS_UTXO": f"{'0d' * 32}#0",
    }
    deployment = GovernanceDeployment.from_env(env)
    assert deployment.config() == CONFIG
    assert deployment.scripts().proposal_spend.hash_hex == APPLIED["proposal_spend"][0]
    assert deployment.proposal_mint_ref == OutputReference(bytes([0x0C]) * 32, 1)
    assert deployment.cross_refs_utxo == OutputReference(bytes([0x0D]) * 32, 0)
    assert set(env) <= set(ENV_VARS.values())


def test_missing_values_name_the_variables() -> None:
    env = dict(REQUIRED_ENV)
    del env["VECTOR_MODULE6_IDENTITY_HASH"], env["VECTOR_MODULE6_REFS_TOKEN_POLICY"]
    with pytest.raises(GovernanceConfigError, match="VECTOR_MODULE6_IDENTITY_HASH, VECTOR_MODULE6_REFS_TOKEN_POLICY"):
        GovernanceDeployment.from_env(env).config()
    with pytest.raises(GovernanceConfigError, match="missing Module-6 deployment values"):
        GovernanceDeployment.from_env({}).scripts()


@pytest.mark.parametrize(
    ("variable", "value", "message"),
    [
        ("VECTOR_MODULE6_IDENTITY_HASH", "00" * 28, "all zero"),
        ("VECTOR_MODULE6_IDENTITY_HASH", LEGACY_REGISTRY_HASH, "legacy agent registry hash"),
        ("VECTOR_MODULE6_RECORD_TOKEN_POLICY", "00" * 28, "all zero"),
    ],
)
def test_refused_values(variable: str, value: str, message: str) -> None:
    with pytest.raises(GovernanceConfigError, match=message):
        GovernanceDeployment.from_env({**REQUIRED_ENV, variable: value}).config()


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("VECTOR_MODULE6_IDENTITY_HASH", "1d" * 27),
        ("VECTOR_MODULE6_ORACLE_HOLDER_HASH", "zz" * 28),
        ("VECTOR_MODULE6_PARAMS_UTXO", "aa" * 32),
    ],
)
def test_malformed_values(variable: str, value: str) -> None:
    with pytest.raises(GovernanceConfigError, match=variable):
        GovernanceDeployment.from_env({**REQUIRED_ENV, variable: value})


def test_keyword_values_win_and_unknown_keywords_fail() -> None:
    deployment = GovernanceDeployment.from_env(REQUIRED_ENV, identity_hash=bytes([0x1E]) * 28)
    assert deployment.config().identity_hash == bytes([0x1E]) * 28
    with pytest.raises(TypeError, match="unknown deployment fields"):
        GovernanceDeployment.from_env(REQUIRED_ENV, identity=bytes(28))
