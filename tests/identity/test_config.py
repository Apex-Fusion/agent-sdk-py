"""Deployment values from the environment (``IdentityConfig``).

``fixtures/deploy/mainnet/deployment.json`` is a byte copy of
``Apex-Fusion/agents-marketplace`` ``contracts/identity-marketplace/deploy/mainnet/deployment.json``
at commit ``4c95c3f`` (git blob ``4df45d5db70939103963a6605cfdde6ac1cc4f37``): the
published record of the identity deployment on Vector mainnet. The test pins it by
sha256 (:data:`MAINNET_DEPLOYMENT_SHA256`).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vector_agent.identity import (
    ENV_VARS,
    MAINNET_IDENTITY_DEPLOYMENT,
    IdentityConfig,
    IdentityConfigError,
    OutputReference,
    PublishedDeployment,
)
from vector_agent.identity.constants import DEFAULT_GATEWAY_URL, DEFAULT_KOIOS_URL, LEGACY_REGISTRY_HASH

ROOT = "7a" * 32
SEED = "5e" * 32 + "#3"
IDENTITY = "7bbdcb5025b366b4c1eda77bf9eee556246e7d8f7a4b1b9127f0e00c"

MAINNET_DEPLOYMENT = Path(__file__).parent / "fixtures" / "deploy" / "mainnet" / "deployment.json"
MAINNET_DEPLOYMENT_SHA256 = "5d9fab437aff5cef9e3fedf85f696c5ff0526766503671d715fe69ace8b0c5b5"
#: The eight scripts of a deployment, by their names in ``deployment.json`` and in ``IdentityScripts``.
SCRIPT_NAMES = ("config_holder", "config_seal", "identity", "attestation", "delegation", "escrow", "vault", "advert")


@pytest.fixture(scope="module")
def published() -> dict:
    raw = MAINNET_DEPLOYMENT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == MAINNET_DEPLOYMENT_SHA256
    return json.loads(raw)


def test_endpoint_defaults() -> None:
    config = IdentityConfig.from_env({})
    assert config.gateway_url == DEFAULT_GATEWAY_URL and config.koios_url == DEFAULT_KOIOS_URL
    assert config.legacy_hash.hex() == LEGACY_REGISTRY_HASH


def test_from_env() -> None:
    env = {
        "VECTOR_IDENTITY_LEGACY_ROOT": ROOT,
        "VECTOR_IDENTITY_CONFIG_SEED": SEED,
        "VECTOR_IDENTITY_POLICY_ID": IDENTITY,
        "VECTOR_IDENTITY_REF_UTXO": "ab" * 32 + "#0",
        "VECTOR_IDENTITY_GATEWAY_URL": "https://gateway.example.org/",
        "VECTOR_MARKETPLACE_INDEXER_URL": "https://indexer.example.org",
    }
    config = IdentityConfig.from_env(env)
    assert config.config_seed == OutputReference(bytes([0x5E]) * 32, 3)
    assert config.identity_ref == OutputReference(bytes([0xAB]) * 32, 0)
    assert config.gateway_url == "https://gateway.example.org"
    assert config.scripts().identity.hash_hex == IDENTITY
    assert IdentityConfig.from_env(env, gateway_url="https://other.example.org").gateway_url == "https://other.example.org"


def test_a_wrong_policy_id_is_refused() -> None:
    env = {"VECTOR_IDENTITY_LEGACY_ROOT": ROOT, "VECTOR_IDENTITY_CONFIG_SEED": SEED, "VECTOR_IDENTITY_POLICY_ID": "00" * 28}
    with pytest.raises(IdentityConfigError, match="VECTOR_IDENTITY_POLICY_ID"):
        IdentityConfig.from_env(env).scripts()


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("VECTOR_IDENTITY_LEGACY_ROOT", "7a" * 31),
        ("VECTOR_IDENTITY_LEGACY_ROOT", "zz" * 32),
        ("VECTOR_IDENTITY_CONFIG_SEED", "5e" * 32),
        ("VECTOR_IDENTITY_CONFIG_SEED", "5e" * 32 + "#x"),
        ("VECTOR_IDENTITY_LEGACY_HASH", "be1a"),
        ("VECTOR_VAULT_REF_UTXO", "00#0"),
    ],
)
def test_invalid_values_name_the_variable(variable: str, value: str) -> None:
    with pytest.raises(IdentityConfigError, match=variable):
        IdentityConfig.from_env({variable: value})


def test_unknown_override_and_variable_names() -> None:
    with pytest.raises(TypeError):
        IdentityConfig.from_env({}, unknown=1)
    assert set(ENV_VARS.values()) >= {
        "VECTOR_IDENTITY_NETWORK",
        "VECTOR_IDENTITY_LEGACY_ROOT",
        "VECTOR_IDENTITY_CONFIG_SEED",
        "VECTOR_ATTESTATION_REF_UTXO",
        "VECTOR_DELEGATION_REF_UTXO",
        "VECTOR_VAULT_REF_UTXO",
        "VECTOR_MODULE1_REF_UTXO",
    }


def test_without_settings_the_published_mainnet_deployment_applies(published: dict) -> None:
    deployment = MAINNET_IDENTITY_DEPLOYMENT
    assert published["network"] == "mainnet"
    refs = ("identity", "attestation", "delegation", "vault", "escrow", "advert")
    assert deployment == PublishedDeployment(
        legacy_hash=bytes.fromhex(published["legacy_hash"]),
        legacy_root=bytes.fromhex(published["legacy_root"]),
        config_seed=OutputReference.parse(published["config_seed"]),
        identity_policy_id=bytes.fromhex(published["identity_hash"]),
        **{f"{name}_ref": OutputReference.parse(published["refs"][name]) for name in refs},
    )
    config = IdentityConfig.from_env({})
    assert (config.legacy_hash, config.legacy_root, config.config_seed, config.identity_policy_id) == (
        deployment.legacy_hash,
        deployment.legacy_root,
        deployment.config_seed,
        deployment.identity_policy_id,
    )
    assert (config.identity_ref, config.attestation_ref, config.delegation_ref, config.vault_ref) == (
        deployment.identity_ref,
        deployment.attestation_ref,
        deployment.delegation_ref,
        deployment.vault_ref,
    )
    assert config.legacy_ref is None and config.module1_ref is None and config.config_utxo is None
    # scripts() derives the identity policy ID and compares it with the published one.
    scripts = config.scripts()
    assert sorted(published["scripts"]) == sorted(SCRIPT_NAMES)
    for name in SCRIPT_NAMES:
        script, record = getattr(scripts, name), published["scripts"][name]
        assert script.hash_hex == record["hash"], name
        assert str(script.address) == record["address"], name
        assert script.code.hex() == record["compiled_code"], name


def test_a_set_value_wins_over_a_mainnet_default() -> None:
    deployment = MAINNET_IDENTITY_DEPLOYMENT
    config = IdentityConfig.from_env({"VECTOR_IDENTITY_REF_UTXO": "ab" * 32 + "#0"})
    assert config.identity_ref == OutputReference(bytes([0xAB]) * 32, 0)
    assert config.attestation_ref == deployment.attestation_ref
    assert IdentityConfig.from_env({}, identity_ref=None).identity_ref is None
    # Another root and seed: their own deployment, without the published policy ID and reference outputs.
    own = IdentityConfig.from_env({"VECTOR_IDENTITY_LEGACY_ROOT": ROOT, "VECTOR_IDENTITY_CONFIG_SEED": SEED})
    assert own.scripts().identity.hash_hex == IDENTITY
    assert own.identity_policy_id is None and own.identity_ref is None and own.vault_ref is None
    # The published root and seed, set by hand, give the same configuration as no setting.
    by_hand = {
        "VECTOR_IDENTITY_LEGACY_ROOT": deployment.legacy_root.hex(),
        "VECTOR_IDENTITY_CONFIG_SEED": str(deployment.config_seed),
    }
    assert IdentityConfig.from_env(by_hand) == IdentityConfig.from_env({})
    # The root and the seed come together: one of them alone gets no default for the other.
    with pytest.raises(IdentityConfigError, match=r"missing deployment values: VECTOR_IDENTITY_CONFIG_SEED \("):
        IdentityConfig.from_env({"VECTOR_IDENTITY_LEGACY_ROOT": ROOT}).scripts()
    other = IdentityConfig.from_env({"VECTOR_IDENTITY_LEGACY_HASH": "00" * 28})
    assert other.legacy_root is None and other.config_seed is None and other.identity_ref is None
    # A policy ID that contradicts the published values fails when the scripts are derived.
    with pytest.raises(IdentityConfigError, match="VECTOR_IDENTITY_POLICY_ID is 0{56}, but"):
        IdentityConfig.from_env({"VECTOR_IDENTITY_POLICY_ID": "00" * 28}).scripts()


def test_the_testnet_has_no_deployment_defaults() -> None:
    for config in (
        IdentityConfig.from_env({"VECTOR_IDENTITY_NETWORK": "testnet"}),
        IdentityConfig.from_env({"VECTOR_IDENTITY_NETWORK": "mainnet"}, network="testnet"),
    ):
        assert (config.legacy_root, config.config_seed, config.identity_policy_id) == (None, None, None)
        assert (config.identity_ref, config.attestation_ref, config.delegation_ref, config.vault_ref) == (None,) * 4
        with pytest.raises(IdentityConfigError) as error:
            config.scripts()
        assert "VECTOR_IDENTITY_LEGACY_ROOT" in str(error.value) and "VECTOR_IDENTITY_CONFIG_SEED" in str(error.value)
    env = {"VECTOR_IDENTITY_NETWORK": "testnet", "VECTOR_IDENTITY_LEGACY_ROOT": ROOT, "VECTOR_IDENTITY_CONFIG_SEED": SEED}
    assert IdentityConfig.from_env(env).scripts().identity.hash_hex == IDENTITY
    with pytest.raises(IdentityConfigError, match="VECTOR_IDENTITY_NETWORK: expected mainnet or testnet"):
        IdentityConfig.from_env({"VECTOR_IDENTITY_NETWORK": "preprod"})
