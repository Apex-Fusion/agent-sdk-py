"""Deployment values from the environment (``IdentityConfig``)."""

from __future__ import annotations

import pytest

from vector_agent.identity import ENV_VARS, IdentityConfig, IdentityConfigError, OutputReference
from vector_agent.identity.constants import DEFAULT_GATEWAY_URL, DEFAULT_KOIOS_URL, LEGACY_REGISTRY_HASH

ROOT = "7a" * 32
SEED = "5e" * 32 + "#3"
IDENTITY = "7bbdcb5025b366b4c1eda77bf9eee556246e7d8f7a4b1b9127f0e00c"


def test_defaults_and_missing_values() -> None:
    config = IdentityConfig.from_env({})
    assert config.gateway_url == DEFAULT_GATEWAY_URL and config.koios_url == DEFAULT_KOIOS_URL
    assert config.legacy_hash.hex() == LEGACY_REGISTRY_HASH
    with pytest.raises(IdentityConfigError) as error:
        config.scripts()
    assert "VECTOR_IDENTITY_LEGACY_ROOT" in str(error.value) and "VECTOR_IDENTITY_CONFIG_SEED" in str(error.value)


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
        "VECTOR_IDENTITY_LEGACY_ROOT",
        "VECTOR_IDENTITY_CONFIG_SEED",
        "VECTOR_ATTESTATION_REF_UTXO",
        "VECTOR_DELEGATION_REF_UTXO",
        "VECTOR_VAULT_REF_UTXO",
        "VECTOR_MODULE1_REF_UTXO",
    }
