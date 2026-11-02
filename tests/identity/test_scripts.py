"""Embedded scripts, their checksums and parameter application.

The expected applied hashes come from ``aiken blueprint apply`` (Aiken
v1.1.21+42babe5) on the blueprint of agents-marketplace ``b5d66a6`` with the
parameters below, applied in blueprint order.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from importlib import resources

import pytest

from vector_agent.identity import IdentityScripts, OutputReference
from vector_agent.identity.constants import LEGACY_REGISTRY_ADDRESS, LEGACY_REGISTRY_HASH
from vector_agent.identity.flat import FlatError, apply_parameter, apply_parameters, plutus_v3_script_hash
from vector_agent.identity.scripts import (
    IDENTITY_BLUEPRINT,
    IDENTITY_BLUEPRINT_SHA256,
    LEGACY_BLUEPRINT,
    LEGACY_BLUEPRINT_SHA256,
    blueprint_bytes,
    unapplied_code,
)

from .world import AIKEN, ALWAYS_OK_V3

SEED = OutputReference(bytes([0x5E]) * 32, 3)
ROOT = bytes([0x7A]) * 32

#: aiken blueprint apply results for SEED, ROOT and the legacy hash.
APPLIED = {
    "config_holder": "288fea77a0f674c6080aadd8ed3ca42cd5a920bf1f00c0d3e63306e4",
    "config_seal": "366f8e7d78edc8f43c2fda8ceb006cc3981c6a7b35a5231e50edb220",
    "identity": "9e7f343b3f839d7251c55572825bda96dbb19da3197d5f48d0f737bc",
    "attestation": "5e0dccff7320d0697e1c762d30b9639befe6cf50c0dcce7f2398823c",
    "delegation": "964ddf0fb625e467cac2cd5d2ab26496a4741f1ca3f02b8b8f3fb2fe",
    "escrow": "3860ac5d54d7d1c624ffd6e612fd8b7629a50bd5a4f15df340a8475d",
    "vault": "2842a4947321a85832177fec3b8a70b5b62c7285362c37d60e161bd0",
    "advert": "f36e366e06d4480651aa0e1064578f0bfe275af96dfcaaabe5efe26c",
}
APPLIED_SIZES = {"identity": 13_699, "attestation": 7_234, "delegation": 7_081, "escrow": 5_915, "vault": 6_932}


def test_embedded_blueprints_are_the_pinned_copies() -> None:
    package = resources.files("vector_agent.identity").joinpath("blueprints")
    for name, digest in ((IDENTITY_BLUEPRINT, IDENTITY_BLUEPRINT_SHA256), (LEGACY_BLUEPRINT, LEGACY_BLUEPRINT_SHA256)):
        assert hashlib.sha256(package.joinpath(name).read_bytes()).hexdigest() == digest
        assert blueprint_bytes(name)


def test_every_validator_matches_its_blueprint_hash() -> None:
    blueprint = json.loads(blueprint_bytes(IDENTITY_BLUEPRINT))
    assert blueprint["preamble"]["compiler"]["version"] == "v1.1.21+42babe5"
    titles = [v["title"] for v in blueprint["validators"]]
    assert len(titles) == 19
    for title in titles:
        assert plutus_v3_script_hash(unapplied_code(title)).hex() == next(
            v["hash"] for v in blueprint["validators"] if v["title"] == title
        )


def test_legacy_registry_script() -> None:
    code = unapplied_code("registry.registry.mint", blueprint=LEGACY_BLUEPRINT)
    assert plutus_v3_script_hash(code).hex() == LEGACY_REGISTRY_HASH
    scripts = IdentityScripts.derive(legacy_hash=bytes.fromhex(LEGACY_REGISTRY_HASH), legacy_root=ROOT, config_seed=SEED)
    assert str(scripts.legacy.address) == LEGACY_REGISTRY_ADDRESS


def test_parameters_apply_like_aiken() -> None:
    scripts = IdentityScripts.derive(legacy_hash=bytes.fromhex(LEGACY_REGISTRY_HASH), legacy_root=ROOT, config_seed=SEED)
    for name, expected in APPLIED.items():
        assert getattr(scripts, name).hash_hex == expected, name
    for name, size in APPLIED_SIZES.items():
        assert len(getattr(scripts, name).code) == size, name
    assert scripts.config_policy.hex() == APPLIED["config_seal"]
    assert str(scripts.identity.address).startswith("addr1w")


def test_another_legacy_hash_has_no_embedded_legacy_script() -> None:
    scripts = IdentityScripts.derive(legacy_hash=bytes(28), legacy_root=ROOT, config_seed=SEED)
    assert scripts.legacy is None
    assert scripts.identity.hash_hex != APPLIED["identity"]


def test_apply_rejects_malformed_code() -> None:
    with pytest.raises(FlatError):
        apply_parameter(bytes.fromhex("4401010000"), 0)
    with pytest.raises(FlatError):
        apply_parameter(b"\x01\x02", 0)
    with pytest.raises(FlatError):
        apply_parameter(bytes.fromhex("450101002499") + b"\x00", 0)


@pytest.mark.skipif(AIKEN is None, reason="aiken is not on PATH")
def test_a_large_parameter_decodes_with_aiken(tmp_path) -> None:
    code = apply_parameters(ALWAYS_OK_V3, [[bytes(range(256)), bytes(range(100))]])
    path = tmp_path / "applied.hex"
    path.write_text(code.hex())
    text = subprocess.run(
        [AIKEN, "uplc", "decode", str(path), "--cbor", "--hex"], capture_output=True, text=True, check=True
    ).stdout
    assert "(lam i_0 (con unit ()))" in text
    assert "B #" + bytes(range(256)).hex() in text and "B #" + bytes(range(100)).hex() in text
