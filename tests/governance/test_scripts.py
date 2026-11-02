"""The embedded Module-6 blueprint and the parameter application.

The expected applied hashes and sizes come from ``aiken blueprint apply``
(Aiken v1.1.21+42babe5) on the blueprint of vector-agent-modules ``91e3823``
with the parameter CBOR of ``Module-6/scripts/deploy_common.py``
(``build_governance_config_cbor``: a definite array) for the configuration below.
The sizes equal the applied sizes of the W4 module reports.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from importlib import resources

import pytest

from vector_agent.governance import GovernanceConfig, GovernanceScripts
from vector_agent.governance.scripts import (
    GOVERNANCE_BLUEPRINT,
    GOVERNANCE_BLUEPRINT_SHA256,
    VALIDATOR_TITLES,
    blueprint_bytes,
    unapplied_code,
)
from vector_agent.identity.flat import apply_parameters, plutus_v3_script_hash

from .world import AIKEN

h = bytes.fromhex
CONFIG = GovernanceConfig(
    refs_token_policy=h("7b" * 28),
    prediction_validator_hash=bytes(28),
    reputation_validator_hash=bytes(28),
    jury_pool_hash=bytes(28),
    governance_oracle_hash=h("4b" * 28),
    governance_params_hash=h("4a" * 28),
    governance_treasury_hash=h("4c" * 28),
    credibility_pool_hash=bytes(28),
    protocol_params_hash=bytes(28),
    record_token_policy=h("7a" * 28),
    identity_hash=h("1d" * 28),
)

#: aiken blueprint apply with CONFIG.parameter_cbor().
APPLIED = {
    "proposal_spend": ("d9ad265a917c8139bb561142b667a476226d797ed1f317791a010e4c", 13_699),
    "proposal_mint": ("15fea7325b650deac9c6d820ae6d9d302e244457b52bae13f66dd205", 1_484),
    "critique_spend": ("f124058e64f6777be27f066138b8e600f6ab50d398b78a527be128ef", 9_018),
    "critique_mint": ("98d8eadc310ec6abab3ff683c23364c7ef6dca0d38583f266b89bb62", 2_140),
    "endorsement_spend": ("db3a0c602537729de4c449be496665c559b485befe83a7b1e46f251f", 7_547),
}


def test_embedded_blueprint_is_the_pinned_copy() -> None:
    raw = resources.files("vector_agent.governance").joinpath("blueprints", GOVERNANCE_BLUEPRINT).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == GOVERNANCE_BLUEPRINT_SHA256 == (
        "6560ff0c79fc5205cf54c2a76b58322d0ed7eb9aea6d6b5e3b324c46f2e88be1"
    )
    blueprint = json.loads(blueprint_bytes())
    assert blueprint["preamble"]["compiler"]["version"] == "v1.1.21+42babe5"
    assert blueprint["preamble"]["plutusVersion"] == "v3"


def test_every_validator_matches_its_blueprint_hash() -> None:
    blueprint = json.loads(blueprint_bytes())
    for validator in blueprint["validators"]:
        assert plutus_v3_script_hash(unapplied_code(validator["title"])).hex() == validator["hash"]
        if validator["title"] in VALIDATOR_TITLES.values():
            assert [p["title"] for p in validator["parameters"]] == ["config"]
    with pytest.raises(KeyError):
        unapplied_code("registry.registry.mint")


def test_parameters_apply_like_the_deploy_script() -> None:
    scripts = GovernanceScripts.derive(CONFIG)
    for name, (expected, size) in APPLIED.items():
        info = scripts.by_name(name)
        assert (info.hash_hex, len(info.code)) == (expected, size), name
    refs = scripts.cross_refs
    assert refs.proposal_validator_hash == scripts.proposal_spend.hash
    assert refs.endorsement_validator_hash == scripts.endorsement_spend.hash
    assert str(scripts.proposal_spend.address).startswith("addr1w")


def test_the_indefinite_parameter_form_gives_other_scripts() -> None:
    """``aiken blueprint apply`` keeps the CBOR form of the parameter, so the
    canonical form of ``to_cbor`` names other scripts than the deployed ones."""
    code = apply_parameters(unapplied_code(VALIDATOR_TITLES["proposal_spend"]), [CONFIG.to_data()])
    assert plutus_v3_script_hash(code).hex() != APPLIED["proposal_spend"][0]


@pytest.mark.skipif(AIKEN is None, reason="aiken is not on PATH")
def test_aiken_blueprint_apply_gives_the_same_scripts(tmp_path) -> None:
    blueprint = tmp_path / "plutus.json"
    blueprint.write_bytes(blueprint_bytes())
    scripts = GovernanceScripts.derive(CONFIG)
    for name, title in VALIDATOR_TITLES.items():
        module, validator, _ = title.split(".")
        out = tmp_path / f"{name}.json"
        subprocess.run(
            [
                AIKEN, "blueprint", "apply", "-i", str(blueprint), "-m", module, "-v", validator,
                "-o", str(out), CONFIG.parameter_cbor().hex(),
            ],
            check=True,
            capture_output=True,
        )
        applied = next(v for v in json.loads(out.read_text())["validators"] if v["title"] == title)
        assert applied["compiledCode"] == scripts.by_name(name).code.hex(), name
