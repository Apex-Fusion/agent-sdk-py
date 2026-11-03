"""The embedded Module-6 blueprint and the scripts of one deployment.

``blueprints/governance-suggestion.plutus.json`` is a byte copy of
Apex-Fusion/vector-agent-modules ``Module-6/contracts/governance-suggestion/plutus.json``
at commit ``91e3823`` (the file last changed in ``9dd049f``; git blob
``6855426c``, sha256 :data:`GOVERNANCE_BLUEPRINT_SHA256`; Aiken v1.1.21). Its
validators are unapplied: their one parameter, ``GovernanceConfig``, holds
deployment values (Part 2 §7 of ``docs/IDENTITY_REGISTRY.md``).

:meth:`GovernanceScripts.derive` applies the configuration to the five
validators that the client uses, as ``aiken blueprint apply`` does with the
CBOR of the Module-6 deploy script (:meth:`GovernanceConfig.parameter_cbor`,
:func:`vector_agent.identity.flat.apply_parameter_cbor`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib import resources

from vector_agent.governance.types import GovernanceConfig, GovernanceCrossRefs
from vector_agent.identity.flat import apply_parameter_cbor, plutus_v3_script_hash
from vector_agent.identity.scripts import ScriptInfo

__all__ = [
    "GOVERNANCE_BLUEPRINT",
    "GOVERNANCE_BLUEPRINT_SHA256",
    "SCRIPT_NAMES",
    "VALIDATOR_TITLES",
    "GovernanceScripts",
    "blueprint_bytes",
    "unapplied_code",
]

GOVERNANCE_BLUEPRINT = "governance-suggestion.plutus.json"
GOVERNANCE_BLUEPRINT_SHA256 = "6560ff0c79fc5205cf54c2a76b58322d0ed7eb9aea6d6b5e3b324c46f2e88be1"

#: Blueprint titles of the validators that the client uses (each takes the ``GovernanceConfig``).
VALIDATOR_TITLES = {
    "proposal_spend": "proposal.proposal_spend.spend",
    "proposal_mint": "proposal.proposal_mint.mint",
    "critique_spend": "critique.critique_spend.spend",
    "critique_mint": "critique.critique_mint.mint",
    "endorsement_spend": "critique.endorsement_spend.spend",
}
SCRIPT_NAMES = tuple(VALIDATOR_TITLES)


@cache
def blueprint_bytes() -> bytes:
    """The embedded blueprint; fails when its sha256 is not the pinned value."""
    raw = resources.files("vector_agent.governance").joinpath("blueprints", GOVERNANCE_BLUEPRINT).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != GOVERNANCE_BLUEPRINT_SHA256:
        raise RuntimeError(
            f"embedded blueprint {GOVERNANCE_BLUEPRINT} has sha256 {digest}, expected {GOVERNANCE_BLUEPRINT_SHA256}"
        )
    return raw


@cache
def _validators() -> dict:
    return {v["title"]: v for v in json.loads(blueprint_bytes())["validators"]}


def unapplied_code(title: str) -> bytes:
    """The compiled code of ``title``; fails when it does not hash to the blueprint hash."""
    validator = _validators().get(title)
    if validator is None:
        raise KeyError(f"blueprint {GOVERNANCE_BLUEPRINT} has no validator {title}")
    code = bytes.fromhex(validator["compiledCode"])
    if plutus_v3_script_hash(code).hex() != validator["hash"]:
        raise RuntimeError(f"the code of {title} does not match its blueprint hash")
    return code


@dataclass(frozen=True)
class GovernanceScripts:
    """The five applied validators of one Module-6 deployment."""

    config: GovernanceConfig
    proposal_spend: ScriptInfo
    proposal_mint: ScriptInfo
    critique_spend: ScriptInfo
    critique_mint: ScriptInfo
    endorsement_spend: ScriptInfo

    @classmethod
    def derive(cls, config: GovernanceConfig) -> GovernanceScripts:
        """Apply ``config`` to the embedded unapplied validators."""
        return _derive(config)

    @property
    def cross_refs(self) -> GovernanceCrossRefs:
        """The ``GovernanceCrossRefs`` datum that names these validators."""
        return GovernanceCrossRefs(
            self.proposal_spend.hash,
            self.critique_spend.hash,
            self.proposal_mint.hash,
            self.critique_mint.hash,
            self.endorsement_spend.hash,
        )

    def by_name(self, name: str) -> ScriptInfo:
        if name not in VALIDATOR_TITLES:
            raise KeyError(f"unknown Module-6 script {name!r}; expected one of {', '.join(SCRIPT_NAMES)}")
        return getattr(self, name)


@lru_cache(maxsize=8)
def _derive(config: GovernanceConfig) -> GovernanceScripts:
    parameter = config.parameter_cbor()
    applied = {
        name: ScriptInfo(name, apply_parameter_cbor(unapplied_code(title), parameter))
        for name, title in VALIDATOR_TITLES.items()
    }
    return GovernanceScripts(config=config, **applied)
