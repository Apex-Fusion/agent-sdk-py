"""Embedded scripts and the script set of one deployment.

The package embeds two CIP-57 blueprints as byte copies:

- ``blueprints/identity-marketplace.plutus.json``: Apex-Fusion/agents-marketplace
  ``contracts/identity-marketplace/plutus.json`` at commit ``1643583`` (the file
  last changed in ``48312ff``; git blob ``9cf2bb0b``, sha256
  :data:`IDENTITY_BLUEPRINT_SHA256`). Its validators are unapplied: their
  parameters are deployment values (Part 2 §2).
- ``blueprints/legacy-registry.plutus.json``: the deployed legacy registry
  (Apex-Fusion/vector-ai-agents ``f6ae4bb`` ``agent-registry/deploy/agent-registry/plutus.json``,
  git blob ``4c79883e``, sha256 :data:`LEGACY_BLUEPRINT_SHA256`), which an
  adoption runs.

:meth:`IdentityScripts.derive` applies the deployment values in the order of
the blueprint parameters (Part 2 §2, §3.8):

- ``config_seal(seed, config_holder)``: the configuration policy;
- ``identity(legacy_hash, legacy_root, config_policy, config_holder)``;
- ``attestation(identity_hash)``, ``delegation(identity_hash)``,
  ``escrow(identity_hash)``;
- ``vault(identity_hash, delegation_hash, escrow_hash)``.

``config_holder`` and ``advert`` have no parameters.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib import resources

from pycardano import Address, Network, PlutusV3Script, ScriptHash

from vector_agent.identity.flat import apply_parameters, plutus_v3_script_hash
from vector_agent.identity.types import OutputReference

__all__ = [
    "IDENTITY_BLUEPRINT_SHA256",
    "LEGACY_BLUEPRINT_SHA256",
    "IdentityScripts",
    "ScriptInfo",
    "blueprint_bytes",
    "enterprise_address",
    "unapplied_code",
]

IDENTITY_BLUEPRINT = "identity-marketplace.plutus.json"
LEGACY_BLUEPRINT = "legacy-registry.plutus.json"
IDENTITY_BLUEPRINT_SHA256 = "9c8d948a2da12fa519b6f97286cbb8374c002b6bca7e4a3ef1a6d65cca51df3e"
LEGACY_BLUEPRINT_SHA256 = "00eb21bf150b9f4ee4ded0b7a7c4779d91284cf795bde653d5702355520ad215"

_CHECKSUMS = {IDENTITY_BLUEPRINT: IDENTITY_BLUEPRINT_SHA256, LEGACY_BLUEPRINT: LEGACY_BLUEPRINT_SHA256}

#: Blueprint titles and parameter counts of the validators that the SDK uses.
_TITLES = {
    "config_holder": ("config.config_holder.spend", 0),
    "config_seal": ("config.config_seal.mint", 2),
    "identity": ("identity.identity.mint", 4),
    "attestation": ("attestation.attestation.mint", 1),
    "delegation": ("delegation.delegation.mint", 1),
    "escrow": ("escrow.escrow.spend", 1),
    "vault": ("vault.vault.spend", 3),
    "advert": ("advert.advert.spend", 0),
}


@cache
def blueprint_bytes(name: str = IDENTITY_BLUEPRINT) -> bytes:
    """The embedded blueprint file; fails when its sha256 is not the pinned value."""
    raw = resources.files("vector_agent.identity").joinpath("blueprints", name).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != _CHECKSUMS[name]:
        raise RuntimeError(f"embedded blueprint {name} has sha256 {digest}, expected {_CHECKSUMS[name]}")
    return raw


@cache
def _validators(name: str) -> dict:
    return {v["title"]: v for v in json.loads(blueprint_bytes(name))["validators"]}


def unapplied_code(title: str, *, blueprint: str = IDENTITY_BLUEPRINT) -> bytes:
    """The compiled code of ``title``; fails when it does not hash to the blueprint hash."""
    validator = _validators(blueprint).get(title)
    if validator is None:
        raise KeyError(f"blueprint {blueprint} has no validator {title}")
    code = bytes.fromhex(validator["compiledCode"])
    if plutus_v3_script_hash(code).hex() != validator["hash"]:
        raise RuntimeError(f"the code of {title} does not match its blueprint hash")
    return code


def enterprise_address(script_hash: bytes) -> Address:
    """The enterprise address of a script: the script as payment credential, no stake."""
    return Address(payment_part=ScriptHash(script_hash), network=Network.MAINNET)


@dataclass(frozen=True)
class ScriptInfo:
    """One applied Plutus V3 script."""

    name: str
    code: bytes

    @property
    def hash(self) -> bytes:
        return plutus_v3_script_hash(self.code)

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()

    @property
    def address(self) -> Address:
        return enterprise_address(self.hash)

    @property
    def plutus_script(self) -> PlutusV3Script:
        return PlutusV3Script(self.code)


@dataclass(frozen=True)
class IdentityScripts:
    """The applied scripts of one identity-registry deployment."""

    legacy_hash: bytes
    legacy_root: bytes
    config_seed: OutputReference
    config_holder: ScriptInfo
    config_seal: ScriptInfo
    identity: ScriptInfo
    attestation: ScriptInfo
    delegation: ScriptInfo
    escrow: ScriptInfo
    vault: ScriptInfo
    advert: ScriptInfo
    #: The deployed legacy registry script; None when ``legacy_hash`` is another hash.
    legacy: ScriptInfo | None

    @property
    def config_policy(self) -> bytes:
        return self.config_seal.hash

    @classmethod
    def derive(
        cls, *, legacy_hash: bytes, legacy_root: bytes, config_seed: OutputReference
    ) -> IdentityScripts:
        """Apply the deployment values to the embedded unapplied scripts."""
        return _derive(bytes(legacy_hash), bytes(legacy_root), config_seed)


@lru_cache(maxsize=8)
def _derive(legacy_hash: bytes, legacy_root: bytes, config_seed: OutputReference) -> IdentityScripts:
    if len(legacy_hash) != 28:
        raise ValueError("legacy_hash must be 28 bytes")
    if len(legacy_root) != 32:
        raise ValueError("legacy_root must be 32 bytes")

    def applied(name: str, parameters: list) -> ScriptInfo:
        title, count = _TITLES[name]
        if len(parameters) != count:
            raise ValueError(f"{name} takes {count} parameters")
        return ScriptInfo(name, apply_parameters(unapplied_code(title), parameters))

    holder = applied("config_holder", [])
    seal = applied("config_seal", [config_seed.to_data(), holder.hash])
    identity = applied("identity", [legacy_hash, legacy_root, seal.hash, holder.hash])
    delegation = applied("delegation", [identity.hash])
    escrow = applied("escrow", [identity.hash])
    legacy_code = unapplied_code("registry.registry.mint", blueprint=LEGACY_BLUEPRINT)
    legacy = ScriptInfo("legacy", legacy_code)
    if legacy.hash != legacy_hash:
        legacy = None  # the embedded legacy script serves only its own hash
    return IdentityScripts(
        legacy_hash=legacy_hash,
        legacy_root=legacy_root,
        config_seed=config_seed,
        config_holder=holder,
        config_seal=seal,
        identity=identity,
        attestation=applied("attestation", [identity.hash]),
        delegation=delegation,
        escrow=escrow,
        vault=applied("vault", [identity.hash, delegation.hash, escrow.hash]),
        advert=applied("advert", []),
        legacy=legacy,
    )
