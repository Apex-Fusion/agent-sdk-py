"""Deployment values of the identity registry.

The script parameters are deployment values (Part 2 §2): the SDK takes them
from configuration and applies them to the embedded unapplied scripts
(:mod:`vector_agent.identity.scripts`). Two values are free:

- ``VECTOR_IDENTITY_LEGACY_ROOT``: the allowlist Merkle root (Part 2 §3.4);
- ``VECTOR_IDENTITY_CONFIG_SEED``: the seed of ``config_seal`` (Part 2 §3.8),
  as ``<tx id>#<index>``.

Every other script hash follows from them. ``VECTOR_IDENTITY_POLICY_ID``,
when set, must equal the derived identity policy ID; a mismatch means a wrong
deployment value.

Reference-script UTxOs (``<tx id>#<index>``) are optional. Without one, a
transaction carries the script itself, which can exceed the size limit
(the identity script has 13.7 KB).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace

from vector_agent.identity.constants import (
    DEFAULT_GATEWAY_URL,
    DEFAULT_KOIOS_URL,
    DEFAULT_OGMIOS_URL,
    LEGACY_REGISTRY_HASH,
)
from vector_agent.identity.errors import IdentityConfigError
from vector_agent.identity.scripts import IdentityScripts
from vector_agent.identity.types import OutputReference

__all__ = ["ENV_VARS", "IdentityConfig", "IdentityConfigError"]


#: Environment variable of each configuration field.
ENV_VARS: Mapping[str, str] = {
    "legacy_root": "VECTOR_IDENTITY_LEGACY_ROOT",
    "config_seed": "VECTOR_IDENTITY_CONFIG_SEED",
    "legacy_hash": "VECTOR_IDENTITY_LEGACY_HASH",
    "identity_policy_id": "VECTOR_IDENTITY_POLICY_ID",
    "identity_ref": "VECTOR_IDENTITY_REF_UTXO",
    "attestation_ref": "VECTOR_ATTESTATION_REF_UTXO",
    "delegation_ref": "VECTOR_DELEGATION_REF_UTXO",
    "vault_ref": "VECTOR_VAULT_REF_UTXO",
    "legacy_ref": "VECTOR_LEGACY_REGISTRY_REF_UTXO",
    "module1_ref": "VECTOR_MODULE1_REF_UTXO",
    "config_utxo": "VECTOR_IDENTITY_CONFIG_UTXO",
    "gateway_url": "VECTOR_IDENTITY_GATEWAY_URL",
    "ogmios_url": "VECTOR_OGMIOS_URL",
    "koios_url": "VECTOR_KOIOS_URL",
    "koios_token": "VECTOR_KOIOS_TOKEN",
    "indexer_url": "VECTOR_MARKETPLACE_INDEXER_URL",
}

_REFS = (
    "config_seed",
    "identity_ref",
    "attestation_ref",
    "delegation_ref",
    "vault_ref",
    "legacy_ref",
    "module1_ref",
    "config_utxo",
)


def _hex(name: str, value: str, size: int) -> bytes:
    text = value.strip().lower()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raw = b""
    if len(raw) != size or len(text) != 2 * size:
        raise IdentityConfigError(f"{ENV_VARS[name]}: expected {2 * size} hexadecimal characters")
    return raw


def _ref(name: str, value: str) -> OutputReference:
    try:
        return OutputReference.parse(value.lower())
    except ValueError:
        raise IdentityConfigError(f"{ENV_VARS[name]}: expected <tx id>#<index>") from None


@dataclass(frozen=True)
class IdentityConfig:
    """Deployment values and endpoints. Build it with :meth:`from_env` or directly."""

    legacy_root: bytes | None = None
    config_seed: OutputReference | None = None
    legacy_hash: bytes = field(default_factory=lambda: bytes.fromhex(LEGACY_REGISTRY_HASH))
    identity_policy_id: bytes | None = None
    identity_ref: OutputReference | None = None
    attestation_ref: OutputReference | None = None
    delegation_ref: OutputReference | None = None
    vault_ref: OutputReference | None = None
    legacy_ref: OutputReference | None = None
    module1_ref: OutputReference | None = None
    config_utxo: OutputReference | None = None
    gateway_url: str = DEFAULT_GATEWAY_URL
    ogmios_url: str = DEFAULT_OGMIOS_URL
    koios_url: str = DEFAULT_KOIOS_URL
    koios_token: str | None = None
    indexer_url: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides) -> IdentityConfig:
        """Read the variables of :data:`ENV_VARS`; keyword arguments win over them."""
        source = os.environ if env is None else env
        values: dict = {}
        for name, variable in ENV_VARS.items():
            raw = source.get(variable, "").strip()
            if not raw:
                continue
            if name in ("legacy_root",):
                values[name] = _hex(name, raw, 32)
            elif name in ("legacy_hash", "identity_policy_id"):
                values[name] = _hex(name, raw, 28)
            elif name in _REFS:
                values[name] = _ref(name, raw)
            elif name.endswith("_url"):
                values[name] = raw.rstrip("/")
            else:
                values[name] = raw
        unknown = set(overrides) - {f.name for f in fields(cls)}
        if unknown:
            raise TypeError(f"unknown configuration fields: {', '.join(sorted(unknown))}")
        values.update(overrides)
        return cls(**values)

    def with_values(self, **changes) -> IdentityConfig:
        return replace(self, **changes)

    def scripts(self) -> IdentityScripts:
        """The applied scripts. Raises :class:`IdentityConfigError` when a value is missing."""
        missing = [
            ENV_VARS[name] for name in ("legacy_root", "config_seed") if getattr(self, name) is None
        ]
        if missing:
            raise IdentityConfigError(
                "missing deployment values: "
                + ", ".join(missing)
                + " (set the environment variables or pass them to IdentityConfig)"
            )
        if len(self.legacy_hash) != 28:
            raise IdentityConfigError(f"{ENV_VARS['legacy_hash']}: expected 28 bytes")
        if len(self.legacy_root) != 32:
            raise IdentityConfigError(f"{ENV_VARS['legacy_root']}: expected 32 bytes")
        scripts = IdentityScripts.derive(
            legacy_hash=self.legacy_hash,
            legacy_root=self.legacy_root,
            config_seed=self.config_seed,
        )
        if self.identity_policy_id is not None and self.identity_policy_id != scripts.identity.hash:
            raise IdentityConfigError(
                f"{ENV_VARS['identity_policy_id']} is {self.identity_policy_id.hex()}, but "
                f"{ENV_VARS['legacy_root']}, {ENV_VARS['config_seed']} and "
                f"{ENV_VARS['legacy_hash']} give {scripts.identity.hash_hex}"
            )
        return scripts
