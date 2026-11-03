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

Mainnet is the default network (``VECTOR_IDENTITY_NETWORK``). On mainnet,
:meth:`IdentityConfig.from_env` fills unset deployment values with the
published values of :data:`MAINNET_IDENTITY_DEPLOYMENT`. The testnet has no
published values.
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

__all__ = [
    "ENV_VARS",
    "MAINNET_IDENTITY_DEPLOYMENT",
    "NETWORKS",
    "IdentityConfig",
    "IdentityConfigError",
    "PublishedDeployment",
]

#: The networks of :meth:`IdentityConfig.from_env`. Both Vector networks use
#: network ID 1, so only this name selects the published deployment values.
NETWORKS = ("mainnet", "testnet")


@dataclass(frozen=True)
class PublishedDeployment:
    """The published values of one identity deployment."""

    legacy_hash: bytes
    legacy_root: bytes
    config_seed: OutputReference
    identity_policy_id: bytes
    identity_ref: OutputReference
    attestation_ref: OutputReference
    delegation_ref: OutputReference
    vault_ref: OutputReference
    #: The clients of this SDK do not spend ``escrow`` or ``advert``; their
    #: reference outputs are here for other callers.
    escrow_ref: OutputReference
    advert_ref: OutputReference


#: The published identity deployment on Vector mainnet (the identity side,
#: 2026-11-03): agents-marketplace ``4c95c3f``,
#: ``contracts/identity-marketplace/deploy/mainnet/deployment.json``. On mainnet,
#: :meth:`IdentityConfig.from_env` uses these values for unset fields. The
#: Module-1 values (M1, its reference output and the configuration record)
#: come with the seal.
MAINNET_IDENTITY_DEPLOYMENT = PublishedDeployment(
    legacy_hash=bytes.fromhex("be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"),
    legacy_root=bytes.fromhex("e4b6b17ce4a8f83aa17d3181ea140d2bd76c0cfa8a7c44ad69543800b4a0df01"),
    config_seed=OutputReference.parse("6c9856c70b1101f1a4e9ceb373188608013416eff48c51f5bb62706a65d41a2a#0"),
    identity_policy_id=bytes.fromhex("d958b823faaa76977d0a07bd9622e87d8e2c85f6692f7f8e8db77762"),
    identity_ref=OutputReference.parse("3d4471222e524584180a4358e05517a243effc46d15ef62443a82aaed822de46#0"),
    attestation_ref=OutputReference.parse("55dfa9e05ff96844fd4313f1c7cb7f0c7f900f1cdf50099b0e2abb242da4128d#0"),
    delegation_ref=OutputReference.parse("f6d47a62146b2bc4dabc12454c8a3dbbedf673d45a6edccd1c462d55c8ba8be7#0"),
    vault_ref=OutputReference.parse("d0bf8f73c915fcbf57ddba714256e520a9a0820bc9e643218db8cf54762d215b#0"),
    escrow_ref=OutputReference.parse("4c2d09858dab0cc22cc77dcb99efed570d909a66e0beb512041dea91005b5e82#0"),
    advert_ref=OutputReference.parse("5efd18a1d90a6b87f1fd4b6fe93acfbe5be082260fd52be194b1088ade7c2758#0"),
)

#: Environment variable of each setting of :meth:`IdentityConfig.from_env`.
ENV_VARS: Mapping[str, str] = {
    "network": "VECTOR_IDENTITY_NETWORK",
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
    """Deployment values and endpoints.

    Build it with :meth:`from_env` (the environment and, on mainnet, the published
    values) or directly (only the values that you give).
    """

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
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, network: str | None = None, **overrides
    ) -> IdentityConfig:
        """Read the variables of :data:`ENV_VARS`; keyword arguments win over them.

        ``network`` (else ``VECTOR_IDENTITY_NETWORK``, default ``mainnet``) selects
        the defaults of the deployment values. On mainnet, unset values take the
        published values of :data:`MAINNET_IDENTITY_DEPLOYMENT`:

        - the root and the seed apply together, and only when neither is set and
          the legacy hash is the published one;
        - the policy ID and the reference outputs of ``identity``, ``attestation``,
          ``delegation`` and ``vault`` apply only when the legacy hash, the root and
          the seed are the published values.

        A keyword argument of None sets no value and no default. The testnet has no
        published values.
        """
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
        env_network = values.pop("network", None)
        selected = (network or env_network or "mainnet").strip().lower()
        if selected not in NETWORKS:
            raise IdentityConfigError(f"{ENV_VARS['network']}: expected mainnet or testnet")
        unknown = set(overrides) - {f.name for f in fields(cls)}
        if unknown:
            raise TypeError(f"unknown configuration fields: {', '.join(sorted(unknown))}")
        values.update(overrides)
        published = MAINNET_IDENTITY_DEPLOYMENT
        legacy_hash = values.get("legacy_hash", bytes.fromhex(LEGACY_REGISTRY_HASH))
        if selected == "mainnet" and legacy_hash == published.legacy_hash:
            if "legacy_root" not in values and "config_seed" not in values:
                values.update(legacy_root=published.legacy_root, config_seed=published.config_seed)
            if values.get("legacy_root") == published.legacy_root and values.get("config_seed") == published.config_seed:
                for name in ("identity_policy_id", "identity_ref", "attestation_ref", "delegation_ref", "vault_ref"):
                    values.setdefault(name, getattr(published, name))
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
