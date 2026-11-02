"""Values of one Module-6 deployment.

The five Module-6 validators take one parameter, ``GovernanceConfig`` (11
fields, ``identity_hash`` last; Part 2 §7 of ``docs/IDENTITY_REGISTRY.md``). The
SDK applies it to the embedded blueprint (:mod:`vector_agent.governance.scripts`).
The new Module-6 deployment is not live yet, so the SDK has no default values:
set the environment variables of :data:`ENV_VARS`, or load the deploy state that
``Module-6/scripts/deploy.py`` writes (``wallets/deploy_state.json``).

- The configuration values give every script hash. ``validator_hashes``, when
  set, must equal the derived hashes; a difference means a wrong value or
  another blueprint.
- Reference-script outputs are optional. Without them a transaction carries
  the scripts, and a proposal submission then exceeds the transaction size
  limit (``proposal_spend`` has 13.7 KB).
- The parameters record, the oracle record and the cross references are found
  by their tokens. A configured output reference must hold the record.
- The head of the activity list moves with every insertion, so the client
  finds it by its record token (``record_token_policy``, ``activity``).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

from vector_agent.governance.errors import GovernanceConfigError
from vector_agent.governance.scripts import SCRIPT_NAMES, VALIDATOR_TITLES, GovernanceScripts
from vector_agent.governance.types import GovernanceConfig
from vector_agent.identity.constants import LEGACY_REGISTRY_HASH
from vector_agent.identity.types import OutputReference

__all__ = ["ENV_VARS", "GovernanceDeployment"]

#: Environment variable of each deployment value.
ENV_VARS: Mapping[str, str] = {
    "deploy_state": "VECTOR_MODULE6_DEPLOY_STATE",
    "identity_hash": "VECTOR_MODULE6_IDENTITY_HASH",
    "record_token_policy": "VECTOR_MODULE6_RECORD_TOKEN_POLICY",
    "refs_token_policy": "VECTOR_MODULE6_REFS_TOKEN_POLICY",
    "governance_oracle_hash": "VECTOR_MODULE6_ORACLE_HOLDER_HASH",
    "governance_params_hash": "VECTOR_MODULE6_PARAMS_HOLDER_HASH",
    "governance_treasury_hash": "VECTOR_MODULE6_TREASURY_HOLDER_HASH",
    "prediction_validator_hash": "VECTOR_MODULE6_PREDICTION_HASH",
    "reputation_validator_hash": "VECTOR_MODULE6_REPUTATION_HASH",
    "jury_pool_hash": "VECTOR_MODULE6_JURY_POOL_HASH",
    "credibility_pool_hash": "VECTOR_MODULE6_CREDIBILITY_POOL_HASH",
    "protocol_params_hash": "VECTOR_MODULE6_PROTOCOL_PARAMS_HASH",
    "proposal_spend_hash": "VECTOR_MODULE6_PROPOSAL_SPEND_HASH",
    "proposal_spend_ref": "VECTOR_MODULE6_PROPOSAL_SPEND_REF_UTXO",
    "proposal_mint_ref": "VECTOR_MODULE6_PROPOSAL_MINT_REF_UTXO",
    "critique_spend_ref": "VECTOR_MODULE6_CRITIQUE_SPEND_REF_UTXO",
    "critique_mint_ref": "VECTOR_MODULE6_CRITIQUE_MINT_REF_UTXO",
    "endorsement_spend_ref": "VECTOR_MODULE6_ENDORSEMENT_SPEND_REF_UTXO",
    "params_utxo": "VECTOR_MODULE6_PARAMS_UTXO",
    "oracle_utxo": "VECTOR_MODULE6_ORACLE_UTXO",
    "cross_refs_utxo": "VECTOR_MODULE6_CROSSREFS_UTXO",
}

#: Configuration values that a deployment must set.
_REQUIRED = (
    "identity_hash",
    "record_token_policy",
    "refs_token_policy",
    "governance_oracle_hash",
    "governance_params_hash",
    "governance_treasury_hash",
)
#: Configuration values that the deploy script keeps at zero.
_ZERO_BY_DEFAULT = (
    "prediction_validator_hash",
    "reputation_validator_hash",
    "jury_pool_hash",
    "credibility_pool_hash",
    "protocol_params_hash",
)
_REFS = (
    "proposal_spend_ref",
    "proposal_mint_ref",
    "critique_spend_ref",
    "critique_mint_ref",
    "endorsement_spend_ref",
    "params_utxo",
    "oracle_utxo",
    "cross_refs_utxo",
)
_ZERO = bytes(28)

#: Deploy-state keys (``tx_hashes``) of the reference-script transactions; the
#: deploy script puts each reference script at output 0.
_STATE_REF_KEYS = {
    "proposal_spend": "proposal_spend_ref",
    "proposal_mint": "proposal_mint_ref",
    "critique_spend": "critique_spend_ref",
    "critique_mint": "critique_mint_ref",
    "endorsement_spend": "endorsement_spend_ref",
}


def _label(name: str) -> str:
    return ENV_VARS.get(name, name)


def _hash28(name: str, value: str | bytes) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value).strip().lower()
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = b""
        if len(text) != 56:
            raw = b""
    if len(raw) != 28:
        raise GovernanceConfigError(f"{_label(name)}: expected 56 hexadecimal characters")
    return raw


def _ref(name: str, value: str | OutputReference) -> OutputReference:
    if isinstance(value, OutputReference):
        return value
    try:
        return OutputReference.parse(str(value).lower())
    except ValueError:
        raise GovernanceConfigError(f"{_label(name)}: expected <tx id>#<index>") from None


def _state_values(state: Mapping, source: str) -> dict:
    """The deployment values of a deploy state (``Module-6/scripts/deploy.py``)."""
    if not state.get("identity_hash"):
        raise GovernanceConfigError(
            f"{source} has no identity_hash: it belongs to a Module-6 deployment with the legacy "
            "agent registry. The SDK serves only the Module-6 deployment that reads identity records."
        )
    holders = state.get("holders") or {}
    values: dict = {
        "identity_hash": state.get("identity_hash"),
        "record_token_policy": state.get("record_token_policy"),
        "refs_token_policy": state.get("refs_token_policy"),
        "governance_oracle_hash": (holders.get("oracle") or {}).get("hash"),
        "governance_params_hash": (holders.get("params") or {}).get("hash"),
        "governance_treasury_hash": (holders.get("treasury") or {}).get("hash"),
    }
    values = {k: _hash28(k, v) for k, v in values.items() if v}
    validators = state.get("validators") or {}
    hashes = {}
    for name, title in VALIDATOR_TITLES.items():
        found = (validators.get(title) or {}).get("hash")
        if found:
            hashes[name] = _hash28(f"{source} validators.{title}.hash", found)
    if hashes:
        values["validator_hashes"] = hashes
    tx_hashes = state.get("tx_hashes") or {}
    for name, key in _STATE_REF_KEYS.items():
        tx = tx_hashes.get(key)
        if tx:
            values[f"{name}_ref"] = _ref(f"{source} tx_hashes.{key}", f"{tx}#0")
    return values


@dataclass(frozen=True)
class GovernanceDeployment:
    """The values of one Module-6 deployment. Build it with :meth:`from_env`,
    :meth:`from_deploy_state` or directly."""

    identity_hash: bytes | None = None
    record_token_policy: bytes | None = None
    refs_token_policy: bytes | None = None
    governance_oracle_hash: bytes | None = None
    governance_params_hash: bytes | None = None
    governance_treasury_hash: bytes | None = None
    prediction_validator_hash: bytes = _ZERO
    reputation_validator_hash: bytes = _ZERO
    jury_pool_hash: bytes = _ZERO
    credibility_pool_hash: bytes = _ZERO
    protocol_params_hash: bytes = _ZERO
    #: Expected script hashes by script name (``proposal_spend``, ...): a check.
    validator_hashes: Mapping[str, bytes] = field(default_factory=dict)
    proposal_spend_ref: OutputReference | None = None
    proposal_mint_ref: OutputReference | None = None
    critique_spend_ref: OutputReference | None = None
    critique_mint_ref: OutputReference | None = None
    endorsement_spend_ref: OutputReference | None = None
    params_utxo: OutputReference | None = None
    oracle_utxo: OutputReference | None = None
    cross_refs_utxo: OutputReference | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides) -> GovernanceDeployment:
        """Read the variables of :data:`ENV_VARS`; keyword arguments win over them.

        ``VECTOR_MODULE6_DEPLOY_STATE`` names a deploy-state file; the other
        variables win over its values.
        """
        source = os.environ if env is None else env
        values: dict = {}
        state_path = source.get(ENV_VARS["deploy_state"], "").strip()
        if state_path:
            values.update(_state_values(_read_state(Path(state_path)), state_path))
        for name, variable in ENV_VARS.items():
            raw = source.get(variable, "").strip()
            if not raw or name == "deploy_state":
                continue
            if name == "proposal_spend_hash":
                values["validator_hashes"] = {**values.get("validator_hashes", {}), "proposal_spend": _hash28(name, raw)}
            elif name in _REFS:
                values[name] = _ref(name, raw)
            else:
                values[name] = _hash28(name, raw)
        return cls._make(values, overrides)

    @classmethod
    def from_deploy_state(cls, state: Mapping | str | Path, **overrides) -> GovernanceDeployment:
        """From the deploy state of ``Module-6/scripts/deploy.py`` (a mapping or a
        file path). A state without ``identity_hash`` belongs to the old deployment
        and is refused."""
        source = "the deploy state"
        if isinstance(state, (str, Path)):
            source = str(state)
            state = _read_state(Path(state))
        return cls._make(_state_values(state, source), overrides)

    @classmethod
    def _make(cls, values: dict, overrides: Mapping) -> GovernanceDeployment:
        unknown = set(overrides) - {f.name for f in fields(cls)}
        if unknown:
            raise TypeError(f"unknown deployment fields: {', '.join(sorted(unknown))}")
        values.update(overrides)
        return cls(**values)

    def with_values(self, **changes) -> GovernanceDeployment:
        return replace(self, **changes)

    def config(self) -> GovernanceConfig:
        """The ``GovernanceConfig`` of the validators. Raises
        :class:`GovernanceConfigError` when a value is missing or invalid."""
        missing = [ENV_VARS[name] for name in _REQUIRED if getattr(self, name) is None]
        if missing:
            raise GovernanceConfigError(
                "missing Module-6 deployment values: "
                + ", ".join(missing)
                + f" (set the environment variables, {ENV_VARS['deploy_state']}, or pass them to GovernanceDeployment)"
            )
        values = {f.name: bytes(getattr(self, f.name)) for f in fields(GovernanceConfig)}
        for name, value in values.items():
            if len(value) != 28:
                raise GovernanceConfigError(f"{_label(name)}: expected 28 bytes")
        for name in _REQUIRED:
            if values[name] == _ZERO:
                raise GovernanceConfigError(f"{_label(name)} is all zero")
        if values["identity_hash"] == bytes.fromhex(LEGACY_REGISTRY_HASH):
            raise GovernanceConfigError(
                f"{_label('identity_hash')} is the legacy agent registry hash; the Module-6 validators "
                "read the records of the identity registry"
            )
        return GovernanceConfig(**values)

    def scripts(self) -> GovernanceScripts:
        """The applied scripts; checks :attr:`validator_hashes`."""
        scripts = GovernanceScripts.derive(self.config())
        for name, expected in self.validator_hashes.items():
            if name not in SCRIPT_NAMES:
                raise GovernanceConfigError(f"validator_hashes: unknown script {name!r}")
            derived = scripts.by_name(name).hash
            if bytes(expected) != derived:
                raise GovernanceConfigError(
                    f"the deployment names {bytes(expected).hex()} for {name}, but the embedded blueprint "
                    f"with these configuration values gives {derived.hex()}"
                )
        return scripts

    def reference(self, name: str) -> OutputReference | None:
        """The configured reference-script output of the script ``name``."""
        if name not in SCRIPT_NAMES:
            raise KeyError(name)
        return getattr(self, f"{name}_ref")


def _read_state(path: Path) -> Mapping:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise GovernanceConfigError(f"cannot read the Module-6 deploy state {path}: {exc}") from exc
