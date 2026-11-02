"""The identity context: configuration, ledger reads and authentic outputs.

An output is authentic (Part 1 §4, Part 2 §4.1, §5.2) only when it is at the
exact enterprise address of its script and holds exactly one token of the
script's policy, named by the identifier. Outputs that only look like records
are ignored.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property
from typing import Generic, TypeVar

from pycardano import Address, AssetName, PlutusV3Script, ScriptHash, UTxO
from pycardano.backend.base import ChainContext
from pycardano.plutus import script_hash as pycardano_script_hash

from vector_agent.identity.chain import Ledger, OgmiosKoiosLedger, SlotClock
from vector_agent.identity.config import ENV_VARS, IdentityConfig
from vector_agent.identity.constants import CONFIG_TOKEN_NAME
from vector_agent.identity.errors import IdentityConfigError, IdentityLookupError
from vector_agent.identity.gateway import IdentityGateway
from vector_agent.identity.plutus_data import PlutusDataError, decode_data
from vector_agent.identity.scripts import IdentityScripts, ScriptInfo
from vector_agent.identity.types import (
    AttestationDatum,
    DelegationDatum,
    IdentityDatum,
    OutputReference,
    Subagent,
)

__all__ = [
    "AuthenticOutput",
    "IdentityContext",
    "IdentityLookupError",
    "ScriptSource",
    "datum_bytes",
    "utxo_ref",
]

D = TypeVar("D")


@dataclass(frozen=True)
class AuthenticOutput(Generic[D]):
    """An authentic output and its decoded datum. ``id`` is the token name."""

    utxo: UTxO
    datum: D
    id: bytes

    @property
    def ref(self) -> OutputReference:
        return utxo_ref(self.utxo)

    @property
    def lovelace(self) -> int:
        amount = self.utxo.output.amount
        return amount if isinstance(amount, int) else amount.coin


@dataclass(frozen=True)
class ScriptSource:
    """A script for a transaction: a reference-script UTxO, or the script itself."""

    script: PlutusV3Script
    reference: UTxO | None = None

    @property
    def script_hash(self) -> bytes:
        return bytes(pycardano_script_hash(self.script).payload)

    @property
    def argument(self):
        """What the PyCardano builder takes: the reference UTxO, or the script."""
        return self.reference if self.reference is not None else self.script


def utxo_ref(utxo: UTxO) -> OutputReference:
    return OutputReference(bytes(utxo.input.transaction_id.payload), utxo.input.index)


def datum_bytes(utxo: UTxO) -> bytes | None:
    """The CBOR bytes of an inline datum, or None."""
    datum = utxo.output.datum
    if datum is None:
        return None
    if hasattr(datum, "cbor"):
        return bytes(datum.cbor)
    return bytes(datum.to_cbor()) if hasattr(datum, "to_cbor") else None


def _sole_token(utxo: UTxO, policy: bytes) -> bytes | None:
    amount = utxo.output.amount
    if isinstance(amount, int):
        return None
    bundle = amount.multi_asset.get(ScriptHash(policy))
    if bundle is None or len(bundle) != 1:
        return None
    (name, quantity), = bundle.items()
    return bytes(name.payload) if quantity == 1 else None


class IdentityContext:
    """Configuration, scripts, clock and ledger reads that every client shares."""

    def __init__(
        self,
        ledger: Ledger,
        config: IdentityConfig | None = None,
        *,
        clock: SlotClock | None = None,
        gateway: IdentityGateway | None = None,
    ) -> None:
        self.ledger = ledger
        self.config = config if config is not None else IdentityConfig.from_env()
        self._clock = clock
        self._gateway = gateway

    @classmethod
    def connect(
        cls,
        config: IdentityConfig | None = None,
        *,
        context: ChainContext | None = None,
        submit_url: str | None = None,
    ) -> IdentityContext:
        """A context on the configured Ogmios and Koios endpoints (Vector mainnet by default)."""
        config = config if config is not None else IdentityConfig.from_env()
        ledger = OgmiosKoiosLedger(
            ogmios_url=config.ogmios_url,
            koios_url=config.koios_url,
            koios_token=config.koios_token,
            context=context,
            submit_url=submit_url,
        )
        return cls(ledger, config)

    @cached_property
    def scripts(self) -> IdentityScripts:
        return self.config.scripts()

    @property
    def clock(self) -> SlotClock:
        if self._clock is None:
            self._clock = SlotClock.from_context(self.ledger.context)
        return self._clock

    @property
    def gateway(self) -> IdentityGateway:
        if self._gateway is None:
            self._gateway = IdentityGateway(self.config.gateway_url)
        return self._gateway

    # ------------------------------------------------------------------
    # Authentic outputs
    # ------------------------------------------------------------------

    def _authentic(
        self,
        script: ScriptInfo,
        name: bytes,
        decode: Callable[[bytes], D],
        what: str,
    ) -> AuthenticOutput[D] | None:
        found = []
        for utxo in self.ledger.token_utxos(script.hash, name):
            if utxo.output.address != script.address or _sole_token(utxo, script.hash) != name:
                continue
            raw = datum_bytes(utxo)
            if raw is None:
                continue
            try:
                found.append(AuthenticOutput(utxo, decode(raw), name))
            except (PlutusDataError, ValueError) as exc:
                raise IdentityLookupError(f"{what} {name.hex()}: the datum does not decode: {exc}") from exc
        if len(found) > 1:
            raise IdentityLookupError(f"{what} {name.hex()}: more than one authentic output")
        return found[0] if found else None

    def find_record(self, vector_id: bytes | str) -> AuthenticOutput[IdentityDatum] | None:
        """The record output of ``vector_id`` (live record or tombstone), or None."""
        name = bytes.fromhex(vector_id) if isinstance(vector_id, str) else vector_id
        return self._authentic(self.scripts.identity, name, IdentityDatum.from_cbor, "identity record")

    def record(self, vector_id: bytes | str) -> AuthenticOutput[IdentityDatum]:
        found = self.find_record(vector_id)
        if found is None:
            name = vector_id if isinstance(vector_id, str) else vector_id.hex()
            raise IdentityLookupError(f"no identity record for {name}")
        return found

    def ancestors(self, record: IdentityDatum) -> list[AuthenticOutput[IdentityDatum]]:
        """The records of the parent, the grandparent and so on (at most 4)."""
        chain = []
        current = record
        while isinstance(current.lineage, Subagent) and len(chain) < 4:
            parent = self.record(current.lineage.parent)
            chain.append(parent)
            current = parent.datum
        return chain

    def find_attestation(self, attestation_id: bytes | str) -> AuthenticOutput[AttestationDatum] | None:
        name = bytes.fromhex(attestation_id) if isinstance(attestation_id, str) else attestation_id
        return self._authentic(self.scripts.attestation, name, AttestationDatum.from_cbor, "attestation")

    def find_delegation(self, delegation_id: bytes | str) -> AuthenticOutput[DelegationDatum] | None:
        name = bytes.fromhex(delegation_id) if isinstance(delegation_id, str) else delegation_id
        return self._authentic(self.scripts.delegation, name, DelegationDatum.from_cbor, "delegation")

    def delegation(self, delegation_id: bytes | str) -> AuthenticOutput[DelegationDatum]:
        found = self.find_delegation(delegation_id)
        if found is None:
            name = delegation_id if isinstance(delegation_id, str) else delegation_id.hex()
            raise IdentityLookupError(f"no delegation {name}")
        return found

    def delegations(self) -> list[AuthenticOutput[DelegationDatum]]:
        """Every authentic delegation output (live delegations)."""
        scripts = self.scripts
        out = []
        for utxo in self.ledger.utxos_at(str(scripts.delegation.address)):
            name = _sole_token(utxo, scripts.delegation.hash)
            raw = datum_bytes(utxo)
            if utxo.output.address != scripts.delegation.address or name is None or raw is None:
                continue
            try:
                out.append(AuthenticOutput(utxo, DelegationDatum.from_cbor(raw), name))
            except (PlutusDataError, ValueError):
                continue
        return out

    # ------------------------------------------------------------------
    # Configuration record and scripts
    # ------------------------------------------------------------------

    @cached_property
    def config_record(self) -> tuple[UTxO, bytes] | None:
        """The configuration record (Part 2 §3.8) and the Module-1 hash ``M1``, or None."""
        scripts = self.scripts
        holder = scripts.config_holder.address
        if self.config.config_utxo is not None:
            candidates = [u for u in [self.ledger.utxo(self.config.config_utxo)] if u is not None]
        else:
            candidates = self.ledger.utxos_at(str(holder))
        for utxo in candidates:
            amount = utxo.output.amount
            if utxo.output.address != holder or isinstance(amount, int):
                continue
            bundle = amount.multi_asset.get(ScriptHash(scripts.config_policy), {})
            if bundle.get(AssetName(CONFIG_TOKEN_NAME), 0) != 1:
                continue
            raw = datum_bytes(utxo)
            m1 = decode_data(raw) if raw is not None else None
            if isinstance(m1, bytes) and len(m1) == 28:
                return utxo, m1
        if self.config.config_utxo is not None:
            raise IdentityConfigError(
                f"{ENV_VARS['config_utxo']} does not hold the configuration record of this deployment"
            )
        return None

    @property
    def module1(self) -> bytes | None:
        """``M1``: the Module-1 hash of the configuration record, or None before the seal."""
        record = self.config_record
        return record[1] if record else None

    def _reference(self, ref: OutputReference | None, expected: bytes, variable: str) -> UTxO | None:
        if ref is None:
            return None
        utxo = self.ledger.utxo(ref)
        if utxo is None:
            raise IdentityConfigError(f"{variable}: {ref} is spent or unknown")
        script = utxo.output.script
        if script is None or bytes(pycardano_script_hash(script).payload) != expected:
            raise IdentityConfigError(f"{variable}: {ref} does not hold the script {expected.hex()}")
        return utxo

    def script_source(self, name: str) -> ScriptSource:
        """The script ``name`` from its configured reference UTxO, else the script itself."""
        scripts = self.scripts
        if name == "legacy":
            info = scripts.legacy
            ref = self._reference(self.config.legacy_ref, scripts.legacy_hash, ENV_VARS["legacy_ref"])
            if ref is not None:
                return ScriptSource(ref.output.script, ref)
            if info is None:
                raise IdentityConfigError(
                    f"the legacy registry script is unknown for this legacy hash; set {ENV_VARS['legacy_ref']}"
                )
            return ScriptSource(info.plutus_script)
        info = getattr(scripts, name)
        variable = ENV_VARS.get(f"{name}_ref")
        ref = self._reference(getattr(self.config, f"{name}_ref", None), info.hash, variable or name)
        return ScriptSource(info.plutus_script, ref)

    def module1_source(self) -> ScriptSource:
        """The Module-1 ``identity_party`` script, from ``VECTOR_MODULE1_REF_UTXO``."""
        m1 = self.module1
        if m1 is None:
            raise IdentityLookupError("the configuration record is not sealed: Module-1 cannot be a party")
        if self.config.module1_ref is None:
            raise IdentityConfigError(
                f"{ENV_VARS['module1_ref']} is required for a transaction that Module-1 approves"
            )
        ref = self._reference(self.config.module1_ref, m1, ENV_VARS["module1_ref"])
        return ScriptSource(ref.output.script, ref)

    def address_of(self, address: str | Address) -> Address:
        return address if isinstance(address, Address) else Address.from_primitive(address)
