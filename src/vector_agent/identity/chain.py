"""Ledger reads for the identity builders.

The builders need four reads besides the PyCardano ``ChainContext`` that
balances a transaction:

- the current output of a reference (Ogmios ``queryLedgerState/utxo`` by
  output reference: inline datums and reference scripts included);
- the outputs at an address (Ogmios, by address);
- the current outputs that hold a token (Koios ``asset_utxos``, then Ogmios
  for the outputs themselves, so that an output that Koios has not yet seen
  spent is not used);
- the tip slot.

:class:`Ledger` is the interface; :class:`OgmiosKoiosLedger` reads Vector
mainnet through the public Ogmios (HTTP JSON-RPC, Ogmios v6) and Koios (v1)
endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx
from pycardano import (
    Address,
    Asset,
    AssetName,
    DatumHash,
    MultiAsset,
    NativeScript,
    PlutusV1Script,
    PlutusV2Script,
    PlutusV3Script,
    ScriptHash,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
)
from pycardano.backend.base import ChainContext
from pycardano.serialization import RawCBOR

from vector_agent.exceptions import ConnectionError as VectorConnectionError
from vector_agent.identity.constants import MAINNET_SLOT_LENGTH_MS, MAINNET_SYSTEM_START_MS
from vector_agent.identity.types import OutputReference

__all__ = [
    "Ledger",
    "OgmiosKoiosLedger",
    "SlotClock",
    "utxo_from_ogmios",
]


@dataclass(frozen=True)
class SlotClock:
    """Slot and POSIX time: ``ms = system_start_ms + slot * slot_length_ms``."""

    system_start_ms: int = MAINNET_SYSTEM_START_MS
    slot_length_ms: int = MAINNET_SLOT_LENGTH_MS

    def posix_ms(self, slot: int) -> int:
        return self.system_start_ms + slot * self.slot_length_ms

    def slot_at_or_before(self, posix_ms: int) -> int:
        return (posix_ms - self.system_start_ms) // self.slot_length_ms

    @classmethod
    def from_context(cls, context: ChainContext) -> SlotClock:
        genesis = context.genesis_param
        return cls(int(genesis.system_start) * 1000, int(genesis.slot_length) * 1000)


@runtime_checkable
class Ledger(Protocol):
    """What the identity builders read from the ledger."""

    @property
    def context(self) -> ChainContext:
        """The PyCardano chain context that balances and evaluates transactions."""

    def tip_slot(self) -> int:
        """The slot of the ledger tip."""

    def utxo(self, ref: OutputReference) -> UTxO | None:
        """The unspent output ``ref``, or None when it is spent or unknown."""

    def utxos_at(self, address: str) -> list[UTxO]:
        """The unspent outputs at ``address``."""

    def token_utxos(self, policy_id: bytes, asset_name: bytes) -> list[UTxO]:
        """The unspent outputs that hold the token ``policy_id.asset_name``."""

    def reward_balance(self, script_hash: bytes) -> int | None:
        """The reward balance of the stake credential ``Script(script_hash)``; None when not registered."""


def _script_from_ogmios(raw: dict | None):
    if not raw:
        return None
    language = raw.get("language", "")
    code = bytes.fromhex(raw.get("cbor", ""))
    if language == "plutus:v3":
        return PlutusV3Script(code)
    if language == "plutus:v2":
        return PlutusV2Script(code)
    if language == "plutus:v1":
        return PlutusV1Script(code)
    if language == "native" and code:
        return NativeScript.from_cbor(code)
    return None


def utxo_from_ogmios(raw: dict) -> UTxO:
    """An Ogmios v6 UTxO object as a PyCardano ``UTxO``.

    Inline datums keep their exact bytes (``RawCBOR``). Reference scripts are
    kept, so the output can serve as a reference-script input.
    """
    tx_in = TransactionInput(TransactionId(bytes.fromhex(raw["transaction"]["id"])), int(raw["index"]))
    value_raw = raw.get("value", {})
    coin = int(value_raw.get("ada", {}).get("lovelace", 0))
    multi_asset = MultiAsset()
    for policy, assets in value_raw.items():
        if policy == "ada":
            continue
        bundle = Asset()
        for name, quantity in assets.items():
            bundle[AssetName(bytes.fromhex(name))] = int(quantity)
        multi_asset[ScriptHash(bytes.fromhex(policy))] = bundle
    value = Value(coin, multi_asset) if multi_asset else coin
    datum = RawCBOR(bytes.fromhex(raw["datum"])) if raw.get("datum") else None
    datum_hash = None
    if raw.get("datumHash") and datum is None:
        datum_hash = DatumHash(bytes.fromhex(raw["datumHash"]))
    output = TransactionOutput(
        Address.from_primitive(raw["address"]),
        value,
        datum_hash=datum_hash,
        datum=datum,
        script=_script_from_ogmios(raw.get("script")),
    )
    return UTxO(tx_in, output)


def holds_token(utxo: UTxO, policy_id: bytes, asset_name: bytes) -> bool:
    amount = utxo.output.amount
    if isinstance(amount, int):
        return False
    policy = ScriptHash(policy_id)
    return policy in amount.multi_asset and amount.multi_asset[policy].get(AssetName(asset_name), 0) > 0


class OgmiosKoiosLedger:
    """Reads Vector through Ogmios (HTTP JSON-RPC) and Koios.

    ``context`` balances transactions; by default it is a
    :class:`vector_agent.chain.VectorChainContext` on the same Ogmios.
    """

    def __init__(
        self,
        *,
        ogmios_url: str,
        koios_url: str,
        koios_token: str | None = None,
        context: ChainContext | None = None,
        submit_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._ogmios_url = ogmios_url.rstrip("/")
        self._koios_url = koios_url.rstrip("/")
        self._koios_headers = {"Authorization": f"Bearer {koios_token}"} if koios_token else {}
        self._timeout = timeout
        if context is None:
            from vector_agent.chain.context import VectorChainContext
            from vector_agent.chain.ogmios import OgmiosClient
            from vector_agent.chain.submit import SubmitClient

            context = VectorChainContext(OgmiosClient(self._ogmios_url), SubmitClient(submit_url or ""))
        self._context = context

    @property
    def context(self) -> ChainContext:
        return self._context

    def _ogmios(self, method: str, params: dict | None = None):
        payload: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            response = httpx.post(self._ogmios_url, json=payload, timeout=self._timeout)
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise VectorConnectionError(f"Ogmios request failed ({method}): {exc}") from exc
        if "error" in body:
            raise VectorConnectionError(f"Ogmios error ({method}): {body['error']}")
        return body.get("result")

    def tip_slot(self) -> int:
        tip = self._ogmios("queryNetwork/tip")
        return int(tip["slot"])

    def utxos_by_refs(self, refs: list[OutputReference]) -> list[UTxO]:
        if not refs:
            return []
        params = {
            "outputReferences": [{"transaction": {"id": ref.tx_id.hex()}, "index": ref.index} for ref in refs]
        }
        return [utxo_from_ogmios(raw) for raw in self._ogmios("queryLedgerState/utxo", params) or []]

    def utxo(self, ref: OutputReference) -> UTxO | None:
        found = self.utxos_by_refs([ref])
        return found[0] if found else None

    def utxos_at(self, address: str) -> list[UTxO]:
        result = self._ogmios("queryLedgerState/utxo", {"addresses": [str(address)]})
        return [utxo_from_ogmios(raw) for raw in result or []]

    def token_utxos(self, policy_id: bytes, asset_name: bytes) -> list[UTxO]:
        try:
            response = httpx.post(
                f"{self._koios_url}/asset_utxos",
                json={"_asset_list": [[policy_id.hex(), asset_name.hex()]], "_extended": False},
                headers=self._koios_headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            rows = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise VectorConnectionError(f"Koios asset_utxos failed: {exc}") from exc
        refs = [
            OutputReference(bytes.fromhex(row["tx_hash"]), int(row["tx_index"]))
            for row in rows
            if not row.get("is_spent", False)
        ]
        return [u for u in self.utxos_by_refs(refs) if holds_token(u, policy_id, asset_name)]

    def reward_balance(self, script_hash: bytes) -> int | None:
        result = self._ogmios("queryLedgerState/rewardAccountSummaries", {"scripts": [script_hash.hex()]})
        # Ogmios v6 answers a list of {from, credential, rewards: {ada: {lovelace}}, ...}.
        entries = result if isinstance(result, list) else list((result or {}).values())
        for entry in entries:
            if entry.get("credential", script_hash.hex()) == script_hash.hex():
                return int(entry["rewards"]["ada"]["lovelace"])
        return None
