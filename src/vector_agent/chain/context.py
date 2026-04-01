"""PyCardano ChainContext backed by Ogmios and the Vector submit API."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from fractions import Fraction
from typing import Dict, List, Optional, Union

import cbor2
from pycardano.address import Address
from pycardano.backend.base import ChainContext, GenesisParameters, ProtocolParameters
from pycardano.hash import DatumHash, ScriptHash, TransactionId
from pycardano.network import Network
from pycardano.plutus import RawPlutusData
from pycardano.transaction import (
    Asset,
    AssetName,
    MultiAsset,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
)

from vector_agent.chain.ogmios import OgmiosClient
from vector_agent.chain.submit import SubmitClient


def _run_sync(coro):
    """Run an async coroutine from synchronous code.

    If there is already a running event loop (e.g. inside a Jupyter notebook or
    an async framework), we create a new thread to avoid "cannot run nested
    event loop" errors.  Otherwise we just use ``asyncio.run()``.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We are inside an existing event loop -- run in a fresh thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


def _fraction(s: str) -> Fraction:
    """Parse an Ogmios fraction string like ``"577/10000"`` into a Fraction."""
    if "/" in s:
        num, den = s.split("/")
        return Fraction(int(num), int(den))
    return Fraction(s)


def _lovelace(obj) -> int:
    """Extract lovelace from an Ogmios ``{ada: {lovelace: N}}`` envelope."""
    if isinstance(obj, dict):
        return int(obj.get("ada", {}).get("lovelace", 0))
    return int(obj)


def _bytes_field(obj) -> int:
    """Extract an integer from ``{bytes: N}``."""
    if isinstance(obj, dict):
        return int(obj["bytes"])
    return int(obj)


def _convert_cost_models(ogmios_models: dict) -> Dict[str, Dict[str, int]]:
    """Convert Ogmios cost model arrays into PyCardano's expected dict format.

    Ogmios keys: ``"plutus:v1"``, ``"plutus:v2"``, ``"plutus:v3"``
    PyCardano keys: ``"PlutusV1"``, ``"PlutusV2"``, ``"PlutusV3"``
    Values: array of ints -> dict mapping stringified indices to ints.
    """
    mapping = {
        "plutus:v1": "PlutusV1",
        "plutus:v2": "PlutusV2",
        "plutus:v3": "PlutusV3",
    }
    result: Dict[str, Dict[str, int]] = {}
    for ogmios_key, pycardano_key in mapping.items():
        arr = ogmios_models.get(ogmios_key)
        if arr is not None:
            result[pycardano_key] = {str(i): int(v) for i, v in enumerate(arr)}
    return result


def _parse_utxo(raw: dict) -> UTxO:
    """Parse a single Ogmios UTxO dict into a PyCardano ``UTxO``."""
    tx_id = TransactionId.from_primitive(raw["transaction"]["id"])
    tx_index = raw["index"]
    tx_in = TransactionInput(tx_id, tx_index)

    address = Address.from_primitive(raw["address"])
    ogmios_value = raw.get("value", {})
    lovelace = int(ogmios_value.get("ada", {}).get("lovelace", 0))

    # Build multi-asset if present
    multi_asset: Optional[MultiAsset] = None
    non_ada_keys = [k for k in ogmios_value if k != "ada"]
    if non_ada_keys:
        ma = MultiAsset()
        for key in non_ada_keys:
            # key format: "policyId.assetName"  (hex encoded)
            if "." in key:
                policy_hex, asset_hex = key.split(".", 1)
            else:
                policy_hex = key
                asset_hex = ""
            script_hash = ScriptHash.from_primitive(policy_hex)
            asset_name = AssetName(bytes.fromhex(asset_hex)) if asset_hex else AssetName(b"")
            amount = int(ogmios_value[key])
            if script_hash not in ma:
                ma[script_hash] = Asset()
            ma[script_hash][asset_name] = amount
        multi_asset = ma

    if multi_asset:
        value = Value(lovelace, multi_asset)
    else:
        value = lovelace

    # Datum handling
    datum = None
    datum_hash_val = None

    if "datumHash" in raw and raw["datumHash"]:
        datum_hash_val = DatumHash.from_primitive(raw["datumHash"])

    if "datum" in raw and raw["datum"]:
        raw_datum = raw["datum"]
        if isinstance(raw_datum, str):
            # Inline datum as CBOR hex
            datum = RawPlutusData(cbor2.loads(bytes.fromhex(raw_datum)))

    # Build script reference (not fully handled -- PyCardano TransactionOutput
    # accepts a script parameter, but faithfully reconstructing it from Ogmios
    # JSON is complex.  For UTxO queries this is rarely needed by the SDK.)
    tx_out = TransactionOutput(address, value, datum_hash=datum_hash_val, datum=datum)
    return UTxO(tx_in, tx_out)


class VectorChainContext(ChainContext):
    """A :class:`pycardano.backend.base.ChainContext` that talks to Ogmios
    (for queries) and the Vector submit API (for transaction submission).

    All PyCardano ``ChainContext`` methods are synchronous.  Internally this
    class delegates to :class:`OgmiosClient` and :class:`SubmitClient` which
    are async, using :func:`_run_sync` as a bridge.
    """

    def __init__(self, ogmios: OgmiosClient, submit: SubmitClient) -> None:
        self._ogmios = ogmios
        self._submit = submit

        # Caches (lazily populated)
        self._protocol_param: Optional[ProtocolParameters] = None
        self._genesis_param: Optional[GenesisParameters] = None
        self._epoch: Optional[int] = None
        self._last_block_slot: Optional[int] = None

    # ------------------------------------------------------------------
    # Async helpers (can be used directly from async callers)
    # ------------------------------------------------------------------

    async def async_protocol_param(self) -> ProtocolParameters:
        """Fetch and cache protocol parameters."""
        if self._protocol_param is None:
            raw = await self._ogmios.query_protocol_parameters()
            self._protocol_param = self._build_protocol_params(raw)
        return self._protocol_param

    async def async_genesis_param(self) -> GenesisParameters:
        """Fetch and cache genesis parameters."""
        if self._genesis_param is None:
            raw = await self._ogmios.query_genesis_config()
            self._genesis_param = self._build_genesis_params(raw)
        return self._genesis_param

    async def async_epoch(self) -> int:
        return await self._ogmios.query_epoch()

    async def async_last_block_slot(self) -> int:
        tip = await self._ogmios.query_network_tip()
        return int(tip.get("slot", 0))

    async def async_utxos(self, address: str) -> List[UTxO]:
        raw_utxos = await self._ogmios.query_utxos([str(address)])
        return [_parse_utxo(u) for u in raw_utxos]

    async def async_submit_tx_cbor(self, cbor: Union[bytes, str]) -> str:
        if isinstance(cbor, bytes):
            cbor = cbor.hex()
        return await self._submit.submit(cbor)

    # ------------------------------------------------------------------
    # ChainContext synchronous interface
    # ------------------------------------------------------------------

    @property
    def protocol_param(self) -> ProtocolParameters:
        if self._protocol_param is None:
            _run_sync(self.async_protocol_param())
        return self._protocol_param  # type: ignore[return-value]

    @property
    def genesis_param(self) -> GenesisParameters:
        if self._genesis_param is None:
            _run_sync(self.async_genesis_param())
        return self._genesis_param  # type: ignore[return-value]

    @property
    def network(self) -> Network:
        return Network.MAINNET

    @property
    def epoch(self) -> int:
        return _run_sync(self.async_epoch())

    @property
    def last_block_slot(self) -> int:
        return _run_sync(self.async_last_block_slot())

    def utxos(self, address: str) -> List[UTxO]:
        return _run_sync(self.async_utxos(str(address)))

    def submit_tx_cbor(self, cbor: Union[bytes, str]) -> str:
        return _run_sync(self.async_submit_tx_cbor(cbor))

    # ------------------------------------------------------------------
    # Cache invalidation
    # ------------------------------------------------------------------

    def invalidate_cache(self) -> None:
        """Clear cached protocol and genesis parameters."""
        self._protocol_param = None
        self._genesis_param = None

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_protocol_params(raw: dict) -> ProtocolParameters:
        """Map an Ogmios protocolParameters response to PyCardano's format."""
        exec_prices = raw.get("scriptExecutionPrices", {})
        max_tx_ex = raw.get("maxExecutionUnitsPerTransaction", {})
        max_block_ex = raw.get("maxExecutionUnitsPerBlock", {})
        version = raw.get("version", {})

        # Reference scripts fields (optional, may not exist on older protocol versions)
        max_ref_scripts_raw = raw.get("maxReferenceScriptsSize")
        max_ref_scripts = None
        if max_ref_scripts_raw is not None:
            if isinstance(max_ref_scripts_raw, dict) and "bytes" in max_ref_scripts_raw:
                max_ref_scripts = {"bytes": int(max_ref_scripts_raw["bytes"])}
            elif isinstance(max_ref_scripts_raw, dict):
                max_ref_scripts = {k: int(v) for k, v in max_ref_scripts_raw.items()}

        min_fee_ref_raw = raw.get("minFeeReferenceScripts")
        min_fee_ref = None
        if min_fee_ref_raw is not None:
            min_fee_ref = {
                "base": float(min_fee_ref_raw.get("base", 0)),
                "range": int(min_fee_ref_raw.get("range", 0)),
                "multiplier": float(min_fee_ref_raw.get("multiplier", 0)),
            }

        return ProtocolParameters(
            min_fee_constant=_lovelace(raw.get("minFeeConstant", 0)),
            min_fee_coefficient=int(raw.get("minFeeCoefficient", 0)),
            max_block_size=_bytes_field(raw.get("maxBlockBodySize", 0)),
            max_tx_size=_bytes_field(raw.get("maxTransactionSize", 0)),
            max_block_header_size=_bytes_field(raw.get("maxBlockHeaderSize", 0)),
            key_deposit=_lovelace(raw.get("stakeCredentialDeposit", 0)),
            pool_deposit=_lovelace(raw.get("stakePoolDeposit", 0)),
            pool_influence=_fraction(str(raw.get("stakePoolPledgeInfluence", "0/1"))),
            monetary_expansion=_fraction(str(raw.get("monetaryExpansion", "0/1"))),
            treasury_expansion=_fraction(str(raw.get("treasuryExpansion", "0/1"))),
            decentralization_param=Fraction(0),
            extra_entropy="",
            protocol_major_version=int(version.get("major", 0)),
            protocol_minor_version=int(version.get("minor", 0)),
            min_utxo=_lovelace(raw.get("minUtxoDepositConstant", 0)),
            min_pool_cost=_lovelace(raw.get("minStakePoolCost", 0)),
            price_mem=_fraction(str(exec_prices.get("memory", "0/1"))),
            price_step=_fraction(str(exec_prices.get("cpu", "0/1"))),
            max_tx_ex_mem=int(max_tx_ex.get("memory", 0)),
            max_tx_ex_steps=int(max_tx_ex.get("cpu", 0)),
            max_block_ex_mem=int(max_block_ex.get("memory", 0)),
            max_block_ex_steps=int(max_block_ex.get("cpu", 0)),
            max_val_size=_bytes_field(raw.get("maxValueSize", 0)),
            collateral_percent=int(raw.get("collateralPercentage", 0)),
            max_collateral_inputs=int(raw.get("maxCollateralInputs", 0)),
            coins_per_utxo_word=0,
            coins_per_utxo_byte=int(raw.get("minUtxoDepositCoefficient", 0)),
            cost_models=_convert_cost_models(raw.get("plutusCostModels", {})),
            maximum_reference_scripts_size=max_ref_scripts,
            min_fee_reference_scripts=min_fee_ref,
        )

    @staticmethod
    def _build_genesis_params(raw: dict) -> GenesisParameters:
        """Map an Ogmios genesis configuration response to PyCardano's format."""
        # Parse start time to unix timestamp
        start_time_str = raw.get("startTime", "")
        if start_time_str:
            dt = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            system_start = int(dt.timestamp())
        else:
            system_start = 0

        # Slot length: Ogmios returns {"milliseconds": N}
        slot_length_raw = raw.get("slotLength", {})
        if isinstance(slot_length_raw, dict):
            slot_length = int(slot_length_raw.get("milliseconds", 1000)) // 1000
        else:
            slot_length = int(slot_length_raw)

        return GenesisParameters(
            active_slots_coefficient=_fraction(
                str(raw.get("activeSlotsCoefficient", "1/1"))
            ),
            update_quorum=int(raw.get("updateQuorum", 0)),
            max_lovelace_supply=int(raw.get("maxLovelaceSupply", 0)),
            network_magic=int(raw.get("networkMagic", 0)),
            epoch_length=int(raw.get("epochLength", 0)),
            system_start=system_start,
            slots_per_kes_period=int(raw.get("slotsPerKesPeriod", 0)),
            slot_length=slot_length,
            max_kes_evolutions=int(raw.get("maxKesEvolutions", 0)),
            security_param=int(raw.get("securityParameter", 0)),
        )
