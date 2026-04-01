"""Async HTTP JSON-RPC client for Ogmios."""

from __future__ import annotations

import httpx

from vector_agent.exceptions import ConnectionError


class OgmiosClient:
    """Async client for Ogmios HTTP JSON-RPC API."""

    def __init__(self, ogmios_url: str):
        self._url = ogmios_url.rstrip("/")

    async def _rpc(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC 2.0 request to Ogmios."""
        payload: dict = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(self._url, json=payload)
                resp.raise_for_status()
            except httpx.HTTPError as e:
                raise ConnectionError(f"Ogmios request failed ({method}): {e}") from e
        data = resp.json()
        if "error" in data:
            raise ConnectionError(f"Ogmios RPC error ({method}): {data['error']}")
        return data.get("result", data)

    async def query_protocol_parameters(self) -> dict:
        """Query current protocol parameters."""
        return await self._rpc("queryLedgerState/protocolParameters")

    async def query_utxos(self, addresses: list[str]) -> list[dict]:
        """Query UTxOs for one or more addresses."""
        result = await self._rpc("queryLedgerState/utxo", {"addresses": addresses})
        if isinstance(result, list):
            return result
        return result.get("result", result) if isinstance(result, dict) else []

    async def query_utxos_by_refs(self, refs: list[dict]) -> list[dict]:
        """Query UTxOs by output references.

        Each ref: {"transaction": {"id": "..."}, "index": N}
        """
        result = await self._rpc("queryLedgerState/utxo", {"outputReferences": refs})
        if isinstance(result, list):
            return result
        return result.get("result", result) if isinstance(result, dict) else []

    async def query_network_tip(self) -> dict:
        """Query the current network tip (slot + block hash)."""
        return await self._rpc("queryNetwork/tip")

    async def query_epoch(self) -> int:
        """Query the current epoch number."""
        result = await self._rpc("queryLedgerState/epoch")
        if isinstance(result, int):
            return result
        return int(result)

    async def query_genesis_config(self) -> dict:
        """Query the genesis configuration (for network_magic, slot length, etc.)."""
        return await self._rpc("queryNetwork/genesisConfiguration", {"era": "shelley"})

    async def evaluate_tx(self, cbor_hex: str) -> dict:
        """Evaluate a transaction (dry run) without submitting."""
        return await self._rpc("evaluateTransaction", {"transaction": {"cbor": cbor_hex}})

    async def close(self):
        """No-op — clients are created per-request."""
        pass
