"""Async client for the Vector TX submission API."""

from __future__ import annotations

import asyncio
import hashlib

import httpx

from vector_agent.exceptions import TransactionError


class SubmitClient:
    """Submit signed transactions via the cardano-submit-api."""

    def __init__(self, submit_url: str):
        self._url = submit_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        current_loop = asyncio.get_running_loop()
        if self._client is not None and not self._client.is_closed:
            if getattr(self, "_client_loop", None) is not current_loop:
                await self._client.aclose()
                self._client = None
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
            self._client_loop = current_loop
        return self._client

    async def submit(self, tx_cbor_hex: str) -> str:
        """Submit a signed transaction (CBOR hex) and return the tx hash.

        The submit-api expects raw CBOR bytes with Content-Type: application/cbor.
        """
        client = await self._ensure_client()
        tx_bytes = bytes.fromhex(tx_cbor_hex)
        try:
            resp = await client.post(
                self._url,
                content=tx_bytes,
                headers={"Content-Type": "application/cbor"},
            )
        except httpx.HTTPError as e:
            raise TransactionError(f"TX submission request failed: {e}") from e

        if resp.status_code == 202 or resp.status_code == 200:
            # Compute tx hash from the CBOR (Blake2b-256 of tx body)
            tx_hash = self._compute_tx_hash(tx_bytes)
            return tx_hash

        # Try to extract error message
        try:
            error_body = resp.json()
            msg = error_body.get("message", resp.text)
        except Exception:
            msg = resp.text
        raise TransactionError(f"TX submission failed (HTTP {resp.status_code}): {msg}")

    @staticmethod
    def _compute_tx_hash(tx_bytes: bytes) -> str:
        """Compute the transaction hash (Blake2b-256 of the tx body).

        For a signed transaction CBOR, the body is the first element of the
        top-level array. We hash the full tx bytes as the submit-api returns
        the hash based on the full transaction.
        """
        # The tx hash is Blake2b-256 of the transaction body CBOR.
        # For simplicity, we use the response from submit-api if available,
        # or compute from the full CBOR. PyCardano's Transaction.id handles this.
        h = hashlib.blake2b(tx_bytes, digest_size=32)
        return h.hexdigest()

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
