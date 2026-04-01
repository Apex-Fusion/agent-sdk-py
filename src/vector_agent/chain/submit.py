"""Async client for the Vector TX submission API."""

from __future__ import annotations

import hashlib

import httpx

from vector_agent.exceptions import TransactionError


class SubmitClient:
    """Submit signed transactions via the cardano-submit-api."""

    def __init__(self, submit_url: str):
        self._url = submit_url.rstrip("/")

    async def submit(self, tx_cbor_hex: str) -> str:
        """Submit a signed transaction (CBOR hex) and return the tx hash.

        The submit-api expects raw CBOR bytes with Content-Type: application/cbor.
        """
        tx_bytes = bytes.fromhex(tx_cbor_hex)
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(
                    self._url,
                    content=tx_bytes,
                    headers={"Content-Type": "application/cbor"},
                )
            except httpx.HTTPError as e:
                raise TransactionError(f"TX submission request failed: {e}") from e

        if resp.status_code == 202 or resp.status_code == 200:
            tx_hash = self._compute_tx_hash(tx_bytes)
            return tx_hash

        try:
            error_body = resp.json()
            msg = error_body.get("message", resp.text)
        except Exception:
            msg = resp.text
        raise TransactionError(f"TX submission failed (HTTP {resp.status_code}): {msg}")

    @staticmethod
    def _compute_tx_hash(tx_bytes: bytes) -> str:
        """Compute the transaction hash (Blake2b-256 of the tx body)."""
        h = hashlib.blake2b(tx_bytes, digest_size=32)
        return h.hexdigest()

    async def close(self):
        """No-op — clients are created per-request."""
        pass
