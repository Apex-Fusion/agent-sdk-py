"""Load cardano-cli signing key (.skey) files.

Supports the standard Shelley-era JSON envelope produced by ``cardano-cli``::

    {
        "type": "PaymentSigningKeyShelley_ed25519",
        "description": "Payment Signing Key",
        "cborHex": "5820..."
    }

The ``cborHex`` field contains a CBOR-wrapped ed25519 private key (the first
two bytes ``5820`` are the CBOR major-type tag for a 32-byte bytestring).
"""

from __future__ import annotations

import json
from pathlib import Path

from pycardano import Address, Network, PaymentSigningKey, PaymentVerificationKey

from vector_agent.exceptions import WalletError


class SkeyWallet:
    """Wallet backed by a cardano-cli ``.skey`` file."""

    def __init__(self, signing_key: PaymentSigningKey) -> None:
        self._payment_sk = signing_key

    # -- constructors --------------------------------------------------------

    @classmethod
    def from_file(cls, skey_path: str) -> SkeyWallet:
        """Read a JSON ``.skey`` envelope produced by ``cardano-cli``.

        Parameters
        ----------
        skey_path:
            Filesystem path to the ``.skey`` JSON file.
        """
        path = Path(skey_path)
        try:
            data = json.loads(path.read_text())
            cbor_hex: str = data["cborHex"]
        except FileNotFoundError as exc:
            raise WalletError(f"Signing key file not found: {path}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            raise WalletError(
                f"Invalid signing key file format: {path}: {exc}"
            ) from exc
        return cls.from_cbor_hex(cbor_hex)

    @classmethod
    def from_cbor_hex(cls, cbor_hex: str) -> SkeyWallet:
        """Parse a CBOR-hex encoded ed25519 private key.

        The standard cardano-cli encoding prefixes the 32-byte key with
        ``5820`` (CBOR bytestring header for 32 bytes).
        """
        try:
            # Strip the CBOR wrapper — first 4 hex chars (2 bytes) are the
            # CBOR major-type + length for a 32-byte bytestring (0x5820).
            raw_hex = cbor_hex[4:]
            signing_key = PaymentSigningKey.from_primitive(
                bytes.fromhex(raw_hex)
            )
        except Exception as exc:
            raise WalletError(f"Failed to parse signing key CBOR: {exc}") from exc
        return cls(signing_key)

    # -- keys ----------------------------------------------------------------

    @property
    def payment_signing_key(self) -> PaymentSigningKey:
        """The ed25519 payment signing key."""
        return self._payment_sk

    @property
    def payment_verification_key(self) -> PaymentVerificationKey:
        """Verification (public) key derived from the signing key."""
        return PaymentVerificationKey.from_signing_key(self._payment_sk)

    # -- address -------------------------------------------------------------

    @property
    def payment_address(self) -> Address:
        """Enterprise address on mainnet (no staking part) — ``addr1...`` prefix."""
        return Address(
            payment_part=self.payment_verification_key.hash(),
            network=Network.MAINNET,
        )
