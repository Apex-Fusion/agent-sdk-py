"""VectorAgent — standalone mode using PyCardano + Ogmios directly."""

from __future__ import annotations

import os
from typing import Optional

from pycardano import TransactionBuilder, TransactionOutput
from pycardano.address import Address
from pycardano.hash import ScriptHash
from pycardano.transaction import Asset, AssetName, MultiAsset, Value

from vector_agent.chain.context import VectorChainContext
from vector_agent.chain.ogmios import OgmiosClient
from vector_agent.chain.submit import SubmitClient
from vector_agent.exceptions import (
    InsufficientFundsError,
    InvalidAddressError,
    TransactionError,
    VectorError,
    WalletError,
)
from vector_agent.safety import SafetyLayer
from vector_agent.types import TokenBalance, TokenTxResult, TxResult, VectorBalance
from vector_agent.wallet.hd import HDWallet
from vector_agent.wallet.skey import SkeyWallet


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def _lovelace_to_ada(lovelace: int) -> str:
    return f"{lovelace / 1_000_000:.6f}"


class VectorAgent:
    """Standalone Vector agent — talks directly to Ogmios and submit-api.

    Usage::

        agent = VectorAgent(
            ogmios_url="https://ogmios.vector.testnet.apexfusion.org",
            submit_url="https://submit.vector.testnet.apexfusion.org/api/submit/tx",
            mnemonic="word1 word2 ...",
        )
        balance = await agent.get_balance()
        tx = await agent.send(to="addr1...", ada=5.0)
    """

    def __init__(
        self,
        ogmios_url: str | None = None,
        submit_url: str | None = None,
        mnemonic: str | None = None,
        skey_path: str | None = None,
        account_index: int | None = None,
        spend_limit_per_tx: int | None = None,
        spend_limit_daily: int | None = None,
        explorer_url: str | None = None,
    ):
        # Resolve from env
        self._ogmios_url = ogmios_url or _env("VECTOR_OGMIOS_URL")
        self._submit_url = submit_url or _env("VECTOR_SUBMIT_URL")
        self._explorer_url = (
            explorer_url
            or _env("VECTOR_EXPLORER_URL", "https://vector.testnet.apexscan.org")
        )

        if not self._ogmios_url:
            raise VectorError("ogmios_url required (or set VECTOR_OGMIOS_URL)")
        if not self._submit_url:
            raise VectorError("submit_url required (or set VECTOR_SUBMIT_URL)")

        # Chain context
        self._ogmios = OgmiosClient(self._ogmios_url)
        self._submit = SubmitClient(self._submit_url)
        self._context = VectorChainContext(self._ogmios, self._submit)

        # Wallet
        mnemonic = mnemonic or _env("VECTOR_MNEMONIC")
        skey_path = skey_path or _env("VECTOR_SKEY_PATH")
        idx = account_index if account_index is not None else int(_env("VECTOR_ACCOUNT_INDEX", "0"))

        if mnemonic:
            self._wallet = HDWallet(mnemonic, account_index=idx)
        elif skey_path:
            self._wallet = SkeyWallet.from_file(skey_path)
        else:
            raise WalletError(
                "Provide mnemonic or skey_path (or set VECTOR_MNEMONIC / VECTOR_SKEY_PATH)"
            )

        # Safety
        per_tx = spend_limit_per_tx or int(_env("VECTOR_SPEND_LIMIT_PER_TX", "100000000"))
        daily = spend_limit_daily or int(_env("VECTOR_SPEND_LIMIT_DAILY", "500000000"))
        self._safety = SafetyLayer(per_tx_limit=per_tx, daily_limit=daily)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def address(self) -> str:
        """The agent's payment address (addr1...)."""
        return str(self._wallet.payment_address)

    @property
    def context(self) -> VectorChainContext:
        """The underlying PyCardano chain context."""
        return self._context

    @property
    def safety(self) -> SafetyLayer:
        """The safety layer instance."""
        return self._safety

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def get_address(self) -> str:
        """Get this agent's payment address."""
        return self.address

    async def get_balance(self, address: str | None = None) -> VectorBalance:
        """Get ADA and token balances for an address (default: own wallet)."""
        addr = address or self.address
        utxos = await self._context.async_utxos(addr)

        total_lovelace = 0
        token_map: dict[str, int] = {}

        for utxo in utxos:
            val = utxo.output.amount
            if isinstance(val, int):
                total_lovelace += val
            else:
                total_lovelace += val.coin
                if val.multi_asset:
                    for script_hash, assets in val.multi_asset.items():
                        for asset_name, qty in assets.items():
                            key = f"{script_hash.payload.hex()}.{asset_name.payload.hex()}"
                            token_map[key] = token_map.get(key, 0) + qty

        tokens = []
        for key, qty in token_map.items():
            policy_id, asset_hex = key.split(".", 1)
            try:
                name = bytes.fromhex(asset_hex).decode("utf-8")
            except Exception:
                name = asset_hex
            tokens.append(TokenBalance(policy_id=policy_id, asset_name=name, quantity=qty))

        return VectorBalance(
            address=addr,
            ada=_lovelace_to_ada(total_lovelace),
            lovelace=total_lovelace,
            tokens=tokens,
        )

    async def get_utxos(self, address: str | None = None) -> list:
        """List UTxOs for an address (default: own wallet).

        Returns PyCardano UTxO objects.
        """
        addr = address or self.address
        return await self._context.async_utxos(addr)

    async def get_protocol_parameters(self) -> dict:
        """Get raw protocol parameters from Ogmios."""
        return await self._ogmios.query_protocol_parameters()

    async def get_spend_limits(self):
        """Get current spend limit status."""
        return self._safety.get_spend_status()

    # ------------------------------------------------------------------
    # Transactions
    # ------------------------------------------------------------------

    async def send(
        self,
        to: str,
        lovelace: int = 0,
        ada: float = 0,
        metadata: dict | None = None,
    ) -> TxResult:
        """Send ADA to an address.

        Specify either ``lovelace`` or ``ada`` (not both).
        """
        if ada and lovelace:
            raise VectorError("Specify either lovelace or ada, not both")
        if ada:
            lovelace = int(ada * 1_000_000)
        if lovelace <= 0:
            raise VectorError("Amount must be positive")

        # Validate address
        try:
            recipient = Address.from_primitive(to)
        except Exception as e:
            raise InvalidAddressError(f"Invalid address: {to}: {e}") from e

        # Safety check
        self._safety.enforce_transaction(lovelace)

        # Ensure protocol params are loaded
        await self._context.async_protocol_param()

        # Build transaction
        try:
            builder = TransactionBuilder(self._context)
            builder.add_input_address(self._wallet.payment_address)
            builder.add_output(TransactionOutput(recipient, lovelace))

            # Metadata (label 674 for messages)
            if metadata:
                from pycardano import AuxiliaryData, Metadata

                aux = AuxiliaryData(data=Metadata(metadata))
                builder.auxiliary_data = aux

            tx = builder.build_and_sign(
                signing_keys=[self._wallet.payment_signing_key],
                change_address=self._wallet.payment_address,
            )
        except Exception as e:
            if "insufficient" in str(e).lower():
                raise InsufficientFundsError(f"Insufficient funds: {e}") from e
            raise TransactionError(f"Transaction build failed: {e}") from e

        # Submit
        tx_cbor = tx.to_cbor()
        if isinstance(tx_cbor, bytes):
            tx_cbor_hex = tx_cbor.hex()
        else:
            tx_cbor_hex = tx_cbor
        tx_hash = str(tx.id)

        try:
            await self._context.async_submit_tx_cbor(tx_cbor_hex)
        except Exception as e:
            raise TransactionError(f"Transaction submission failed: {e}") from e

        # Record in safety layer
        self._safety.record_transaction(tx_hash, lovelace, to)

        return TxResult(
            tx_hash=tx_hash,
            sender=self.address,
            recipient=to,
            amount_lovelace=lovelace,
            explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
        )

    async def send_tokens(
        self,
        to: str,
        policy_id: str,
        asset_name: str,
        quantity: int,
        ada: float = 2.0,
    ) -> TokenTxResult:
        """Send native tokens with companion ADA.

        Parameters
        ----------
        to: Recipient address
        policy_id: Token policy ID (hex)
        asset_name: Token asset name (UTF-8 string or hex)
        quantity: Number of tokens to send
        ada: Companion ADA amount (default 2.0 for min UTxO)
        """
        lovelace = int(ada * 1_000_000)

        # Validate address
        try:
            recipient = Address.from_primitive(to)
        except Exception as e:
            raise InvalidAddressError(f"Invalid address: {to}: {e}") from e

        # Safety check on the ADA portion
        self._safety.enforce_transaction(lovelace)

        # Ensure protocol params loaded
        await self._context.async_protocol_param()

        # Build multi-asset value
        try:
            script_hash = ScriptHash.from_primitive(policy_id)
            try:
                asset_bytes = asset_name.encode("utf-8")
            except Exception:
                asset_bytes = bytes.fromhex(asset_name)
            asset_name_obj = AssetName(asset_bytes)

            multi_asset = MultiAsset()
            multi_asset[script_hash] = Asset()
            multi_asset[script_hash][asset_name_obj] = quantity

            value = Value(lovelace, multi_asset)

            builder = TransactionBuilder(self._context)
            builder.add_input_address(self._wallet.payment_address)
            builder.add_output(TransactionOutput(recipient, value))

            tx = builder.build_and_sign(
                signing_keys=[self._wallet.payment_signing_key],
                change_address=self._wallet.payment_address,
            )
        except Exception as e:
            if "insufficient" in str(e).lower():
                raise InsufficientFundsError(f"Insufficient funds: {e}") from e
            raise TransactionError(f"Token transaction build failed: {e}") from e

        # Submit
        tx_cbor = tx.to_cbor()
        if isinstance(tx_cbor, bytes):
            tx_cbor_hex = tx_cbor.hex()
        else:
            tx_cbor_hex = tx_cbor
        tx_hash = str(tx.id)

        try:
            await self._context.async_submit_tx_cbor(tx_cbor_hex)
        except Exception as e:
            raise TransactionError(f"Token transaction submission failed: {e}") from e

        self._safety.record_transaction(tx_hash, lovelace, to)

        return TokenTxResult(
            tx_hash=tx_hash,
            sender=self.address,
            recipient=to,
            amount_lovelace=lovelace,
            explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
            policy_id=policy_id,
            asset_name=asset_name,
            token_quantity=quantity,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self):
        """Close underlying HTTP connections."""
        await self._ogmios.close()
        await self._submit.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
