"""VectorAgent — standalone mode using PyCardano + Ogmios directly."""

from __future__ import annotations

import os
from typing import Optional

import httpx
from pycardano import TransactionBuilder, TransactionOutput
from pycardano.address import Address
from pycardano.hash import ScriptHash
from pycardano.plutus import PlutusV1Script, PlutusV2Script, PlutusData, RawPlutusData, script_hash as compute_script_hash
from pycardano.transaction import Asset, AssetName, MultiAsset, TransactionInput, Value

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
from vector_agent.types import (
    BuildTxResult,
    DeployContractResult,
    DryRunResult,
    InteractContractResult,
    TokenBalance,
    TokenTxResult,
    TxResult,
    TxSummary,
    VectorBalance,
)
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
        koios_url: str | None = None,
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
        self._koios_url = (
            koios_url
            or _env("VECTOR_KOIOS_URL", "https://koios.vector.testnet.apexfusion.org")
        )
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
    # Day 2: Advanced Operations
    # ------------------------------------------------------------------

    async def dry_run(
        self,
        to: str,
        lovelace: int = 0,
        ada: float = 0,
    ) -> DryRunResult:
        """Simulate a transaction without submitting — returns fee estimate.

        Parameters
        ----------
        to: Recipient address
        lovelace: Amount in lovelace
        ada: Amount in ADA (alternative to lovelace)
        """
        if ada and lovelace:
            raise VectorError("Specify either lovelace or ada, not both")
        if ada:
            lovelace = int(ada * 1_000_000)
        if lovelace <= 0:
            raise VectorError("Amount must be positive")

        try:
            recipient = Address.from_primitive(to)
        except Exception as e:
            raise InvalidAddressError(f"Invalid address: {to}: {e}") from e

        await self._context.async_protocol_param()

        try:
            builder = TransactionBuilder(self._context)
            builder.add_input_address(self._wallet.payment_address)
            builder.add_output(TransactionOutput(recipient, lovelace))

            tx = builder.build(
                change_address=self._wallet.payment_address,
            )
            fee = tx.transaction_body.fee
            tx_cbor = tx.to_cbor()
            if isinstance(tx_cbor, bytes):
                tx_cbor_hex = tx_cbor.hex()
            else:
                tx_cbor_hex = tx_cbor

            # Evaluate via Ogmios
            eval_result = None
            try:
                eval_result = await self._ogmios.evaluate_tx(tx_cbor_hex)
            except Exception:
                pass  # Evaluation is optional

            execution_units = None
            if eval_result and isinstance(eval_result, list):
                total_mem = sum(item.get("budget", {}).get("memory", 0) for item in eval_result)
                total_cpu = sum(item.get("budget", {}).get("cpu", 0) for item in eval_result)
                if total_mem > 0 or total_cpu > 0:
                    execution_units = {"memory": total_mem, "cpu": total_cpu}

            return DryRunResult(
                valid=True,
                fee_lovelace=fee,
                fee_ada=_lovelace_to_ada(fee),
                execution_units=execution_units,
            )
        except Exception as e:
            return DryRunResult(
                valid=False,
                fee_lovelace=0,
                fee_ada="0",
                error=str(e),
            )

    async def build_transaction(
        self,
        outputs: list[dict],
        metadata: dict | None = None,
        submit: bool = False,
    ) -> BuildTxResult:
        """Build a multi-output transaction.

        Parameters
        ----------
        outputs: List of dicts with 'address', 'lovelace', optional 'assets'
        metadata: Optional transaction metadata
        submit: If True, sign and submit. If False, return unsigned CBOR.
        """
        if not outputs:
            raise VectorError("At least one output is required")

        total_lovelace = sum(o.get("lovelace", 0) for o in outputs)
        self._safety.enforce_transaction(total_lovelace)

        await self._context.async_protocol_param()

        try:
            builder = TransactionBuilder(self._context)
            builder.add_input_address(self._wallet.payment_address)

            for output in outputs:
                addr = Address.from_primitive(output["address"])
                lovelace = int(output.get("lovelace", 2_000_000))
                assets_dict = output.get("assets")

                if assets_dict:
                    multi_asset = MultiAsset()
                    for unit, qty in assets_dict.items():
                        # unit = policyId (56 chars) + assetNameHex
                        policy_hex = unit[:56]
                        asset_hex = unit[56:]
                        sh = ScriptHash.from_primitive(policy_hex)
                        an = AssetName(bytes.fromhex(asset_hex)) if asset_hex else AssetName(b"")
                        if sh not in multi_asset:
                            multi_asset[sh] = Asset()
                        multi_asset[sh][an] = int(qty)
                    value = Value(lovelace, multi_asset)
                else:
                    value = lovelace

                builder.add_output(TransactionOutput(addr, value))

            if metadata:
                from pycardano import AuxiliaryData, Metadata
                aux = AuxiliaryData(data=Metadata(metadata))
                builder.auxiliary_data = aux

            if submit:
                tx = builder.build_and_sign(
                    signing_keys=[self._wallet.payment_signing_key],
                    change_address=self._wallet.payment_address,
                )
                tx_cbor = tx.to_cbor()
                if isinstance(tx_cbor, bytes):
                    tx_cbor_hex = tx_cbor.hex()
                else:
                    tx_cbor_hex = tx_cbor
                tx_hash = str(tx.id)

                await self._context.async_submit_tx_cbor(tx_cbor_hex)
                recipients = ", ".join(o["address"] for o in outputs)
                self._safety.record_transaction(tx_hash, total_lovelace, recipients)

                return BuildTxResult(
                    tx_cbor="",
                    tx_hash=tx_hash,
                    fee_lovelace=tx.transaction_body.fee,
                    fee_ada=_lovelace_to_ada(tx.transaction_body.fee),
                    submitted=True,
                    explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
                )
            else:
                tx = builder.build(change_address=self._wallet.payment_address)
                tx_cbor = tx.to_cbor()
                if isinstance(tx_cbor, bytes):
                    tx_cbor_hex = tx_cbor.hex()
                else:
                    tx_cbor_hex = tx_cbor
                tx_hash = str(tx.id)

                return BuildTxResult(
                    tx_cbor=tx_cbor_hex,
                    tx_hash=tx_hash,
                    fee_lovelace=tx.transaction_body.fee,
                    fee_ada=_lovelace_to_ada(tx.transaction_body.fee),
                    submitted=False,
                )
        except Exception as e:
            if "insufficient" in str(e).lower():
                raise InsufficientFundsError(f"Insufficient funds: {e}") from e
            raise TransactionError(f"Build transaction failed: {e}") from e

    async def get_transaction_history(
        self,
        address: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[TxSummary]:
        """Get transaction history via Koios.

        Parameters
        ----------
        address: Address to query (default: own wallet)
        limit: Max transactions to return (1-50)
        offset: Pagination offset
        """
        addr = address or self.address
        koios_url = self._koios_url.rstrip("/")

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Get tx hashes
            resp = await client.post(
                f"{koios_url}/api/v1/address_txs",
                json={"_addresses": [addr], "_after_block_height": 0},
            )
            resp.raise_for_status()
            tx_list = resp.json()

            # Paginate
            paginated = tx_list[offset : offset + limit]
            if not paginated:
                return []

            # Step 2: Get full tx info
            tx_hashes = [tx["tx_hash"] for tx in paginated]
            try:
                info_resp = await client.post(
                    f"{koios_url}/api/v1/tx_info",
                    json={"_tx_hashes": tx_hashes},
                )
                info_resp.raise_for_status()
                tx_infos = info_resp.json()

                return [
                    TxSummary(
                        tx_hash=info["tx_hash"],
                        block_height=info.get("block_height", 0),
                        block_time=(
                            str(info.get("tx_timestamp", info.get("block_time", "")))
                        ),
                        fee=str(info.get("fee", "0")),
                    )
                    for info in tx_infos
                ]
            except Exception:
                # Fallback to basic info from address_txs
                return [
                    TxSummary(
                        tx_hash=tx["tx_hash"],
                        block_height=tx.get("block_height", 0),
                        block_time=str(tx.get("block_time", "")),
                        fee="0",
                    )
                    for tx in paginated
                ]

    async def deploy_contract(
        self,
        script_cbor: str,
        script_type: str = "PlutusV2",
        initial_datum: bytes | None = None,
        lovelace: int = 2_000_000,
    ) -> DeployContractResult:
        """Deploy a Plutus/Aiken smart contract by locking funds at its script address.

        Parameters
        ----------
        script_cbor: Compiled script CBOR hex
        script_type: "PlutusV1", "PlutusV2", or "PlutusV3"
        initial_datum: Optional datum bytes (CBOR). Defaults to void (Constr(0, []))
        lovelace: ADA to lock in lovelace (default 2 ADA)
        """
        self._safety.enforce_transaction(lovelace)
        await self._context.async_protocol_param()

        # Parse script
        script_bytes = bytes.fromhex(script_cbor)
        if script_type == "PlutusV1":
            script = PlutusV1Script(script_bytes)
        else:
            # PlutusV2 and PlutusV3 both use PlutusV2Script in pycardano
            # (PlutusV3 is not yet separate in most pycardano versions)
            script = PlutusV2Script(script_bytes)

        script_hash_val = compute_script_hash(script)
        script_address = Address(script_hash_val, network=self._context.network)

        # Datum
        if initial_datum:
            import cbor2
            datum = RawPlutusData(cbor2.loads(initial_datum))
        else:
            # Void datum: Constr(0, [])
            from pycardano.plutus import PlutusData
            datum = PlutusData()

        try:
            builder = TransactionBuilder(self._context)
            builder.add_input_address(self._wallet.payment_address)
            builder.add_output(
                TransactionOutput(script_address, lovelace, datum=datum)
            )

            tx = builder.build_and_sign(
                signing_keys=[self._wallet.payment_signing_key],
                change_address=self._wallet.payment_address,
            )

            tx_cbor_out = tx.to_cbor()
            if isinstance(tx_cbor_out, bytes):
                tx_cbor_hex = tx_cbor_out.hex()
            else:
                tx_cbor_hex = tx_cbor_out
            tx_hash = str(tx.id)

            await self._context.async_submit_tx_cbor(tx_cbor_hex)
            self._safety.record_transaction(tx_hash, lovelace, str(script_address))

            return DeployContractResult(
                tx_hash=tx_hash,
                sender=self.address,
                recipient=str(script_address),
                amount_lovelace=lovelace,
                explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
                script_address=str(script_address),
                script_hash=str(script_hash_val),
                script_type=script_type,
            )
        except Exception as e:
            if "insufficient" in str(e).lower():
                raise InsufficientFundsError(f"Insufficient funds: {e}") from e
            raise TransactionError(f"Deploy contract failed: {e}") from e

    async def interact_contract(
        self,
        script_cbor: str,
        script_type: str = "PlutusV2",
        action: str = "spend",
        redeemer: bytes | None = None,
        datum: bytes | None = None,
        lovelace: int = 2_000_000,
        utxo_ref: dict | None = None,
    ) -> InteractContractResult:
        """Interact with a deployed smart contract.

        Parameters
        ----------
        script_cbor: Compiled script CBOR hex
        script_type: "PlutusV1", "PlutusV2", or "PlutusV3"
        action: "spend" to collect from script, "lock" to send funds to it
        redeemer: Redeemer bytes (CBOR, for spend). Defaults to void.
        datum: Datum bytes (CBOR, for lock). Defaults to void.
        lovelace: ADA amount in lovelace (for lock)
        utxo_ref: Optional {"tx_hash": "...", "output_index": N} for specific UTxO
        """
        await self._context.async_protocol_param()

        script_bytes = bytes.fromhex(script_cbor)
        if script_type == "PlutusV1":
            script = PlutusV1Script(script_bytes)
        else:
            script = PlutusV2Script(script_bytes)

        script_hash_val = compute_script_hash(script)
        script_address = Address(script_hash_val, network=self._context.network)

        if action == "lock":
            self._safety.enforce_transaction(lovelace)

            if datum:
                import cbor2
                datum_obj = RawPlutusData(cbor2.loads(datum))
            else:
                from pycardano.plutus import PlutusData
                datum_obj = PlutusData()

            try:
                builder = TransactionBuilder(self._context)
                builder.add_input_address(self._wallet.payment_address)
                builder.add_output(
                    TransactionOutput(script_address, lovelace, datum=datum_obj)
                )

                tx = builder.build_and_sign(
                    signing_keys=[self._wallet.payment_signing_key],
                    change_address=self._wallet.payment_address,
                )
                tx_cbor_out = tx.to_cbor()
                if isinstance(tx_cbor_out, bytes):
                    tx_cbor_hex = tx_cbor_out.hex()
                else:
                    tx_cbor_hex = tx_cbor_out
                tx_hash = str(tx.id)

                await self._context.async_submit_tx_cbor(tx_cbor_hex)
                self._safety.record_transaction(tx_hash, lovelace, str(script_address))

                return InteractContractResult(
                    tx_hash=tx_hash,
                    sender=self.address,
                    recipient=str(script_address),
                    amount_lovelace=lovelace,
                    explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
                    script_address=str(script_address),
                    action="lock",
                )
            except Exception as e:
                if "insufficient" in str(e).lower():
                    raise InsufficientFundsError(f"Insufficient funds: {e}") from e
                raise TransactionError(f"Lock to contract failed: {e}") from e

        else:
            # SPEND: collect from script
            if redeemer:
                import cbor2
                redeemer_obj = RawPlutusData(cbor2.loads(redeemer))
            else:
                from pycardano.plutus import PlutusData
                redeemer_obj = PlutusData()

            # Find UTxOs at script address
            script_utxos = await self._context.async_utxos(str(script_address))

            if utxo_ref:
                # Filter to specific UTxO
                target_hash = utxo_ref["tx_hash"]
                target_idx = utxo_ref["output_index"]
                script_utxos = [
                    u for u in script_utxos
                    if str(u.input.transaction_id) == target_hash
                    and u.input.index == target_idx
                ]

            if not script_utxos:
                raise TransactionError(f"No UTxOs found at script address {script_address}")

            try:
                from pycardano import Redeemer
                builder = TransactionBuilder(self._context)
                builder.add_input_address(self._wallet.payment_address)

                for utxo in script_utxos:
                    builder.add_script_input(
                        utxo,
                        script=script,
                        datum=utxo.output.datum,
                        redeemer=Redeemer(redeemer_obj),
                    )

                builder.required_signers = [self._wallet.payment_verification_key.hash()]

                tx = builder.build_and_sign(
                    signing_keys=[self._wallet.payment_signing_key],
                    change_address=self._wallet.payment_address,
                )
                tx_cbor_out = tx.to_cbor()
                if isinstance(tx_cbor_out, bytes):
                    tx_cbor_hex = tx_cbor_out.hex()
                else:
                    tx_cbor_hex = tx_cbor_out
                tx_hash = str(tx.id)

                await self._context.async_submit_tx_cbor(tx_cbor_hex)

                return InteractContractResult(
                    tx_hash=tx_hash,
                    sender=str(script_address),
                    recipient=self.address,
                    amount_lovelace=0,
                    explorer_url=f"{self._explorer_url}/transaction/{tx_hash}",
                    script_address=str(script_address),
                    action="spend",
                )
            except Exception as e:
                if "insufficient" in str(e).lower():
                    raise InsufficientFundsError(f"Insufficient funds: {e}") from e
                raise TransactionError(f"Spend from contract failed: {e}") from e

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
