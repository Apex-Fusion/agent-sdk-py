"""VectorAgentMCP — MCP client mode (SSE to hosted server, or stdio to local subprocess)."""

from __future__ import annotations

import json
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client

from vector_agent.exceptions import TransactionError, VectorError
from vector_agent.types import (
    BuildTxResult,
    DeployContractResult,
    DryRunResult,
    InteractContractResult,
    SpendStatus,
    TokenTxResult,
    TxResult,
    TxSummary,
    VectorBalance,
)


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


class VectorAgentMCP:
    """Vector agent that delegates to an MCP server.

    Connects via SSE (hosted) or stdio (local subprocess).

    Usage::

        # SSE — hosted server (preferred)
        async with VectorAgentMCP(server_url="https://mcp.vector.testnet.apexfusion.org/sse") as agent:
            balance = await agent.get_balance()

        # stdio — local subprocess (fallback)
        async with VectorAgentMCP(server_command="node", server_args=["build/index.js"]) as agent:
            balance = await agent.get_balance()
    """

    def __init__(
        self,
        server_url: str | None = None,
        server_headers: dict[str, str] | None = None,
        server_command: str | None = None,
        server_args: list[str] | None = None,
        server_env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ):
        self._server_url = server_url or _env("VECTOR_MCP_URL")
        self._server_headers = server_headers
        self._use_sse = self._server_url is not None

        self._server_command = server_command or _env("VECTOR_MCP_COMMAND", "node")
        self._server_args = server_args or self._default_server_args()
        self._server_env = server_env
        self._working_dir = working_dir

        self._session: ClientSession | None = None
        self._transport_context = None
        self._session_context = None

    def _default_server_args(self) -> list[str]:
        """Determine default args for spawning the MCP server."""
        mcp_server_path = _env("VECTOR_MCP_SERVER_PATH")
        if mcp_server_path:
            return [mcp_server_path]
        return ["build/index.js"]

    async def connect(self):
        """Connect to the MCP server (SSE if URL provided, stdio otherwise)."""
        if self._use_sse:
            self._transport_context = sse_client(
                url=self._server_url,
                headers=self._server_headers,
            )
        else:
            server_params = StdioServerParameters(
                command=self._server_command,
                args=self._server_args,
                env=self._server_env,
                cwd=self._working_dir,
            )
            self._transport_context = stdio_client(server_params)

        read_stream, write_stream = await self._transport_context.__aenter__()

        self._session_context = ClientSession(read_stream, write_stream)
        self._session = await self._session_context.__aenter__()

        await self._session.initialize()

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call an MCP tool and return the parsed result."""
        if self._session is None:
            raise VectorError("Not connected — call connect() or use async with")

        args = arguments or {}
        result = await self._session.call_tool(tool_name, args)

        # MCP tool results have a `content` list, each with `text`
        if result.content:
            text = result.content[0].text
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text

        return None

    # ------------------------------------------------------------------
    # Queries (mirror VectorAgent API)
    # ------------------------------------------------------------------

    async def get_address(self) -> str:
        """Get the agent's payment address via MCP."""
        result = await self._call_tool("vector_get_address")
        if isinstance(result, dict):
            return result.get("address", str(result))
        return str(result)

    async def get_balance(self, address: str | None = None) -> VectorBalance:
        """Get balance via MCP."""
        args = {}
        if address:
            args["address"] = address
        result = await self._call_tool("vector_get_balance", args)

        if isinstance(result, dict):
            tokens = []
            for t in result.get("tokens", []):
                from vector_agent.types import TokenBalance
                tokens.append(TokenBalance(
                    policy_id=t.get("policyId", t.get("policy_id", "")),
                    asset_name=t.get("name", t.get("asset_name", "")),
                    quantity=int(t.get("quantity", 0)),
                ))
            return VectorBalance(
                address=result.get("address", address or ""),
                ada=str(result.get("ada", "0")),
                lovelace=int(result.get("lovelace", 0)),
                tokens=tokens,
            )
        raise VectorError(f"Unexpected balance response: {result}")

    async def get_utxos(self, address: str | None = None) -> list[dict]:
        """Get UTxOs via MCP. Returns raw dicts (not PyCardano objects)."""
        args = {}
        if address:
            args["address"] = address
        result = await self._call_tool("vector_get_utxos", args)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("utxos", [])
        return []

    async def get_spend_limits(self) -> SpendStatus:
        """Get spend limit status via MCP."""
        result = await self._call_tool("vector_get_spend_limits")
        if isinstance(result, dict):
            return SpendStatus(
                per_transaction_limit=int(result.get("perTransactionLimit", result.get("per_transaction_limit", 0))),
                daily_limit=int(result.get("dailyLimit", result.get("daily_limit", 0))),
                daily_spent=int(result.get("dailySpent", result.get("daily_spent", 0))),
                daily_remaining=int(result.get("dailyRemaining", result.get("daily_remaining", 0))),
                reset_time=str(result.get("resetTime", result.get("reset_time", ""))),
            )
        raise VectorError(f"Unexpected spend limits response: {result}")

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
        """Send ADA via MCP."""
        if ada and lovelace:
            raise VectorError("Specify either lovelace or ada, not both")

        amount = lovelace if lovelace else int(ada * 1_000_000)
        args: dict[str, Any] = {
            "recipientAddress": to,
            "amount": amount / 1_000_000,  # MCP server expects ADA as number
        }
        if metadata:
            args["metadata"] = json.dumps(metadata)

        result = await self._call_tool("vector_send_ada", args)

        if isinstance(result, dict):
            return TxResult(
                tx_hash=result.get("txHash", result.get("tx_hash", "")),
                sender=result.get("senderAddress", result.get("sender", "")),
                recipient=result.get("recipientAddress", result.get("recipient", to)),
                amount_lovelace=int(float(result.get("amount", amount / 1_000_000)) * 1_000_000),
                explorer_url=result.get("links", {}).get("explorer", ""),
            )
        raise TransactionError(f"Unexpected send response: {result}")

    async def send_tokens(
        self,
        to: str,
        policy_id: str,
        asset_name: str,
        quantity: int,
        ada: float = 2.0,
    ) -> TokenTxResult:
        """Send native tokens via MCP."""
        args = {
            "recipientAddress": to,
            "policyId": policy_id,
            "assetName": asset_name,
            "amount": str(quantity),
        }

        result = await self._call_tool("vector_send_tokens", args)

        if isinstance(result, dict):
            token_info = result.get("token", {})
            return TokenTxResult(
                tx_hash=result.get("txHash", result.get("tx_hash", "")),
                sender=result.get("senderAddress", result.get("sender", "")),
                recipient=result.get("recipientAddress", result.get("recipient", to)),
                amount_lovelace=int(float(result.get("ada", ada)) * 1_000_000),
                explorer_url=result.get("links", {}).get("explorer", ""),
                policy_id=token_info.get("policyId", policy_id),
                asset_name=token_info.get("name", asset_name),
                token_quantity=int(token_info.get("amount", quantity)),
            )
        raise TransactionError(f"Unexpected token send response: {result}")

    # ------------------------------------------------------------------
    # Day 2: Advanced Operations (MCP wrappers)
    # ------------------------------------------------------------------

    async def dry_run(
        self,
        to: str,
        lovelace: int = 0,
        ada: float = 0,
    ) -> DryRunResult:
        """Dry run a transaction via MCP."""
        if ada and lovelace:
            raise VectorError("Specify either lovelace or ada, not both")
        if ada:
            lovelace = int(ada * 1_000_000)

        args = {
            "outputs": [{"address": to, "lovelace": lovelace}],
        }
        result = await self._call_tool("vector_dry_run", args)

        if isinstance(result, dict):
            return DryRunResult(
                valid=result.get("valid", True),
                fee_lovelace=int(result.get("fee", 0)),
                fee_ada=str(result.get("feeAda", "0")),
                execution_units=result.get("executionUnits"),
                error=result.get("error"),
            )
        # Return parsed from text
        return DryRunResult(valid=True, fee_lovelace=0, fee_ada="0")

    async def build_transaction(
        self,
        outputs: list[dict],
        metadata: dict | None = None,
        submit: bool = False,
    ) -> BuildTxResult:
        """Build a multi-output transaction via MCP."""
        args: dict[str, Any] = {"outputs": outputs}
        if metadata:
            args["metadata"] = json.dumps(metadata)
        if submit:
            args["submit"] = True

        result = await self._call_tool("vector_build_transaction", args)

        if isinstance(result, dict):
            return BuildTxResult(
                tx_cbor=result.get("txCbor", result.get("tx_cbor", "")),
                tx_hash=result.get("txHash", result.get("tx_hash", "")),
                fee_lovelace=int(result.get("fee", result.get("fee_lovelace", 0))),
                fee_ada=str(result.get("feeAda", result.get("fee_ada", "0"))),
                submitted=result.get("submitted", submit),
                explorer_url=result.get("links", {}).get("explorer"),
            )
        raise TransactionError(f"Unexpected build transaction response: {result}")

    async def get_transaction_history(
        self,
        address: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[TxSummary]:
        """Get transaction history via MCP."""
        args: dict[str, Any] = {}
        if address:
            args["address"] = address
        if limit != 20:
            args["limit"] = limit
        if offset != 0:
            args["offset"] = offset

        result = await self._call_tool("vector_get_transaction_history", args)

        if isinstance(result, list):
            return [
                TxSummary(
                    tx_hash=tx.get("txHash", tx.get("tx_hash", "")),
                    block_height=int(tx.get("blockHeight", tx.get("block_height", 0))),
                    block_time=str(tx.get("blockTime", tx.get("block_time", ""))),
                    fee=str(tx.get("fee", "0")),
                )
                for tx in result
            ]
        return []

    async def deploy_contract(
        self,
        script_cbor: str,
        script_type: str = "PlutusV2",
        initial_datum: str | None = None,
        lovelace: int = 2_000_000,
        as_reference_script: bool = False,
    ) -> DeployContractResult:
        """Deploy a smart contract via MCP."""
        args: dict[str, Any] = {
            "scriptCbor": script_cbor,
            "scriptType": script_type,
        }
        if initial_datum:
            args["initialDatum"] = initial_datum
        if lovelace != 2_000_000:
            args["lovelaceAmount"] = lovelace
        if as_reference_script:
            args["asReferenceScript"] = True

        result = await self._call_tool("vector_deploy_contract", args)

        if isinstance(result, dict):
            ref_utxo = result.get("referenceUtxo", result.get("reference_utxo"))
            return DeployContractResult(
                tx_hash=result.get("txHash", result.get("tx_hash", "")),
                sender="",
                recipient=result.get("scriptAddress", result.get("script_address", "")),
                amount_lovelace=lovelace,
                explorer_url=result.get("links", {}).get("explorer", ""),
                script_address=result.get("scriptAddress", result.get("script_address", "")),
                script_hash=result.get("scriptHash", result.get("script_hash", "")),
                script_type=result.get("scriptType", result.get("script_type", script_type)),
                reference_utxo=ref_utxo,
            )
        raise TransactionError(f"Unexpected deploy response: {result}")

    async def interact_contract(
        self,
        script_cbor: str | None = None,
        script_hash: str | None = None,
        script_type: str = "PlutusV2",
        action: str = "spend",
        redeemer: str | None = None,
        datum: str | None = None,
        lovelace: int = 2_000_000,
        utxo_ref: dict | None = None,
        reference_utxo: dict | None = None,
    ) -> InteractContractResult:
        """Interact with a smart contract via MCP."""
        args: dict[str, Any] = {
            "scriptType": script_type,
            "action": action,
        }
        if script_cbor:
            args["scriptCbor"] = script_cbor
        if script_hash:
            args["scriptHash"] = script_hash
        if redeemer:
            args["redeemer"] = redeemer
        if datum:
            args["datum"] = datum
        if lovelace != 2_000_000:
            args["lovelaceAmount"] = lovelace
        if utxo_ref:
            args["utxoRef"] = {
                "txHash": utxo_ref.get("tx_hash", utxo_ref.get("txHash", "")),
                "outputIndex": utxo_ref.get("output_index", utxo_ref.get("outputIndex", 0)),
            }
        if reference_utxo:
            args["referenceUtxo"] = {
                "txHash": reference_utxo.get("tx_hash", reference_utxo.get("txHash", "")),
                "outputIndex": reference_utxo.get("output_index", reference_utxo.get("outputIndex", 0)),
            }

        result = await self._call_tool("vector_interact_contract", args)

        if isinstance(result, dict):
            return InteractContractResult(
                tx_hash=result.get("txHash", result.get("tx_hash", "")),
                sender="",
                recipient=result.get("scriptAddress", result.get("script_address", "")),
                amount_lovelace=lovelace if action == "lock" else 0,
                explorer_url=result.get("links", {}).get("explorer", ""),
                script_address=result.get("scriptAddress", result.get("script_address", "")),
                action=action,
            )
        raise TransactionError(f"Unexpected contract interaction response: {result}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self):
        """Shut down the MCP session and transport."""
        if self._session_context:
            await self._session_context.__aexit__(None, None, None)
            self._session = None
        if self._transport_context:
            await self._transport_context.__aexit__(None, None, None)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()
