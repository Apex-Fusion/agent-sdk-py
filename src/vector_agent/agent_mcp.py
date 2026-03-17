"""VectorAgentMCP — MCP client mode that connects to the TypeScript MCP server."""

from __future__ import annotations

import json
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vector_agent.exceptions import TransactionError, VectorError
from vector_agent.types import SpendStatus, TokenTxResult, TxResult, VectorBalance


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


class VectorAgentMCP:
    """Vector agent that delegates to the TypeScript MCP server.

    Spawns the MCP server as a subprocess and communicates via stdio.

    Usage::

        async with VectorAgentMCP() as agent:
            balance = await agent.get_balance()
            tx = await agent.send(to="addr1...", ada=5.0)
    """

    def __init__(
        self,
        server_command: str | None = None,
        server_args: list[str] | None = None,
        server_env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ):
        self._server_command = server_command or _env("VECTOR_MCP_COMMAND", "node")
        self._server_args = server_args or self._default_server_args()
        self._server_env = server_env
        self._working_dir = working_dir

        self._session: ClientSession | None = None
        self._stdio_context = None
        self._session_context = None

    def _default_server_args(self) -> list[str]:
        """Determine default args for spawning the MCP server."""
        mcp_server_path = _env("VECTOR_MCP_SERVER_PATH")
        if mcp_server_path:
            return [mcp_server_path]
        return ["build/index.js"]

    async def connect(self):
        """Spawn the TypeScript MCP server and establish a session."""
        server_params = StdioServerParameters(
            command=self._server_command,
            args=self._server_args,
            env=self._server_env,
            cwd=self._working_dir,
        )

        self._stdio_context = stdio_client(server_params)
        read_stream, write_stream = await self._stdio_context.__aenter__()

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
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self):
        """Shut down the MCP session and server process."""
        if self._session_context:
            await self._session_context.__aexit__(None, None, None)
            self._session = None
        if self._stdio_context:
            await self._stdio_context.__aexit__(None, None, None)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()
