"""Example: Use VectorAgentMCP to connect via SSE (hosted) or stdio (local)."""

import asyncio

from vector_agent import VectorAgentMCP


async def main():
    # SSE — connect to hosted MCP server (preferred).
    # URL can also be set via VECTOR_MCP_URL env var.
    agent = VectorAgentMCP(
        server_url="https://mcp.vector.testnet.apexfusion.org/sse",
    )

    async with agent:
        address = await agent.get_address()
        print(f"Address (via MCP/SSE): {address}")

        balance = await agent.get_balance()
        print(f"ADA (via MCP/SSE): {balance.ada}")

        limits = await agent.get_spend_limits()
        print(f"Daily limit: {limits.daily_limit / 1_000_000:.6f} ADA")


async def main_stdio():
    # stdio — spawn local TypeScript MCP server (fallback).
    agent = VectorAgentMCP(
        server_command="node",
        server_args=["build/index.js"],
        working_dir="/home/david/code/web3-mcp",
        server_env={
            "VECTOR_OGMIOS_URL": "https://ogmios.vector.testnet.apexfusion.org",
            "VECTOR_SUBMIT_URL": "https://submit.vector.testnet.apexfusion.org/api/submit/tx",
            "VECTOR_MNEMONIC": "your mnemonic here",
        },
    )

    async with agent:
        address = await agent.get_address()
        print(f"Address (via MCP/stdio): {address}")


if __name__ == "__main__":
    asyncio.run(main())
