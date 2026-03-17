"""Example: Use VectorAgentMCP to connect to the TypeScript MCP server."""

import asyncio

from vector_agent import VectorAgentMCP


async def main():
    # Spawns the TS MCP server and communicates via stdio
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
        print(f"Address (via MCP): {address}")

        balance = await agent.get_balance()
        print(f"ADA (via MCP): {balance.ada}")

        limits = await agent.get_spend_limits()
        print(f"Daily limit: {limits.daily_limit / 1_000_000:.6f} ADA")


if __name__ == "__main__":
    asyncio.run(main())
