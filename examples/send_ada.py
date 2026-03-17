"""Example: Send ADA using standalone VectorAgent."""

import asyncio

from vector_agent import VectorAgent


async def main():
    async with VectorAgent() as agent:
        address = await agent.get_address()
        print(f"Sending from: {address}")

        # Check balance first
        balance = await agent.get_balance()
        print(f"Current balance: {balance.ada} ADA")

        # Check spend limits
        limits = await agent.get_spend_limits()
        print(f"Daily remaining: {limits.daily_remaining / 1_000_000:.6f} ADA")

        # Send 5 ADA
        recipient = "addr1..."  # Replace with actual address
        tx = await agent.send(to=recipient, ada=5.0)
        print(f"TX Hash: {tx.tx_hash}")
        print(f"Explorer: {tx.explorer_url}")


if __name__ == "__main__":
    asyncio.run(main())
