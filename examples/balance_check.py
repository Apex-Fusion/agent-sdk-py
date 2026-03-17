"""Example: Check balance using standalone VectorAgent."""

import asyncio

from vector_agent import VectorAgent


async def main():
    # Uses VECTOR_* env vars by default (see .env.example)
    async with VectorAgent() as agent:
        address = await agent.get_address()
        print(f"Address: {address}")

        balance = await agent.get_balance()
        print(f"ADA: {balance.ada}")
        print(f"Lovelace: {balance.lovelace}")

        if balance.tokens:
            print("Tokens:")
            for t in balance.tokens:
                print(f"  {t.asset_name} ({t.policy_id[:16]}...): {t.quantity}")

        utxos = await agent.get_utxos()
        print(f"UTxO count: {len(utxos)}")


if __name__ == "__main__":
    asyncio.run(main())
