# apex-fusion-agent-sdk

Python Agent SDK for the Vector blockchain. Built on PyCardano + Ogmios.

## Installation

```bash
pip install apex-fusion-agent-sdk
```

Requires Python >= 3.11.

## Quick Start

```python
import asyncio
from vector_agent import VectorAgent

async def main():
    async with VectorAgent() as agent:
        address = await agent.get_address()
        print(f"Address: {address}")

        balance = await agent.get_balance()
        print(f"ADA: {balance.ada}")

        tx = await agent.send(to="addr1...", ada=5.0)
        print(f"TX Hash: {tx.tx_hash}")
        print(f"Explorer: {tx.explorer_url}")

asyncio.run(main())
```

Configuration is read from environment variables by default (see [Configuration](#configuration)).

## Features

### Two Modes of Operation

- **`VectorAgent`** — Standalone mode. Talks directly to Ogmios and submit-api via PyCardano. No external server needed.
- **`VectorAgentMCP`** — MCP client mode. Connects to a TypeScript MCP server via stdio. Same API surface as `VectorAgent`.

### Wallet Management

- **HD Wallets** — BIP39 mnemonic with CIP-1852 derivation
- **`.skey` Files** — cardano-cli signing key files

### Transactions

- Send ADA and native tokens
- Build multi-output transactions
- Dry-run simulation with fee estimates
- Transaction history queries via Koios

### Smart Contracts

- Deploy PlutusV1/V2/V3 scripts
- Interact with deployed contracts (lock & spend)

### Safety Layer

- Configurable per-transaction and daily spend limits (in lovelace)
- Audit logging of all transactions

## API

### Query Methods

```python
await agent.get_address()                  # Agent's payment address
await agent.get_balance()                  # ADA + token balances
await agent.get_balance("addr1...")         # Balance of any address
await agent.get_utxos()                    # List UTxOs
await agent.get_protocol_parameters()      # Raw protocol params
await agent.get_spend_limits()             # Current spend limit status
await agent.get_transaction_history()      # TX history via Koios
```

### Transfer Methods

```python
# Send ADA
tx = await agent.send(to="addr1...", ada=5.0)
tx = await agent.send(to="addr1...", lovelace=5_000_000)

# Send native tokens
tx = await agent.send_tokens(
    to="addr1...",
    policy_id="abcd1234...",
    asset_name="MyToken",
    quantity=100,
)
```

### Advanced Transaction Building

```python
# Dry-run (simulate without submitting)
result = await agent.dry_run(to="addr1...", ada=5.0)
print(f"Fee: {result.fee_ada} ADA")

# Multi-output transaction
result = await agent.build_transaction(
    outputs=[
        {"address": "addr1...", "lovelace": 5_000_000},
        {"address": "addr1...", "lovelace": 3_000_000},
    ],
    submit=True,
)
```

### Smart Contracts

```python
# Deploy a script
result = await agent.deploy_contract(
    script_cbor="59...",
    script_type="PlutusV2",
    lovelace=2_000_000,
)
print(f"Script address: {result.script_address}")

# Interact with a deployed contract
result = await agent.interact_contract(
    script_cbor="59...",
    action="spend",
    utxo_ref={"tx_hash": "abcd...", "output_index": 0},
)
```

## MCP Client Mode

```python
from vector_agent import VectorAgentMCP

async with VectorAgentMCP(
    server_command="node",
    server_args=["build/index.js"],
    working_dir="/path/to/mcp-server",
) as agent:
    balance = await agent.get_balance()
```

`VectorAgentMCP` has the same API as `VectorAgent` — it delegates all operations to a TypeScript MCP server over stdio.

## Configuration

All settings can be passed as constructor arguments or read from environment variables:

| Environment Variable | Description | Default |
|---|---|---|
| `VECTOR_OGMIOS_URL` | Ogmios endpoint | — |
| `VECTOR_SUBMIT_URL` | Submit-api endpoint | — |
| `VECTOR_KOIOS_URL` | Koios endpoint (for history) | testnet |
| `VECTOR_EXPLORER_URL` | Block explorer base URL | testnet |
| `VECTOR_MNEMONIC` | BIP39 mnemonic | — |
| `VECTOR_SKEY_PATH` | Path to cardano-cli `.skey` file | — |
| `VECTOR_ACCOUNT_INDEX` | HD derivation account index | `0` |
| `VECTOR_SPEND_LIMIT_PER_TX` | Per-transaction limit (lovelace) | `100000000` (100 ADA) |
| `VECTOR_SPEND_LIMIT_DAILY` | Daily limit (lovelace) | `500000000` (500 ADA) |

See [.env.example](.env.example) for a template.

## License

MIT
