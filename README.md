# apex-fusion-agent-sdk

Python Agent SDK for **Vector**, the Apex Fusion eUTXO L2. Built on PyCardano + Ogmios.

**Vector mainnet is live.** Full guides: [Vector AI documentation](https://apex-fusion.github.io/vector-ai-documentation/).

## Installation

```bash
pip install apex-fusion-agent-sdk
```

Requires Python >= 3.11.

## Networks

Vector runs a public testnet and mainnet. The SDK talks to whichever endpoints you configure:

| Variable | Testnet | Mainnet |
|---|---|---|
| `VECTOR_OGMIOS_URL` | `https://ogmios.vector.testnet.apexfusion.org` | `https://ogmios.vector.mainnet.apexfusion.org` |
| `VECTOR_SUBMIT_URL` | `https://submit.vector.testnet.apexfusion.org/api/submit/tx` | `https://submit.vector.mainnet.apexfusion.org/api/submit/tx` |
| `VECTOR_KOIOS_URL` | `https://v2.koios.vector.testnet.apexfusion.org/` | `https://v2.koios.vector.mainnet.apexfusion.org/` |
| `VECTOR_EXPLORER_URL` | `https://vector.testnet.apexscan.org` | `https://vector.apexscan.org/en/` |

Two things to know: Vector's testnet uses the **mainnet network ID**, so all addresses start with `addr1`. And the native coin is **AP3X** (smallest unit DFM, 1 AP3X = 1,000,000 DFM). Since 0.1.11 the amount parameters accept `apex=` (whole AP3X) and `dfm=` (smallest unit) as the preferred names; `ada=`/`lovelace=` remain as compatibility aliases from the underlying Cardano tooling, and response fields keep their tooling names. 0.1.11 also adds `vector_agent.self_improvement` as the preferred import for the Game 6 client (`SelfImprovementClient`); `vector_agent.governance` remains as a compatibility alias.

## Quick Start

```python
import asyncio
from vector_agent import VectorAgent

async def main():
    async with VectorAgent() as agent:
        address = await agent.get_address()
        print(f"Address: {address}")

        balance = await agent.get_balance()
        print(f"AP3X: {balance.ada}")

        tx = await agent.send(to="addr1...", apex=5.0)
        print(f"TX Hash: {tx.tx_hash}")
        print(f"Explorer: {tx.explorer_url}")

asyncio.run(main())
```

Configuration is read from environment variables by default (see [Configuration](#configuration)).

## Features

### Two Modes of Operation

- **`VectorAgent`** - Standalone mode. Talks directly to Ogmios and submit-api via PyCardano. No external server needed.
- **`VectorAgentMCP`** - MCP client mode. Connects to a TypeScript MCP server via stdio. Same API surface as `VectorAgent`.

### Wallet Management

- **HD Wallets** - BIP39 mnemonic with CIP-1852 derivation
- **`.skey` Files** - cardano-cli signing key files

### Transactions

- Send AP3X and native tokens
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
await agent.get_balance()                  # AP3X + token balances
await agent.get_balance("addr1...")         # Balance of any address
await agent.get_utxos()                    # List UTxOs
await agent.get_protocol_parameters()      # Raw protocol params
await agent.get_spend_limits()             # Current spend limit status
await agent.get_transaction_history()      # TX history via Koios
```

### Transfer Methods

```python
# Send AP3X
tx = await agent.send(to="addr1...", apex=5.0)
tx = await agent.send(to="addr1...", dfm=5_000_000)
# ada= / lovelace= still work as compatibility aliases

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
print(f"Fee: {result.fee_ada} AP3X")

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

`VectorAgentMCP` has the same API as `VectorAgent` - it delegates all operations to a TypeScript MCP server over stdio.

## Configuration

All settings can be passed as constructor arguments or read from environment variables:

| Environment Variable | Description | Default |
|---|---|---|
| `VECTOR_OGMIOS_URL` | Ogmios endpoint | - |
| `VECTOR_SUBMIT_URL` | Submit-api endpoint | - |
| `VECTOR_KOIOS_URL` | Koios endpoint (for history) | testnet |
| `VECTOR_EXPLORER_URL` | Block explorer base URL | testnet |
| `VECTOR_MNEMONIC` | BIP39 mnemonic | - |
| `VECTOR_SKEY_PATH` | Path to cardano-cli `.skey` file | - |
| `VECTOR_ACCOUNT_INDEX` | HD derivation account index | `0` |
| `VECTOR_SPEND_LIMIT_PER_TX` | Per-transaction limit (lovelace) | `100000000` (100 AP3X) |
| `VECTOR_SPEND_LIMIT_DAILY` | Daily limit (lovelace) | `500000000` (500 AP3X) |

See [.env.example](.env.example) for a template.

## License

MIT
