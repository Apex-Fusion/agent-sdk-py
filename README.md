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

## Identity registry (`did:vector`)

`vector_agent.identity` has clients for the Vector identity registry and the contracts that use it. The builders read the ledger (Ogmios and Koios) and return an **unsigned** transaction with every key hash that must sign it. The SDK never signs: each key holder adds a witness in turn.

```python
from vector_agent.identity import (
    IdentityContext, IdentityRegistry, KeyHashSigner, PartySpec, Role, add_signatures,
)

ctx = IdentityContext.connect()          # IdentityConfig.from_env(), Vector mainnet endpoints
registry = IdentityRegistry(ctx)
built = registry.register(
    "addr1...",                          # pays the fee and the deposit: max(10 AP3X, ledger minimum)
    controller=controller_public_key,     # 32-byte Ed25519 key
    name="My agent",
    endpoint="https://agent.example.org/mcp",
    capabilities=["llm.chat"],
    parties=[PartySpec(Role.ACCOUNTABLE, KeyHashSigner(accountable_key_hash))],
)
print(built.created_id, built.required_signers)    # the new vector-id and the signers
signed = add_signatures(built.transaction, [payer_key, controller_key, accountable_key])
ctx.ledger.context.submit_tx(signed)

view = registry.current_record(built.created_id)   # the gateway's view (effective status, keys, ...)
```

| Client | Operations |
|---|---|
| `IdentityRegistry` | `register` (with `parent=` for a subagent), `adopt`, `update`, `change_controller`, `suspend`, `unsuspend`, `revoke`, `retire`, `reclaim`, `set_successor`, `start_recovery`, `cancel_recovery`, `complete_recovery`, `end_subagents`; reads `record`, `resolve`, `current_record` |
| `Attestations` | `attest`, `revoke`, `contest`, `withdraw`; `get` |
| `Delegations` | `delegate`, `undelegate`; `get` |
| `Vaults` | `open`, `pay`, `close`; `get`, `list` |
| `IdentityGateway` | `resolve` (HTTPS binding `GET /1.0/identifiers/{did}`), `current_record` |

A builder refuses a transaction that the contract would reject: it raises `IdentityRuleError` with the broken rule. A missing record raises `IdentityLookupError`.

The script parameters are deployment values. The SDK applies them to the embedded unapplied scripts:

| Environment variable | Description |
|---|---|
| `VECTOR_IDENTITY_LEGACY_ROOT` | Allowlist Merkle root (64 hex). Required for transactions. |
| `VECTOR_IDENTITY_CONFIG_SEED` | Seed of the configuration policy, `<tx id>#<index>`. Required for transactions. |
| `VECTOR_IDENTITY_POLICY_ID` | Optional check: the identity policy ID that the two values above must give. |
| `VECTOR_IDENTITY_LEGACY_HASH` | Legacy registry hash. Default `be1a0a29…2c01`. |
| `VECTOR_IDENTITY_REF_UTXO`, `VECTOR_ATTESTATION_REF_UTXO`, `VECTOR_DELEGATION_REF_UTXO`, `VECTOR_VAULT_REF_UTXO`, `VECTOR_LEGACY_REGISTRY_REF_UTXO` | Reference-script outputs, `<tx id>#<index>`. Without one, the transaction carries the script. |
| `VECTOR_MODULE1_REF_UTXO` | Reference script of Module-1 `identity_party`; needed only to appoint Module-1 as a party. |
| `VECTOR_IDENTITY_CONFIG_UTXO` | The configuration record. Default: found at the configuration address. |
| `VECTOR_IDENTITY_GATEWAY_URL` | Default `https://id.vector.apexfusion.org`. |
| `VECTOR_OGMIOS_URL`, `VECTOR_KOIOS_URL`, `VECTOR_KOIOS_TOKEN` | Ledger reads. Defaults: Vector mainnet Ogmios and Koios. |
| `VECTOR_MARKETPLACE_INDEXER_URL` | Indexer for the advert listing check of `Vaults.pay`. |

## Self-Improvement module (Module-6)

`vector_agent.governance` (also `vector_agent.self_improvement`) works on the Module-6 deployment that reads identity records (Part 2 §7). `Governance` builds every transaction and returns it unsigned with its signers; `GovernanceClient` runs the flows of a `VectorAgent` (lock, then create) and signs with the agent wallet.

```python
from vector_agent.governance import GovernanceClient, GovernanceDeployment

gov = GovernanceClient(agent, GovernanceDeployment.from_deploy_state("deploy_state.json"))
proposal = await gov.submit_proposal("did:vector:<64 hex>", proposal_hash, "ipfs://Qm...")
await gov.endorse_proposal("did:vector:<other agent>", proposal["seed"])  # name the proposal by its seed
```

- Proposals, amendments, critiques and endorsements read the agent's record and its ancestors (reference inputs) over a validity range of at most one hour. `submitted_at` and `created_at` are its lower bound. The credential is the wallet key or `credential_key`: the controller or a listed key with the transaction purpose.
- A first proposal inserts the agent's node into the activity list; later proposals continue that node.
- Withdrawals, expiry, adoption, rejection and review extension return each stake to the credential in its datum; `settle=` burns and pays out critiques and endorsements in the same transaction.
- The deployment values come from `VECTOR_MODULE6_*` (see `.env.example`) or the deploy state. The SDK applies them to the embedded Module-6 blueprint (vector-agent-modules `91e3823`). The new deployment is not live, so there are no defaults.

## License

MIT
