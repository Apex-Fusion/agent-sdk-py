# vector-agent-sdk

Python Agent SDK for the Vector blockchain. Built on PyCardano + Ogmios.

## Quick Start

```python
from vector_agent import VectorAgent

agent = VectorAgent(
    ogmios_url="https://ogmios.vector.testnet.apexfusion.org",
    submit_url="https://submit.vector.testnet.apexfusion.org/api/submit/tx",
    mnemonic="your fifteen word mnemonic phrase here ...",
)

balance = await agent.get_balance()
tx = await agent.send(to="addr1...", ada=5.0)
```

## Installation

```bash
pip install vector-agent-sdk
```
