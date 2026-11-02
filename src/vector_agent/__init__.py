"""Vector Agent SDK — Python SDK for the Vector blockchain.

Modes of operation:
- ``VectorAgent``: Standalone mode (direct PyCardano + Ogmios)
- ``VectorAgentMCP``: MCP client mode (Streamable HTTP to the hosted server, or stdio to a local subprocess)
- ``vector_agent.identity``: identity registry (``did:vector``), attestation, delegation and vault
  clients; they build unsigned transactions and resolve DIDs through the identity gateway
"""

from vector_agent import governance as governance
from vector_agent import identity as identity
from vector_agent import self_improvement as self_improvement
from vector_agent.agent import VectorAgent
from vector_agent.agent_mcp import VectorAgentMCP
from vector_agent.exceptions import (
    InsufficientFundsError,
    InvalidAddressError,
    SpendLimitExceededError,
    TransactionError,
    VectorError,
    WalletError,
)
from vector_agent.types import (
    AuditEntry,
    BuildTxResult,
    DeployContractResult,
    DryRunResult,
    InteractContractResult,
    SpendStatus,
    TokenBalance,
    TokenTxResult,
    TxResult,
    TxSummary,
    VectorBalance,
)

__version__ = "0.2.0"

__all__ = [
    "AuditEntry",
    "BuildTxResult",
    "DeployContractResult",
    "DryRunResult",
    "InsufficientFundsError",
    "InteractContractResult",
    "InvalidAddressError",
    "SpendLimitExceededError",
    "SpendStatus",
    "TokenBalance",
    "TokenTxResult",
    "TransactionError",
    "TxResult",
    "TxSummary",
    "VectorAgent",
    "VectorAgentMCP",
    "VectorBalance",
    "VectorError",
    "WalletError",
]
