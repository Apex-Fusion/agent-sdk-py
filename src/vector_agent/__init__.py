"""Vector Agent SDK — Python SDK for the Vector blockchain.

Two modes of operation:
- ``VectorAgent``: Standalone mode (direct PyCardano + Ogmios)
- ``VectorAgentMCP``: MCP client mode (connects to TypeScript MCP server)
"""

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

from vector_agent import governance as governance  # noqa: F401 — Game 6

__version__ = "0.1.0"

__all__ = [
    "VectorAgent",
    "VectorAgentMCP",
    "VectorBalance",
    "TokenBalance",
    "TxResult",
    "TokenTxResult",
    "SpendStatus",
    "AuditEntry",
    "BuildTxResult",
    "DryRunResult",
    "TxSummary",
    "DeployContractResult",
    "InteractContractResult",
    "VectorError",
    "InsufficientFundsError",
    "SpendLimitExceededError",
    "TransactionError",
    "WalletError",
    "InvalidAddressError",
]
