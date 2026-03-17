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
    SpendStatus,
    TokenBalance,
    TokenTxResult,
    TxResult,
    VectorBalance,
)

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
    "VectorError",
    "InsufficientFundsError",
    "SpendLimitExceededError",
    "TransactionError",
    "WalletError",
    "InvalidAddressError",
]
