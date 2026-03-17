"""Pydantic models for the Vector Agent SDK."""

from pydantic import BaseModel


class TokenBalance(BaseModel):
    """A single native token balance."""

    policy_id: str
    asset_name: str
    quantity: int


class VectorBalance(BaseModel):
    """Balance information for a Vector address."""

    address: str
    ada: str  # human-readable e.g. "125.432100"
    lovelace: int
    tokens: list[TokenBalance]


class TxResult(BaseModel):
    """Result of a submitted transaction."""

    tx_hash: str
    sender: str
    recipient: str
    amount_lovelace: int
    explorer_url: str


class TokenTxResult(TxResult):
    """Result of a token transfer transaction."""

    policy_id: str
    asset_name: str
    token_quantity: int


class SpendStatus(BaseModel):
    """Current spend limit status."""

    per_transaction_limit: int
    daily_limit: int
    daily_spent: int
    daily_remaining: int
    reset_time: str


class AuditEntry(BaseModel):
    """A single entry in the transaction audit log."""

    timestamp: str
    tx_hash: str
    amount_lovelace: int
    recipient: str
    action: str
