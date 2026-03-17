"""Custom exceptions for the Vector Agent SDK."""


class VectorError(Exception):
    """Base exception for all Vector Agent SDK errors."""


class ConnectionError(VectorError):
    """Failed to connect to Ogmios or submit-api."""


class InsufficientFundsError(VectorError):
    """Wallet does not have enough ADA or tokens for this transaction."""


class SpendLimitExceededError(VectorError):
    """Transaction exceeds configured spend limits."""

    def __init__(self, message: str, limit_type: str, limit: int, attempted: int):
        super().__init__(message)
        self.limit_type = limit_type
        self.limit = limit
        self.attempted = attempted


class TransactionError(VectorError):
    """Transaction building, signing, or submission failed."""


class WalletError(VectorError):
    """Wallet initialization or key derivation failed."""


class InvalidAddressError(VectorError):
    """The provided address is not a valid Vector/Cardano address."""
