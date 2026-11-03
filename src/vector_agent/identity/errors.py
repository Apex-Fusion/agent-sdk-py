"""Errors of the identity clients."""

from __future__ import annotations

from vector_agent.exceptions import VectorError

__all__ = ["IdentityConfigError", "IdentityLookupError", "IdentityRuleError"]


class IdentityConfigError(VectorError):
    """A deployment value is missing or invalid."""


class IdentityLookupError(VectorError):
    """An identity record, an attestation, a delegation or a configuration output is missing."""


class IdentityRuleError(VectorError, ValueError):
    """The contract would reject the transaction: the message names the broken rule."""
