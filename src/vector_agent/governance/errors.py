"""Errors of the Module-6 client.

Each class is a subclass of the matching identity error, so one ``except``
clause can catch the errors of both clients.
"""

from __future__ import annotations

from vector_agent.identity.errors import IdentityConfigError, IdentityLookupError, IdentityRuleError

__all__ = ["GovernanceConfigError", "GovernanceLookupError", "GovernanceRuleError"]


class GovernanceConfigError(IdentityConfigError):
    """A value of the Module-6 deployment is missing or invalid."""


class GovernanceLookupError(IdentityLookupError):
    """An output that the Module-6 validators read is missing: a record, the
    parameters, the oracle, the cross references, the activity list or a position."""


class GovernanceRuleError(IdentityRuleError):
    """The Module-6 contracts would reject the transaction: the message names the broken rule."""
