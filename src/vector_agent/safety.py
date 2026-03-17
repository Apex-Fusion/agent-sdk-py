"""Safety layer — spend limits and audit logging."""

from __future__ import annotations

from datetime import datetime, timezone

from vector_agent.exceptions import SpendLimitExceededError
from vector_agent.types import AuditEntry, SpendStatus

# Defaults: 100 ADA per-tx, 500 ADA daily (in lovelace)
DEFAULT_PER_TX_LIMIT = 100_000_000
DEFAULT_DAILY_LIMIT = 500_000_000


class SafetyLayer:
    """Enforce per-transaction and daily spend limits with audit logging."""

    def __init__(
        self,
        per_tx_limit: int = DEFAULT_PER_TX_LIMIT,
        daily_limit: int = DEFAULT_DAILY_LIMIT,
    ):
        self.per_tx_limit = per_tx_limit
        self.daily_limit = daily_limit
        self._daily_spent: int = 0
        self._last_reset: str = self._today()
        self._audit_log: list[AuditEntry] = []

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _maybe_reset_daily(self):
        today = self._today()
        if today != self._last_reset:
            self._daily_spent = 0
            self._last_reset = today

    def check_transaction(self, amount_lovelace: int) -> tuple[bool, str | None]:
        """Pre-flight check. Returns (allowed, reason_if_denied)."""
        self._maybe_reset_daily()

        if amount_lovelace > self.per_tx_limit:
            return False, (
                f"Amount {amount_lovelace} lovelace exceeds per-transaction limit "
                f"of {self.per_tx_limit} lovelace ({self.per_tx_limit / 1_000_000:.6f} ADA)"
            )

        if self._daily_spent + amount_lovelace > self.daily_limit:
            remaining = self.daily_limit - self._daily_spent
            return False, (
                f"Amount {amount_lovelace} lovelace would exceed daily limit. "
                f"Daily remaining: {remaining} lovelace ({remaining / 1_000_000:.6f} ADA)"
            )

        return True, None

    def enforce_transaction(self, amount_lovelace: int):
        """Check and raise SpendLimitExceededError if not allowed."""
        allowed, reason = self.check_transaction(amount_lovelace)
        if not allowed:
            limit_type = "per_transaction" if "per-transaction" in reason else "daily"
            limit_val = self.per_tx_limit if limit_type == "per_transaction" else self.daily_limit
            raise SpendLimitExceededError(
                reason, limit_type=limit_type, limit=limit_val, attempted=amount_lovelace
            )

    def record_transaction(self, tx_hash: str, amount_lovelace: int, recipient: str):
        """Record a completed transaction in the audit log."""
        self._maybe_reset_daily()
        self._daily_spent += amount_lovelace
        self._audit_log.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                tx_hash=tx_hash,
                amount_lovelace=amount_lovelace,
                recipient=recipient,
                action="send",
            )
        )

    def get_spend_status(self) -> SpendStatus:
        """Get current spend limit status."""
        self._maybe_reset_daily()
        remaining = max(0, self.daily_limit - self._daily_spent)
        # Next reset is midnight UTC
        now = datetime.now(timezone.utc)
        reset = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if reset <= now:
            reset = reset.replace(day=reset.day + 1)
        return SpendStatus(
            per_transaction_limit=self.per_tx_limit,
            daily_limit=self.daily_limit,
            daily_spent=self._daily_spent,
            daily_remaining=remaining,
            reset_time=reset.isoformat(),
        )

    def get_audit_log(self) -> list[AuditEntry]:
        """Get the full audit log."""
        return list(self._audit_log)
