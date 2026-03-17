"""Tests for the safety layer."""

from vector_agent.safety import SafetyLayer
from vector_agent.exceptions import SpendLimitExceededError

import pytest


def test_per_tx_limit_allows_under():
    safety = SafetyLayer(per_tx_limit=100_000_000, daily_limit=500_000_000)
    allowed, reason = safety.check_transaction(50_000_000)
    assert allowed is True
    assert reason is None


def test_per_tx_limit_blocks_over():
    safety = SafetyLayer(per_tx_limit=100_000_000, daily_limit=500_000_000)
    allowed, reason = safety.check_transaction(150_000_000)
    assert allowed is False
    assert "per-transaction limit" in reason


def test_daily_limit_blocks_cumulative():
    safety = SafetyLayer(per_tx_limit=100_000_000, daily_limit=200_000_000)
    # First tx OK
    safety.enforce_transaction(100_000_000)
    safety.record_transaction("tx1", 100_000_000, "addr1...")
    # Second tx OK
    safety.enforce_transaction(100_000_000)
    safety.record_transaction("tx2", 100_000_000, "addr1...")
    # Third tx should be blocked (daily limit reached)
    allowed, reason = safety.check_transaction(50_000_000)
    assert allowed is False
    assert "daily limit" in reason


def test_enforce_raises():
    safety = SafetyLayer(per_tx_limit=10_000_000, daily_limit=500_000_000)
    with pytest.raises(SpendLimitExceededError):
        safety.enforce_transaction(20_000_000)


def test_spend_status():
    safety = SafetyLayer(per_tx_limit=100_000_000, daily_limit=500_000_000)
    safety.record_transaction("tx1", 50_000_000, "addr1...")
    status = safety.get_spend_status()
    assert status.daily_spent == 50_000_000
    assert status.daily_remaining == 450_000_000
    assert status.per_transaction_limit == 100_000_000


def test_audit_log():
    safety = SafetyLayer(per_tx_limit=100_000_000, daily_limit=500_000_000)
    safety.record_transaction("tx_abc", 10_000_000, "addr1test")
    log = safety.get_audit_log()
    assert len(log) == 1
    assert log[0].tx_hash == "tx_abc"
    assert log[0].recipient == "addr1test"
    assert log[0].amount_lovelace == 10_000_000
