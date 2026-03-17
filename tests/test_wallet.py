"""Tests for wallet management."""

import json
import tempfile
from pathlib import Path

import pytest

from vector_agent.wallet.hd import HDWallet
from vector_agent.wallet.skey import SkeyWallet
from vector_agent.exceptions import WalletError


def test_hd_wallet_from_mnemonic(sample_mnemonic):
    """HD wallet derives addr1... (mainnet) addresses."""
    wallet = HDWallet(sample_mnemonic, account_index=0)
    addr = str(wallet.payment_address)
    assert addr.startswith("addr1"), f"Expected addr1... prefix, got: {addr}"


def test_hd_wallet_different_accounts(sample_mnemonic):
    """Different account indices produce different addresses."""
    w0 = HDWallet(sample_mnemonic, account_index=0)
    w1 = HDWallet(sample_mnemonic, account_index=1)
    assert str(w0.payment_address) != str(w1.payment_address)


def test_hd_wallet_deterministic(sample_mnemonic):
    """Same mnemonic + account produces the same address."""
    w1 = HDWallet(sample_mnemonic, account_index=0)
    w2 = HDWallet(sample_mnemonic, account_index=0)
    assert str(w1.payment_address) == str(w2.payment_address)


def test_hd_wallet_stake_address(sample_mnemonic):
    """HD wallet produces stake1... address."""
    wallet = HDWallet(sample_mnemonic, account_index=0)
    stake_addr = str(wallet.stake_address)
    assert stake_addr.startswith("stake1"), f"Expected stake1... prefix, got: {stake_addr}"


def test_hd_wallet_invalid_mnemonic():
    """Invalid mnemonic raises WalletError."""
    with pytest.raises(WalletError):
        HDWallet("invalid mnemonic words that dont exist")


def test_skey_wallet_from_cbor_hex():
    """SkeyWallet parses a CBOR hex signing key."""
    # A dummy 32-byte key (not real, just for format testing)
    raw_key_hex = "a" * 64  # 32 bytes
    cbor_hex = "5820" + raw_key_hex
    wallet = SkeyWallet.from_cbor_hex(cbor_hex)
    addr = str(wallet.payment_address)
    assert addr.startswith("addr1"), f"Expected addr1... prefix, got: {addr}"


def test_skey_wallet_from_file():
    """SkeyWallet reads a cardano-cli .skey JSON file."""
    raw_key_hex = "b" * 64
    skey_data = {
        "type": "PaymentSigningKeyShelley_ed25519",
        "description": "Payment Signing Key",
        "cborHex": "5820" + raw_key_hex,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
        json.dump(skey_data, f)
        f.flush()
        wallet = SkeyWallet.from_file(f.name)
    addr = str(wallet.payment_address)
    assert addr.startswith("addr1")


def test_skey_wallet_missing_file():
    """SkeyWallet raises WalletError for missing file."""
    with pytest.raises(WalletError, match="not found"):
        SkeyWallet.from_file("/nonexistent/path.skey")
