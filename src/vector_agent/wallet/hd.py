"""HD wallet using PyCardano's built-in HDWallet support.

Derives keys from a BIP39 mnemonic using CIP-1852 derivation paths:
  m/1852'/1815'/{account}'/0/0  — payment key
  m/1852'/1815'/{account}'/2/0  — staking key
"""

from __future__ import annotations

from pycardano import Address, Network
from pycardano.crypto.bip32 import HDWallet as PyCardanoHDWallet
from pycardano.key import (
    PaymentExtendedSigningKey,
    PaymentExtendedVerificationKey,
    StakeExtendedSigningKey,
    StakeExtendedVerificationKey,
)

from vector_agent.exceptions import WalletError


class HDWallet:
    """Cardano HD wallet derived from a BIP39 mnemonic."""

    def __init__(self, mnemonic: str, account_index: int = 0) -> None:
        try:
            hdwallet = PyCardanoHDWallet.from_mnemonic(mnemonic)
            payment_derived = hdwallet.derive_from_path(
                f"m/1852'/1815'/{account_index}'/0/0"
            )
            staking_derived = hdwallet.derive_from_path(
                f"m/1852'/1815'/{account_index}'/2/0"
            )
            self._payment_sk = PaymentExtendedSigningKey(payment_derived.xprivate_key)
            self._payment_vk = PaymentExtendedVerificationKey(payment_derived.public_key)
            self._staking_sk = StakeExtendedSigningKey(staking_derived.xprivate_key)
            self._staking_vk = StakeExtendedVerificationKey(staking_derived.public_key)
        except Exception as exc:
            raise WalletError(f"HD wallet derivation failed: {exc}") from exc

    # -- signing keys --------------------------------------------------------

    @property
    def payment_signing_key(self) -> PaymentExtendedSigningKey:
        """Extended signing key for the payment address."""
        return self._payment_sk

    @property
    def payment_verification_key(self) -> PaymentExtendedVerificationKey:
        """Verification (public) key corresponding to the payment signing key."""
        return self._payment_vk

    # -- staking keys --------------------------------------------------------

    @property
    def staking_signing_key(self) -> StakeExtendedSigningKey:
        """Extended signing key for the stake address."""
        return self._staking_sk

    @property
    def staking_verification_key(self) -> StakeExtendedVerificationKey:
        """Verification (public) key corresponding to the staking signing key."""
        return self._staking_vk

    # -- addresses -----------------------------------------------------------

    @property
    def payment_address(self) -> Address:
        """Base address (payment + staking) on mainnet — ``addr1...`` prefix."""
        return Address(
            payment_part=self._payment_vk.hash(),
            staking_part=self._staking_vk.hash(),
            network=Network.MAINNET,
        )

    @property
    def stake_address(self) -> Address:
        """Reward / stake address on mainnet — ``stake1...`` prefix."""
        return Address(
            staking_part=self._staking_vk.hash(),
            network=Network.MAINNET,
        )
