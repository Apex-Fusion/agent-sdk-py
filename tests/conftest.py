"""Shared test fixtures."""

import pytest


@pytest.fixture
def sample_mnemonic():
    """A test-only mnemonic (DO NOT use with real funds)."""
    return (
        "snow train heart fiscal fever volcano payment raise art burst velvet clip"
        " point people violin average tower taste income boost dash unique lobster sport"
    )


@pytest.fixture
def sample_ogmios_protocol_params():
    """Ogmios v6 protocol parameters response (subset for testing)."""
    return {
        "minFeeCoefficient": 45,
        "minFeeConstant": {"ada": {"lovelace": 156253}},
        "maxBlockBodySize": {"bytes": 180224},
        "maxBlockHeaderSize": {"bytes": 1100},
        "maxTransactionSize": {"bytes": 16384},
        "stakeCredentialDeposit": {"ada": {"lovelace": 500000000}},
        "stakePoolDeposit": {"ada": {"lovelace": 5000000000000}},
        "stakePoolPledgeInfluence": "0/1",
        "monetaryExpansion": "1/100000",
        "treasuryExpansion": "1/1000000",
        "minStakePoolCost": {"ada": {"lovelace": 0}},
        "minUtxoDepositConstant": {"ada": {"lovelace": 0}},
        "minUtxoDepositCoefficient": 4310,
        "plutusCostModels": {
            "plutus:v1": [197209, 0, 1, 1],
            "plutus:v2": [205665, 812, 1, 1],
        },
        "scriptExecutionPrices": {"memory": "577/10000", "cpu": "721/10000000"},
        "maxExecutionUnitsPerTransaction": {"memory": 16000000, "cpu": 10000000000},
        "maxExecutionUnitsPerBlock": {"memory": 80000000, "cpu": 40000000000},
        "maxValueSize": {"bytes": 5000},
        "collateralPercentage": 150,
        "maxCollateralInputs": 3,
        "version": {"major": 10, "minor": 0},
    }


@pytest.fixture
def sample_ogmios_genesis():
    """Ogmios genesis configuration response."""
    return {
        "startTime": "2025-07-09T10:38:04Z",
        "networkMagic": 764824073,
        "network": "mainnet",
        "activeSlotsCoefficient": "1/4",
        "securityParameter": 2160,
        "epochLength": 86400,
        "slotsPerKesPeriod": 129600,
        "maxKesEvolutions": 62,
        "slotLength": {"milliseconds": 1000},
        "updateQuorum": 3,
        "maxLovelaceSupply": 3000000000000000,
    }
